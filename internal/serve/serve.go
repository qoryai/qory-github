// Package serve is qory-github serve: a long-running server that takes the GitHub App's
// webhook deliveries. The command exists only where the environment variable
// QORY_FEATURES names factory, and no document describes it.
//
// The [Receiver] checks each delivery's signature with the App's webhook secret, keeps
// it in the [store] and answers GitHub at once. The [Worker] then hands each kept
// delivery to the [Handler] its event is registered with in [Handlers], one
// installation's deliveries in the order they arrived. TLS is the operator's proxy's:
// serve listens on plain HTTP.
//
// serve is the GitHub adapter of Qory Apiary: the [Adapter] sends Qory Apiary the
// repositories, issues and comments of the installations linked to it, through the
// [Apiary] client, every request signed with the adapter's access key and every answer
// checked under the pin. The change feed's reader, one for each serve, applies on
// GitHub what Qory Apiary's feed says.
//
// Put serve behind a proxy that holds the whole request body before it passes the
// request on, as nginx does by default (proxy_request_buffering on). Then a sender that
// sends a body slowly holds the proxy's buffer, not serve's, and serve reads each body
// at the proxy's speed: the progress deadline, see [Receiver.ServeHTTP], cuts only
// senders that reach serve directly. The byte budget, see [readBudget], bounds the
// bodies serve holds at once whichever way they come, through the proxy or not.
package serve

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/store"
)

// The server's bounds. A delivery's headers are read within three seconds, and its body,
// 25 MiB at most, within 15 seconds after them, as the [Receiver] counts from when it
// starts on the request; it is answered within a minute of its headers. GitHub counts a
// delivery not answered within ten seconds as failed, so a delivery that takes longer
// to arrive is lost already. A connection is idle five
// seconds at most. Both keep a sender that reaches serve directly, sending headers
// slowly or nothing at all, from holding the [maxConns] slots.
const (
	readHeaderTimeout = 3 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = time.Minute
	idleTimeout       = 5 * time.Second
	maxHeaderBytes    = 64 << 10
	// shutdownBound is how long a stop waits for the requests under way to be answered,
	// and handlerGrace how long for the handlers that run to return.
	shutdownBound = 10 * time.Second
	handlerGrace  = 20 * time.Second
	// sweepEvery is how often the store drops what has expired.
	sweepEvery = time.Hour
)

// Options are what [Run] runs with besides the settings.
type Options struct {
	// Handlers are the handlers by event name; nil is the [Adapter]'s.
	Handlers *Handlers
	// Log takes serve's lines; nil logs nothing.
	Log *slog.Logger
	// Listening, when set, is called with the address serve listens on, once it does.
	Listening func(net.Addr)

	// idleTimeout, maxConns and refusalEvery replace [idleTimeout], [maxConns] and
	// [refusalEvery] in a test.
	idleTimeout  time.Duration
	maxConns     int
	refusalEvery time.Duration
}

// Run serves until ctx is done. Before it listens it reads the App's private key, the
// webhook secret and the access key's secret, so a wrong file stops it at once, and
// opens the store. Then it reads Qory Apiary's change feed, after it declares the
// adapter, until it stops, and pulls from GitHub what the webhooks missed, see
// [puller]. When ctx is done it stops taking deliveries, waits for the requests under
// way and the handlers that run, each within a bound, stops the feed's reader and the
// pull, and closes the store.
func Run(ctx context.Context, s Settings, opts Options) error {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	key, err := readKey(s.PrivateKeyFile)
	if err != nil {
		return err
	}
	secret, err := ReadWebhookSecret(s.WebhookSecretFile)
	if err != nil {
		return err
	}
	accessKey, err := ReadAccessKeySecret(s.AccessKeySecretFile)
	if err != nil {
		return err
	}
	st, err := store.Open(s.StateDir, store.Options{})
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.Sweep(); err != nil {
		return err
	}
	instance, err := instanceID(st)
	if err != nil {
		return err
	}
	apiary := &Apiary{
		URL: s.ApiaryURL, KeyID: s.AccessKeyID, Key: accessKey, Pin: s.ApiaryPublicKey, InstanceID: instance, Log: log,
		Unlinked: func(ref string, began uint64) {
			if _, err := unlinkSince(st, ref, began); err != nil {
				log.Error("marking a collection not linked", slog.String("error", err.Error()))
			}
		},
	}
	adapter := &Adapter{Store: st, GitHub: github.Client{API: s.APIURL}, AppID: s.AppID, Key: key, Slug: s.AppSlug, Sink: apiary, Log: log}
	handlers := opts.Handlers
	if handlers == nil {
		handlers = &Handlers{}
		adapter.Register(handlers)
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	worker := &Worker{Store: st, Handlers: handlers, Log: log}
	rc := &Receiver{Secret: secret, Store: st, Log: log, Stored: worker.Notify, refusalEvery: opts.refusalEvery}
	srv := &http.Server{
		Handler:           rc.Mux(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       cmp.Or(opts.idleTimeout, idleTimeout),
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	worker.Start()
	feedCtx, stopFeed := context.WithCancel(context.Background())
	defer stopFeed()
	fed, declared, pulled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(fed)
		(&feed{apiary: apiary, adapter: adapter, store: st, publicURL: s.PublicURL, log: log, declared: declared}).run(feedCtx)
	}()
	go func() {
		defer close(pulled)
		select {
		case <-declared:
			(&puller{adapter: adapter, store: st, log: log}).run(feedCtx)
		case <-feedCtx.Done():
		}
	}()
	served := make(chan error, 1)
	limited := limit(ln, cmp.Or(opts.maxConns, maxConns), log)
	go func() { served <- srv.Serve(limited) }()
	log.Info("serving", slog.String("address", ln.Addr().String()), slog.String("path", WebhookPath))
	if opts.Listening != nil {
		opts.Listening(ln.Addr())
	}
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	var serveErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case serveErr = <-served:
			break loop
		case <-sweep.C:
			if n, err := st.Sweep(); err != nil {
				log.Error("dropping expired deliveries", slog.String("error", err.Error()))
			} else if n > 0 {
				log.Info("dropped expired deliveries", slog.Int("count", n))
			}
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownBound)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		srv.Close()
	}
	worker.Stop(handlerGrace)
	stopFeed()
	<-fed
	<-pulled
	// A count of lines held back is logged before serve stops.
	rc.stopLog()
	adapter.stopLog()
	apiary.init()
	apiary.unauthorized.stop()
	limited.full.stop()
	log.Info("stopped")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
