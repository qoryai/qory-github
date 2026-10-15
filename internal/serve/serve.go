// Package serve is qory-github-server serve: a long-running server that takes the
// GitHub App's webhook deliveries. The command exists only where the environment
// variable QORY_FEATURES names factory, and no document describes it.
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

// endedIn is what serve does when Qory Apiary answers that a connection ended: it drops
// what st keeps of the connection, see [dropConnection], and logs it on log.
func endedIn(st *store.Store, log *slog.Logger) func(connection string) {
	return func(connection string) {
		dropped, err := dropConnection(st, connection)
		switch {
		case err != nil:
			log.Error("dropping an ended connection", slog.String("connection", connection), slog.String("error", err.Error()))
		case dropped:
			log.Info("the connection ended in Qory Apiary, so its installation is no longer linked", slog.String("connection", connection))
		}
	}
}

// answeredIn is what serve does with Qory Apiary's signed answer for a connection: it
// notes it, see [noteAnswer], and drops the connection as [endedIn] does once its 403s
// have lasted.
func answeredIn(st *store.Store, log *slog.Logger) func(connection string, status int, code string, at time.Time) {
	ended := endedIn(st, log)
	return func(connection string, status int, code string, at time.Time) {
		end, err := noteAnswer(st, connection, status, code, at)
		if err != nil {
			// placeholder: wording waits for the user
			log.Error("keeping when a connection's requests began to be refused", slog.String("connection", connection), slog.String("error", err.Error()))
			return
		}
		if end {
			// placeholder: wording waits for the user
			log.Info("Qory Apiary answered connection_unknown for a day, so the connection is dropped", slog.String("connection", connection))
			ended(connection)
		}
	}
}

// Run serves until ctx is done. Before it listens it reads the App's private key, the
// webhook secret, the access key's secret and the App's client secret, so a wrong file
// stops it at once, and opens the store. It serves the webhook receiver and, beside it,
// the connect page, see [Connect]. Then it reads Qory Apiary's change feed, after it
// declares the adapter, until it stops, and pulls from GitHub what the webhooks missed,
// see [puller]. When ctx is done it stops taking deliveries, waits for the requests
// under way and the handlers that run, each within a bound, stops the fills a
// re-connect started, the feed's reader and the pull, and closes the store.
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
	clientSecret, err := ReadClientSecret(s.ClientSecretFile)
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
		Ended:        endedIn(st, log),
		Answered:     answeredIn(st, log),
		ConnectionOf: func(ref string) string { c, _ := connectionOf(st, ref); return c },
	}
	adapter := &Adapter{Store: st, GitHub: github.Client{API: s.APIURL}, AppID: s.AppID, Key: key, Slug: s.AppSlug, Sink: apiary, Log: log}
	// The adapter's handlers serve only a linked installation, so the receiver keeps no
	// other's delivery, see [Receiver.Linked].
	handlers, linked := opts.Handlers, func(int64) (bool, error) { return true, nil }
	if handlers == nil {
		handlers = &Handlers{}
		adapter.Register(handlers)
		linked = func(id int64) (bool, error) { return Linked(st, id) }
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	worker := &Worker{Store: st, Handlers: handlers, Log: log}
	rc := &Receiver{Secret: secret, Store: st, Log: log, Stored: worker.Notify, Handlers: handlers, Linked: linked, refusalEvery: opts.refusalEvery}
	connect := &Connect{
		Store: st, Adapter: adapter, Pin: s.ApiaryPublicKey, AdapterID: s.AdapterID, Key: accessKey, ClientID: s.ClientID, ClientSecret: clientSecret,
		PublicURL: s.PublicURL, ApiaryURL: s.ApiaryURL, Log: log,
	}
	srv := &http.Server{
		Handler:           connect.Route(rc.Mux()),
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
	connect.stop()
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
