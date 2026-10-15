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
// Put serve behind a proxy that holds the whole request body before it passes the
// request on, as nginx does by default (proxy_request_buffering on). Then a sender that
// sends a body slowly holds the proxy's buffer, not serve's: serve reads each body at
// the proxy's speed, and its byte budget and progress deadline, see [Receiver.ServeHTTP],
// cut only senders that reach it directly.
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

// The server's bounds. A delivery is read within 15 seconds, 25 MiB at most, and
// answered within a minute of its headers; GitHub counts a delivery not answered within
// ten seconds as failed, so a body that takes longer to arrive is lost already. A
// connection is idle five seconds at most, so idle connections do not hold the
// [maxConns] slots.
const (
	readHeaderTimeout = 10 * time.Second
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
	// Handlers are the handlers by event name; nil has none, so every delivery is
	// marked done as it is.
	Handlers *Handlers
	// Log takes serve's lines; nil logs nothing.
	Log *slog.Logger
	// Listening, when set, is called with the address serve listens on, once it does.
	Listening func(net.Addr)

	// idleTimeout and maxConns replace [idleTimeout] and [maxConns] in a test.
	idleTimeout time.Duration
	maxConns    int
}

// Run serves until ctx is done. Before it listens it reads the App's private key and
// the webhook secret, so a wrong file stops it at once, and opens the store. When ctx
// is done it stops taking deliveries, waits for the requests under way and the
// handlers that run, each within a bound, and closes the store.
func Run(ctx context.Context, s Settings, opts Options) error {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// The key is read so that a wrong one stops serve before it listens. Nothing here
	// signs with it.
	if _, err := github.ReadKeyFile(s.PrivateKeyFile); err != nil {
		return err
	}
	secret, err := ReadWebhookSecret(s.WebhookSecretFile)
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
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	worker := &Worker{Store: st, Handlers: opts.Handlers, Log: log}
	rc := &Receiver{Secret: secret, Store: st, Log: log, Stored: worker.Notify}
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
	served := make(chan error, 1)
	go func() { served <- srv.Serve(limit(ln, cmp.Or(opts.maxConns, maxConns), log)) }()
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
	log.Info("stopped")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
