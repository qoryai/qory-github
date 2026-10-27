// Package serve is qory-github-server serve: a long-running server that takes the
// GitHub App's webhook deliveries. The command exists only where the environment
// variable QORY_FEATURES names factory, and no document describes it.
//
// The [Receiver] checks each delivery's signature with the App's webhook secret, keeps
// it in the [store] and answers GitHub at once. The [Worker] then hands each kept
// delivery to the [Handler] its event is registered with in [Handlers], one
// installation's deliveries in the order they arrived. TLS is the instance admin's
// proxy's: serve listens on plain HTTP.
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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
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
	// ProgramVersion is the program's version, which the description serve declares
	// at each start carries, see [Apiary.Declare]. It is required.
	ProgramVersion string
	// Handlers are the handlers by event name; nil is the [Adapter]'s.
	Handlers *Handlers
	// Log takes serve's lines; nil logs nothing.
	Log *slog.Logger
	// Listening, when set, is called with the address serve listens on, once it serves
	// there: at a first start that enrols, before it is enrolled; otherwise, before
	// serve reads the App from Qory Apiary, see [Run].
	Listening func(net.Addr)

	// idleTimeout, maxConns and refusalEvery replace [idleTimeout], [maxConns] and
	// [refusalEvery] in a test.
	idleTimeout  time.Duration
	maxConns     int
	refusalEvery time.Duration
	// enrolWait replaces [wait] between the attempts of an enrolment at first start,
	// and enrolTransport, when set, carries its requests in place of
	// [http.DefaultTransport].
	enrolWait      func(context.Context, time.Duration) error
	enrolTransport http.RoundTripper
	// feedSleep replaces the change feed reader's waits, see [feed].
	feedSleep func(context.Context, time.Duration) error
	// declarerWaits, when set, is called with done, closed when the declaration with
	// setup_url has ended, as the stop of [runner.declareForSetup] starts to wait for
	// it; feedStarts, when set, is called as the change feed's reader starts. A test
	// orders them.
	declarerWaits func(done <-chan struct{})
	feedStarts    func()
	// uploadWait replaces the waits between the App setup's uploads of the App, see
	// [appSetup.retry].
	uploadWait func(context.Context, time.Duration) error
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

// answeredIn is what serve does with Qory Apiary's signed answer to a request that
// names a connection: it notes it, see [noteAnswer], and drops the connection as
// [endedIn] does once its 403s have lasted.
func answeredIn(st *store.Store, log *slog.Logger) func(connection string, status int, code string, at time.Time) {
	ended := endedIn(st, log)
	return func(connection string, status int, code string, at time.Time) {
		end, err := noteAnswer(st, connection, status, code, at)
		if err != nil {
			log.Error("could not store when the connection's requests began to be refused", slog.String("connection", connection), slog.String("error", err.Error()))
			return
		}
		if end {
			log.Info("Qory Apiary answered connection_unknown for a day, so the connection is dropped", slog.String("connection", connection))
			ended(connection)
		}
	}
}

// Run serves until ctx is done. It refuses options without a program version before it
// reads anything, and then settings that give part of the enrolment in Qory Apiary,
// see [Settings.check], and settings that give no enrolment when the state directory
// holds none and enrolment_code_file is not set. When the settings give the enrolment,
// it reads the access key's secret from its value or its file, so a wrong secret or
// file stops it at once. Then it opens the store and listens; /health answers 200 from
// then on.
//
// serve goes through these phases, forward only, on the one listener. A start goes
// through the App check or the no-App phase, never both.
//
//   - Enrolling, when the settings give no enrolment and the state directory holds
//     none: at the first start it enrols with the code in the file
//     enrolment_code_file names, see [enroller.run]. Every request but /health is
//     answered 503 until it is enrolled.
//   - Reading the App: serve reads the App's values from Qory Apiary, sealed to its
//     access key, see [runner.loadApp], and keeps them in memory alone. Every request
//     but /health gets 503 until serve has read the App, or that Qory Apiary stores
//     none.
//   - App check, when Qory Apiary delivers an App: serve checks with GitHub which App
//     it is, see [runner.checkApp]. Every request but /health gets 503 until serve
//     serves with the App or stops.
//   - No App, when Qory Apiary stores no App: it declares the adapter with setup_url,
//     <public_url>/setup, where an instance admin sets the App up, see [appSetup],
//     and answers 503 to every other request, the webhook's and the connect page's
//     among them. The change feed is not read and nothing is pulled, since nothing can
//     be linked without an App. Once the setup has stored an App in Qory Apiary, serve
//     goes on to serve without a restart, and declares the adapter again at once,
//     without setup_url, after the declaration with it has ended.
//   - Serving: the webhook receiver and, beside it, the connect page, see [Connect],
//     and, with call_url set, Qory Apiary's calls, see [Calls].
//     It reads Qory Apiary's change feed, after it declares the adapter, without
//     setup_url, until it stops, and pulls from GitHub what the webhooks missed, see
//     [puller]. The App setup refuses every setup pass.
//
// serve writes none of the App's values to disk: the state directory contains the
// access key, the enrolment and the store alone. Before serve serves with the App Qory
// Apiary delivered, it checks once with GitHub which App it is, see [runner.checkApp],
// and stops with an error when GitHub does not accept the App's token, or when
// GitHub's answer has no id, is for another App, or has a new slug that is no slug.
// A new slug is used in place of the old one and stored in Qory Apiary. An App whose
// webhook secret GitHub did not confirm has it set again at each start. With
// public_address false, serve declares that it learns of changes on GitHub by pulling,
// and so it does for an App whose webhook was created inactive.
//
// With the enrolment kept in the state directory and enrolment_code_file set, it looks
// at the code file again at start and after each 401 Qory Apiary answers, beside
// serving, and replaces the key once a new one is enrolled, see [reenroller]; a 401
// itself changes no state, and with the enrolment in the settings it never looks at the
// code file. After each new enrolment, the adapter is declared again under the new
// key, with setup_url while no App is in use; one that makes the adapter another
// adapter in Qory Apiary drops what the store held for the old one first, see
// [ownState], or, should serve stop before, at the next start, and stores the App in
// use, if any, in the new adapter. When ctx is done it stops taking requests, waits
// for the requests under way and the handlers that run, each within a bound, stops the
// fills a re-connect started, the App setup's uploads, the declaration, the feed's
// reader, the pull and the reenroller, and closes the store.
func Run(ctx context.Context, s Settings, opts Options) error {
	if opts.ProgramVersion == "" {
		return errors.New("no program version, which the description serve declares carries")
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := s.check(); err != nil {
		return err
	}
	if err := s.checkEnrolmentSource(); err != nil {
		return err
	}
	var accessKey *accesskey.Key
	if s.GivesEnrolment() {
		var err error
		if accessKey, err = s.secretOf("access_key_secret_file").accessKey(); err != nil {
			return err
		}
	}
	st, err := store.Open(s.StateDir, store.Options{})
	if err != nil {
		return err
	}
	defer st.Close()
	// The store is open, so no other serve runs on the state directory, which is
	// checked: the enrolment is kept there when the settings give none.
	if _, err := st.Sweep(); err != nil {
		return err
	}
	instance, err := instanceID(st)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	log.Info("listening", slog.String("address", ln.Addr().String()))
	r := &runner{
		s: s, opts: opts, log: log, st: st, instance: instance,
		creds:  &credentials{e: enrolment{keyID: s.AccessKeyID, key: accessKey, pin: s.ApiaryPublicKey, adapterID: s.AdapterID}},
		router: &router{}, setUp: make(chan *app, 1),
	}
	return r.run(ctx, ln)
}

// runner is one [Run] of serve, once it listens: what each phase starts and what the
// stop stops.
type runner struct {
	// ctx is Run's: done when serve stops.
	ctx      context.Context
	s        Settings
	opts     Options
	log      *slog.Logger
	st       *store.Store
	instance string
	creds    *credentials
	router   *router
	srv      *http.Server
	limited  *limitListener
	served   chan error
	started  bool
	apiary   *Apiary
	setup    *appSetup
	re       *reenroller
	// setUp takes the App the App setup stored in Qory Apiary, which Run's goroutine
	// then serves.
	setUp chan *app
	// inUse is the App serve serves with, nil before; mu guards it once serving starts.
	inUse *app
	// storeMu guards newRecordApp: the App to store in the adapter record of a new
	// enrolment once the adapter is declared there, nil when none waits, see
	// [runner.storeInNewRecord].
	storeMu      sync.Mutex
	newRecordApp *app

	// mu guards start, stop and inUse: start starts what declares the adapter in the
	// phase in place, the declaration with setup_url or the change feed's reader and the
	// pull, and returns what stops it, stop, which waits for it; both are nil until
	// serve has read the App. A phase's change and a new enrolment both stop it and
	// start it again.
	mu    sync.Mutex
	start func() func()
	stop  func()

	// What serving starts, which the stop stops, nil before.
	worker  *Worker
	rc      *Receiver
	connect *Connect
	adapter *Adapter
	// calls answers Qory Apiary's calls, nil when call_url is not set.
	calls *Calls
	// confirmCancel and confirmed are the setting again of the App's webhook
	// secret, see [runner.confirm], which the stop cancels and waits for.
	confirmCancel context.CancelFunc
	confirmed     chan struct{}
}

// serve starts serving on the listener with the phase in place, once: from then on
// Listening, when set, has been called.
func (r *runner) serve() {
	if r.started {
		return
	}
	r.started = true
	go func() { r.served <- r.srv.Serve(r.limited) }()
	if r.opts.Listening != nil {
		r.opts.Listening(r.limited.Addr())
	}
}

// run is [Run]'s part from when serve listens on ln.
func (r *runner) run(ctx context.Context, ln net.Listener) error {
	r.ctx = ctx
	s, log, st := r.s, r.log, r.st
	r.router.set(&phase{health: healthEnrolling, unavailable: unavailableEnrolling})
	r.srv = &http.Server{
		Handler:           r.router,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       cmp.Or(r.opts.idleTimeout, idleTimeout),
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	r.limited = limit(ln, cmp.Or(r.opts.maxConns, maxConns), log)
	r.served = make(chan error, 1)
	// end stops what is started before the serving loop, when Run returns before it.
	end := func() {
		if r.started {
			r.shutdownServer()
		} else {
			ln.Close()
		}
		r.limited.full.stop()
	}
	// serve listens before each wait: a first start that enrols waits for its code in
	// the enrolling phase, and a start with an App waits for GitHub's answer to the App
	// check in the App-check phase. A start with no App listens once the no-App phase is
	// in place.
	if !s.GivesEnrolment() && !hasKeptEnrolment(s.StateDir) {
		r.serve()
	}
	// refused is told of each 401 Qory Apiary answers: with the enrolment kept in the
	// state directory and enrolment_code_file set, the reenroller looks at the code
	// file; with it kept there and no code file, a line says so once; with the
	// enrolment in the settings, nothing more happens than the 401's line.
	var refused func()
	if !s.GivesEnrolment() {
		e, en, err := s.enrolmentOf(ctx, r.opts, log)
		if err != nil {
			end()
			if ctx.Err() != nil {
				log.Info("stopped")
				return nil
			}
			return err
		}
		r.creds.set(e)
		// The store's state is the adapter record's that the enrolment names: a start
		// that finds another record's, after a re-enrolment in a new record stopped
		// before it dropped that state, drops it now.
		if err := ownState(st, e.adapterID, log); err != nil {
			end()
			return err
		}
		if en != nil {
			r.re = newReenroller(en, r.creds, log)
			refused = r.re.refused
		} else {
			var once sync.Once
			refused = func() {
				once.Do(func() {
					log.Warn("Qory Apiary answered a request 401; enrolment_code_file is not set, so serve looks for no code to enrol a new key with")
				})
			}
		}
	}
	in := r.creds.get()
	r.apiary = &Apiary{
		URL: s.ApiaryURL, KeyID: in.keyID, Key: in.key, Pin: in.pin, InstanceID: r.instance, ProgramVersion: r.opts.ProgramVersion, Log: log,
		Unlinked: func(ref string, began uint64) {
			if _, err := unlinkSince(st, ref, began); err != nil {
				log.Error("marking a collection not linked", slog.String("error", err.Error()))
			}
		},
		Ended:        endedIn(st, log),
		Answered:     answeredIn(st, log),
		ConnectionOf: func(ref string) string { c, _ := connectionOf(st, ref); return c },
		PullsAlone:   !s.publicAddress(),
		creds:        r.creds, refused: refused, lastGet: storeLastGet{st},
	}
	if r.re != nil {
		// A new enrolment stops what declares the adapter, drops what the store holds
		// for the old record when the enrolment is in another one, puts the enrolment
		// in use, whether the drop failed or not, and starts it again, so the adapter
		// is declared again under the new key, and a new record's feed is read from its
		// start. In another record, the App in use is stored there too, once the adapter
		// is declared there, see [runner.storeInNewRecord]: Qory Apiary returns 400 for
		// a secret that the source role of the record's latest description does not
		// list. Only the reenroller calls it, one look at a time, and it is stopped
		// before what declares the adapter is at the stop. Before serve has read the
		// App, nothing declares the adapter yet.
		r.re.inUse = func(got enrolment) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			old := r.creds.get()
			if r.stop != nil {
				r.stop()
			}
			err := ownState(st, got.adapterID, log)
			r.creds.set(got)
			if got.adapterID != old.adapterID && r.inUse != nil {
				r.storeMu.Lock()
				r.newRecordApp = r.inUse
				r.storeMu.Unlock()
			}
			if r.start != nil {
				r.stop = r.start()
			}
			return err
		}
	}
	reenrolled := make(chan struct{})
	reCtx, stopRe := context.WithCancel(context.Background())
	defer stopRe()
	go func() {
		defer close(reenrolled)
		if r.re != nil {
			r.re.run(reCtx)
		}
	}()
	// stopped stops the reenroller, then what is started before the serving loop, when
	// Run returns before it.
	stopped := func() {
		stopRe()
		<-reenrolled
		end()
	}
	r.router.set(&phase{health: healthLoading, unavailable: unavailableLoading})
	r.serve()
	a, err := r.loadApp(ctx)
	if err == nil && a != nil {
		// The App Qory Apiary delivered is checked with GitHub before anything serves
		// with it; a stop meanwhile stops serve.
		r.router.set(&phase{health: healthAppCheck, unavailable: unavailableAppCheck})
		a, err = r.checkApp(ctx, a)
	}
	if err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		stopped()
		log.Info("stopped")
		return nil
	}
	if err != nil {
		stopped()
		return err
	}
	if !s.publicAddress() {
		log.Info("public_address is false: GitHub sends no webhooks, and serve learns of changes on GitHub by pulling")
	}
	r.setup = &appSetup{
		Store: st, GitHub: github.Client{API: s.APIURL}, PublicURL: s.PublicURL, ApiaryPublicURL: cmp.Or(s.ApiaryPublicURL, s.ApiaryURL),
		Active: s.publicAddress(), Log: log, creds: r.creds, refusalEvery: r.opts.refusalEvery,
		Upload: r.upload, UploadFor: s.uploadFor(), ctx: ctx, wait: r.opts.uploadWait,
		setUp: func(kept *app) { r.setUp <- kept },
	}
	r.mu.Lock()
	if a == nil {
		r.router.set(&phase{health: healthNoApp, unavailable: unavailableNoApp, setup: r.setup})
		r.start = r.declareForSetup
		log.Info("waiting for the GitHub App's setup: an instance admin presses Set up on the adapter's page in Qory Apiary")
	} else {
		r.setup.markKept()
		r.serveApp(a, true)
	}
	r.stop = r.start()
	r.mu.Unlock()
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	var serveErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case serveErr = <-r.served:
			break loop
		case kept := <-r.setUp:
			// The App setup stored kept in Qory Apiary before it handed kept on, so the
			// start-up body without setup_url follows the upload, as
			// adapter-secrets.schema.json:5 orders it. The declaration with setup_url
			// ends before the one without starts.
			r.mu.Lock()
			r.stop()
			r.serveApp(kept, false)
			r.stop = r.start()
			r.mu.Unlock()
		case <-sweep.C:
			if n, err := st.Sweep(); err != nil {
				log.Error("dropping expired deliveries", slog.String("error", err.Error()))
			} else if n > 0 {
				log.Info("dropped expired deliveries", slog.Int("count", n))
			}
		}
	}
	r.shutdownServer()
	r.setup.stop()
	if r.worker != nil {
		r.worker.Stop(handlerGrace)
		r.connect.stop()
	}
	stopRe()
	<-reenrolled
	r.mu.Lock()
	r.stop()
	r.mu.Unlock()
	if r.confirmCancel != nil {
		r.confirmCancel()
		<-r.confirmed
	}
	// The grant ends sent again stop once nothing starts one, and a count of lines held
	// back is logged before serve stops.
	if r.worker != nil {
		r.adapter.stopEnds()
		r.rc.stopLog()
		r.adapter.stopLog()
	}
	if r.calls != nil {
		r.calls.stopLog()
	}
	r.apiary.init()
	r.apiary.unauthorized.stop()
	r.limited.full.stop()
	log.Info("stopped")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// shutdownServer stops taking requests and waits for those under way, within
// [shutdownBound], then closes what is left.
func (r *runner) shutdownServer() {
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownBound)
	defer cancel()
	if err := r.srv.Shutdown(shutdown); err != nil {
		r.srv.Close()
	}
}

// loadApp reads the App from Qory Apiary, see [Apiary.Secrets], and returns it, or nil
// when Qory Apiary stores none, see [appOf]. A read that fails, Qory Apiary out of
// reach, a 401, or an answer refused, is tried again after a wait that doubles, as
// the change feed's reader waits, with a line at the first failure and then once each
// [feedMaxBackoff] at most. Secrets that are not an App serve uploads refuse the
// start. When ctx is done it returns ctx's error.
func (r *runner) loadApp(ctx context.Context) (*app, error) {
	waits := &feed{sleep: r.opts.feedSleep}
	failed := &throttle{every: feedMaxBackoff}
	backoff := feedFirstBackoff
	for {
		p, err := r.apiary.Secrets(ctx)
		if err == nil {
			a, err := appOf(p)
			if err != nil {
				return nil, fmt.Errorf("reading the GitHub App from Qory Apiary: %w", err)
			}
			return a, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if ok, dropped := failed.allow(); ok {
			attrs := []slog.Attr{slog.String("error", err.Error())}
			if dropped > 0 {
				attrs = append(attrs, slog.Int("failed_dropped", dropped))
			}
			r.log.LogAttrs(ctx, slog.LevelWarn, "reading the GitHub App from Qory Apiary failed, and is tried again", attrs...)
		}
		if waits.wait(ctx, backoff) != nil {
			return nil, ctx.Err()
		}
		backoff = min(2*backoff, feedMaxBackoff)
	}
}

// upload stores the App a in Qory Apiary, see [Apiary.UploadSecrets].
func (r *runner) upload(ctx context.Context, a *app) error {
	p, err := a.plaintext()
	if err != nil {
		return err
	}
	return r.apiary.UploadSecrets(ctx, p)
}

// storeInNewRecord stores the App that waits in newRecordApp, if any, in the adapter
// record of the enrolment in use, after a new enrolment made the adapter another
// record in Qory Apiary, which stores no App. It runs once the change feed's reader
// has declared the adapter in that record: adapter-secrets.schema.json:5 has an
// adapter that is set up but receives no secrets upload right after its start-up
// body, and Qory Apiary returns 400 for a secret the source role of the record's
// latest description does not list. A failed upload is tried again, after a wait
// that doubles from [feedFirstBackoff] to [feedMaxBackoff], until ctx is done; a
// permanent error, such as a 400, ends it.
// When the App is not stored, a line says so: the next start of serve finds no App,
// and serves the App setup.
func (r *runner) storeInNewRecord(ctx context.Context) {
	waits := &feed{sleep: r.opts.feedSleep}
	backoff := feedFirstBackoff
	for {
		r.storeMu.Lock()
		a := r.newRecordApp
		r.storeMu.Unlock()
		if a == nil {
			return
		}
		upCtx, cancel := context.WithTimeout(ctx, connectBound)
		err := r.upload(upCtx, a)
		cancel()
		if err == nil || IsPermanent(err) {
			r.storeMu.Lock()
			if r.newRecordApp == a {
				r.newRecordApp = nil
			}
			r.storeMu.Unlock()
		}
		switch {
		case err == nil:
			return
		case IsPermanent(err):
			r.log.Error("storing the GitHub App in the new adapter in Qory Apiary failed; at its next start serve finds no App there", slog.String("slug", a.slug), slog.String("error", err.Error()))
			return
		case r.ctx.Err() != nil:
			r.log.Error("serve stopped before it stored the GitHub App in the new adapter in Qory Apiary; at its next start serve finds no App there", slog.String("slug", a.slug))
			return
		case ctx.Err() != nil:
			return
		}
		r.log.Warn("storing the GitHub App in the new adapter in Qory Apiary failed, and is tried again", slog.String("slug", a.slug), slog.String("error", err.Error()))
		if waits.wait(ctx, backoff) != nil {
			if r.ctx.Err() != nil {
				r.log.Error("serve stopped before it stored the GitHub App in the new adapter in Qory Apiary; at its next start serve finds no App there", slog.String("slug", a.slug))
			}
			return
		}
		backoff = min(2*backoff, feedMaxBackoff)
	}
}

// declareForSetup starts declaring the adapter with setup_url, until Qory Apiary
// accepts it, and returns what stops it. The stop waits for the declaration under way,
// if any, to be answered, or for its request's bound, so a declaration with setup_url
// never follows the one without, which the change feed's reader sends once an App is
// kept; Run's stop cancels it at once.
func (r *runner) declareForSetup() func() {
	stop, done := make(chan struct{}), make(chan struct{})
	waitCtx, cancelWait := context.WithCancel(r.ctx)
	go func() {
		defer close(done)
		waits := &feed{sleep: r.opts.feedSleep}
		backoff := feedFirstBackoff
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := r.apiary.Declare(r.ctx, r.s.PublicURL, r.s.PublicURL+setupPath)
			if err == nil || r.ctx.Err() != nil {
				return
			}
			r.log.Error("declaring the adapter to Qory Apiary", slog.String("error", err.Error()))
			if waits.wait(waitCtx, backoff) != nil {
				return
			}
			backoff = min(2*backoff, feedMaxBackoff)
		}
	}()
	return func() {
		close(stop)
		cancelWait()
		if r.opts.declarerWaits != nil {
			r.opts.declarerWaits(done)
		}
		<-done
	}
}

// serveApp serves with the App a: it starts the adapter, the webhook receiver, the
// connect page, Qory Apiary's calls when call_url is set, see [Calls], and the
// handlers' worker, puts the serving phase in place, and makes
// start the change feed's reader and the pull, which declare the adapter without
// setup_url first. serve declares that it sends changes as they happen only with
// public_address true and a's webhook active; an App whose webhook was created
// inactive is said so. atStart is whether a is the App serve started with: then an App
// whose webhook secret GitHub did not confirm has it set again, see [runner.confirm].
// What declares the adapter in the phase before is stopped already. r.mu is held.
func (r *runner) serveApp(a *app, atStart bool) {
	s, log, st := r.s, r.log, r.st
	r.inUse = a
	web := github.Client{API: s.APIURL}.Web()
	r.apiary.PullsAlone = !s.publicAddress() || !a.webhookActive
	if s.publicAddress() && !a.webhookActive {
		log.Warn("the App's webhook was created inactive, so serve declares that it learns of changes by pulling; to change that, set the App's webhook URL to " + s.PublicURL + WebhookPath + " and turn the webhook on at " + a.settingsURL(web))
	}
	adapter := &Adapter{Store: st, GitHub: github.Client{API: s.APIURL}, AppID: a.id, Key: a.key, Slug: a.slug, Sink: r.apiary, Log: log}
	r.apiary.Ended = adapter.forgetEnded(r.apiary.Ended)
	// The adapter's handlers serve only a linked installation, so the receiver keeps no
	// other's delivery but those [Receiver.Linked] names.
	handlers, linked := r.opts.Handlers, func(int64) (bool, error) { return true, nil }
	if handlers == nil {
		handlers = &Handlers{}
		adapter.Register(handlers)
		linked = func(id int64) (bool, error) { return granted(st, id, adapter.clock()) }
	}
	worker := &Worker{Store: st, Handlers: handlers, Log: log}
	rc := &Receiver{Secret: a.webhookSecret, Store: st, Log: log, Stored: worker.Notify, Handlers: handlers, Linked: linked, refusalEvery: r.opts.refusalEvery}
	in := r.creds.get()
	connect := &Connect{
		Store: st, Adapter: adapter, Pin: in.pin, AdapterID: in.adapterID, Key: in.key, ClientID: a.clientID, ClientSecret: a.clientSecret,
		PublicURL: s.PublicURL, ApiaryPublicURL: cmp.Or(s.ApiaryPublicURL, s.ApiaryURL), Log: log, creds: r.creds,
	}
	r.adapter, r.worker, r.rc, r.connect = adapter, worker, rc, connect
	next := connect.Route(rc.Mux())
	// With call_url set, serve answers Qory Apiary's calls and declares where; without
	// it, no call route answers, and the declaration has no call_url.
	if s.CallURL != "" {
		r.calls = &Calls{
			Store: st, Grants: storeGrants{st: st, now: adapter.clock}, GitHub: github.Client{API: s.APIURL}, Public: github.Public{Git: s.PublicGitURL, Raw: s.PublicRawURL, API: s.PublicAPIURL}, AppID: a.id, Key: a.key, InstanceID: r.instance, Log: log, creds: r.creds,
			listingToken: func(ctx context.Context, installation int64) (string, error) {
				return adapter.token(ctx, installation, 0, "")
			},
			refusalEvery: r.opts.refusalEvery,
		}
		next = r.calls.Route(next)
		r.apiary.CallURL = s.CallURL
	}
	worker.Start()
	r.router.set(&phase{health: healthServing, setup: r.setup, next: next})
	log.Info("serving", slog.String("address", r.limited.Addr().String()), slog.String("path", WebhookPath))
	r.start = func() func() {
		if r.opts.feedStarts != nil {
			r.opts.feedStarts()
		}
		feedCtx, stopFeed := context.WithCancel(context.Background())
		fed, declared, pulled := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			defer close(fed)
			(&feed{apiary: r.apiary, adapter: adapter, store: st, publicURL: s.PublicURL, log: log, declared: declared, sleep: r.opts.feedSleep}).run(feedCtx)
		}()
		go func() {
			defer close(pulled)
			select {
			case <-declared:
				(&puller{adapter: adapter, store: st, log: log}).run(feedCtx)
			case <-feedCtx.Done():
			}
		}()
		stored := make(chan struct{})
		go func() {
			defer close(stored)
			select {
			case <-declared:
				r.storeInNewRecord(feedCtx)
			case <-feedCtx.Done():
			}
		}()
		return func() {
			stopFeed()
			<-fed
			<-pulled
			<-stored
		}
	}
	if atStart && !a.confirmed {
		r.confirm(a)
	}
}

// confirm sets the App a's webhook secret on its webhook again, beside serving, since
// GitHub did not confirm it when the App was set up, and stores in Qory Apiary that
// GitHub confirmed it once GitHub does, see [Apiary.UploadSecrets]; when GitHub does
// not, or the upload fails, a line says so, and the next start sets it again.
func (r *runner) confirm(a *app) {
	ctx, cancel := context.WithTimeout(context.Background(), connectBound)
	r.confirmCancel, r.confirmed = cancel, make(chan struct{})
	go func() {
		defer close(r.confirmed)
		defer cancel()
		if err := (github.Client{API: r.s.APIURL}).SetAppWebhookSecret(ctx, a.numericID, a.key, string(a.webhookSecret)); err != nil {
			r.log.Warn("GitHub did not confirm the App's webhook secret; serve sets it again at its next start", slog.Int64("app_id", a.numericID), slog.String("error", err.Error()))
			return
		}
		if err := r.upload(ctx, a.with(func(c *app) { c.confirmed = true })); err != nil {
			r.log.Warn("storing in Qory Apiary that GitHub confirmed the App's webhook secret failed; serve sets it again at its next start", slog.Int64("app_id", a.numericID), slog.String("error", err.Error()))
		}
	}()
}
