package serve

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/qoryai/qory-github/internal/store"
)

// Delivery is one webhook delivery a [Handler] handles, its body among it.
type Delivery = store.Delivery

// Handler handles the deliveries of one event. It returns nil once the delivery is
// handled, and an error to have it tried again later: an error [Permanent] marks fails
// the delivery at once, one [Held] marks has it tried again for as long as it takes,
// and one [Outage] marks has it tried again for a day. A delivery may be handed to it
// again after a restart, so handling one twice must do no harm. Its error is logged, so
// it never contains a secret, a token or the body. It returns soon after ctx is
// cancelled, which a stop does.
type Handler interface {
	HandleDelivery(ctx context.Context, d Delivery) error
}

// HandlerFunc is a function that is a [Handler].
type HandlerFunc func(ctx context.Context, d Delivery) error

// HandleDelivery calls f.
func (f HandlerFunc) HandleDelivery(ctx context.Context, d Delivery) error { return f(ctx, d) }

// Handlers are the handlers by event name, such as issues or installation. The zero
// value has none; each is registered once, before the worker starts.
type Handlers struct {
	mu sync.RWMutex
	m  map[string]Handler
}

// Handle registers h for the event named event. It panics when that event has a handler
// already, or when event or h is empty, as [http.ServeMux.Handle] does: a registration
// is the program's, never its input's.
func (hs *Handlers) Handle(event string, h Handler) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if event == "" || h == nil {
		panic("serve: a handler is registered for an event, neither empty")
	}
	if _, ok := hs.m[event]; ok {
		panic("serve: the event " + event + " has a handler already")
	}
	if hs.m == nil {
		hs.m = map[string]Handler{}
	}
	hs.m[event] = h
}

// HandleFunc registers f for the event named event, as [Handlers.Handle] does.
func (hs *Handlers) HandleFunc(event string, f func(ctx context.Context, d Delivery) error) {
	hs.Handle(event, HandlerFunc(f))
}

// handler is the event's handler, or nil when it has none.
func (hs *Handlers) handler(event string) Handler {
	if hs == nil {
		return nil
	}
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return hs.m[event]
}

// The worker's defaults.
const (
	// DefaultAttempts is how many times a handler is called for one delivery before the
	// delivery is marked failed.
	DefaultAttempts = 5
	// firstBackoff is the wait after the first failed attempt; each wait doubles, up
	// to maxBackoff.
	firstBackoff = 2 * time.Second
	maxBackoff   = time.Minute
	// outageEvery is how often the first outage of a delivery is logged at most; those
	// in between are counted.
	outageEvery = time.Minute
	// outageFor is how long a delivery whose handler meets Qory Apiary's [Outage] is
	// tried again, from its first attempt, after a wait that doubles from two seconds
	// to outageMaxBackoff, so a deploy of Qory Apiary loses no delivery.
	outageFor        = 24 * time.Hour
	outageMaxBackoff = 5 * time.Minute
	// rescan is how often the worker reads the store's pending deliveries when nothing
	// wakes it.
	rescan = time.Minute
	// maxLanes is how many installations' deliveries are handled at once; the other
	// installations wait their turn, in the order their first delivery was queued.
	maxLanes = 16
)

// Worker hands the store's pending deliveries to their handlers, after the receiver
// answered GitHub. The deliveries of one installation, the payload's installation.id,
// are handled one after another in the order they arrived; those of different
// installations at once. A delivery whose event has no handler is marked done. A
// handler's error is tried again after a wait that doubles each time, [Worker.Attempts]
// times in all, and the delivery is then marked failed. A [Permanent] error marks it
// failed at once. A [Held] error is tried again after a wait that doubles to a minute,
// and counts as no attempt, so the installation's later deliveries wait behind it. An
// [Outage] error, Qory Apiary's, counts as no attempt either: it is tried again after a
// wait that doubles to five minutes, until a day has passed since the delivery's first
// attempt, and the delivery is then marked failed and logged. The first outage a
// delivery meets is logged at the warning level, one line a minute at most, the lines
// held back counted. A delivery stays pending
// until one of these, so one that a stop interrupted is handled after the next start,
// and its day counted again from then.
type Worker struct {
	// Store keeps the deliveries.
	Store *store.Store
	// Handlers are the handlers by event name.
	Handlers *Handlers
	// Log takes one line for each delivery's outcome: its event, its action when it has
	// one, its GUID, and the outcome; nil logs nothing.
	Log *slog.Logger
	// Attempts is how many times a handler is called for one delivery; zero is
	// [DefaultAttempts].
	Attempts int
	// Backoff is the wait after the attempt numbered attempt, from 1, failed; nil
	// doubles from two seconds, to a minute at most, or to five minutes for an
	// [Outage].
	Backoff func(attempt int) time.Duration

	// now is the clock an outage's day is counted by; nil is time.Now.
	now func() time.Time

	once     sync.Once
	outages  *throttle
	wake     chan struct{}
	stopping chan struct{}
	// ctx is the handlers' context, cancelled when a stop's bound has passed.
	ctx    context.Context
	cancel context.CancelFunc
	// lanes are the deliveries queued for each installation; an installation is in the
	// map while a goroutine handles its lane or while it waits for one, in waiting.
	// running is how many goroutines handle a lane, maxLanes at most. queued are the
	// sequence numbers of the deliveries in a lane, the one being handled among them.
	mu       sync.Mutex
	lanes    map[int64][]Delivery
	waiting  []int64
	running  int
	queued   map[uint64]bool
	maxLanes int
	lanew    sync.WaitGroup
	loop     sync.WaitGroup
}

func (w *Worker) init() {
	w.once.Do(func() {
		w.wake = make(chan struct{}, 1)
		w.stopping = make(chan struct{})
		w.ctx, w.cancel = context.WithCancel(context.Background())
		w.lanes = map[int64][]Delivery{}
		w.queued = map[uint64]bool{}
		if w.maxLanes <= 0 {
			w.maxLanes = maxLanes
		}
		if w.Log == nil {
			w.Log = slog.New(slog.DiscardHandler)
		}
		w.outages = &throttle{every: outageEvery, flush: func(dropped int) {
			w.Log.LogAttrs(context.Background(), slog.LevelWarn, "outages of Qory Apiary dropped", slog.Int("outages_dropped", dropped))
		}}
	})
}

// Start starts handling the store's pending deliveries, those kept before it among
// them, and those kept after it each time [Worker.Notify] is called, or a minute later.
func (w *Worker) Start() {
	w.init()
	w.loop.Add(1)
	go func() {
		defer w.loop.Done()
		t := time.NewTicker(rescan)
		defer t.Stop()
		for {
			w.scan()
			select {
			case <-w.wake:
			case <-t.C:
			case <-w.stopping:
				return
			}
		}
	}()
}

// Notify wakes the worker to read the store's pending deliveries; it never waits.
func (w *Worker) Notify() {
	w.init()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Stop stops handing out deliveries and waits for the handlers that run to return,
// for grace at most. Then it cancels their context, and waits as long again at most.
// A delivery that is not done or failed when its handler returns stays pending.
func (w *Worker) Stop(grace time.Duration) {
	w.init()
	select {
	case <-w.stopping:
		return
	default:
		close(w.stopping)
	}
	w.loop.Wait()
	done := make(chan struct{})
	go func() { w.lanew.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
		w.cancel()
		select {
		case <-done:
		case <-time.After(grace):
		}
	}
	w.cancel()
	w.outages.stop()
}

// scan queues each pending delivery that is not queued yet in its installation's lane,
// and starts a goroutine for a lane that has none, or has it wait for one when
// [maxLanes] run already.
func (w *Worker) scan() {
	pending, err := w.Store.Pending()
	if err != nil {
		w.Log.Error("reading the pending deliveries", slog.String("error", err.Error()))
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, d := range pending {
		if w.queued[d.Seq] {
			continue
		}
		w.queued[d.Seq] = true
		_, present := w.lanes[d.InstallationID]
		w.lanes[d.InstallationID] = append(w.lanes[d.InstallationID], d)
		switch {
		case present:
		case w.running < w.maxLanes:
			w.running++
			w.lanew.Add(1)
			go w.lane(d.InstallationID)
		default:
			w.waiting = append(w.waiting, d.InstallationID)
		}
	}
}

// lane handles an installation's queued deliveries one after another, then the lane
// that has waited longest, if any, and returns when none is left or the worker stops.
// A lane whose delivery the store failed on is dropped, the delivery and those after
// it left pending, so the next scan queues them again in their order.
func (w *Worker) lane(installation int64) {
	defer w.lanew.Done()
	for {
		w.mu.Lock()
		q := w.lanes[installation]
		stopped := false
		select {
		case <-w.stopping:
			stopped = true
		default:
		}
		if len(q) == 0 || stopped {
			w.drop(installation)
			if stopped || len(w.waiting) == 0 {
				w.running--
				w.mu.Unlock()
				return
			}
			installation, w.waiting = w.waiting[0], w.waiting[1:]
			w.mu.Unlock()
			continue
		}
		d := q[0]
		w.mu.Unlock()
		goOn := w.handle(d)
		w.mu.Lock()
		if goOn {
			w.lanes[installation] = w.lanes[installation][1:]
			delete(w.queued, d.Seq)
		} else {
			// The lane is emptied, and the next turn drops it.
			w.drop(installation)
			w.lanes[installation] = nil
		}
		w.mu.Unlock()
	}
}

// drop takes an installation's lane out, with every delivery queued in it. w.mu is
// held.
func (w *Worker) drop(installation int64) {
	for _, d := range w.lanes[installation] {
		delete(w.queued, d.Seq)
	}
	delete(w.lanes, installation)
}

// handle hands one delivery to its handler, and marks it done or failed, or leaves it
// pending when a stop interrupts it. It returns false when the store failed, so the
// delivery is still pending and its lane stops until the next scan.
func (w *Worker) handle(meta Delivery) bool {
	// The delivery is read again, body and all: a scan that read it pending before
	// it was done may have queued it a second time.
	d, err := w.Store.Load(meta.Seq)
	if err != nil {
		w.outcome(meta, "store_failed", slog.String("error", err.Error()))
		return false
	}
	if d.State != store.Pending {
		return true
	}
	h := w.Handlers.handler(d.Event)
	if h == nil {
		return w.settle(d, store.Done, "unhandled")
	}
	attempts := w.Attempts
	if attempts <= 0 {
		attempts = DefaultAttempts
	}
	attempt, held, outage := 1, 0, 0
	first := w.clock()
	for {
		err := call(w.ctx, h, d)
		if err == nil {
			return w.settle(d, store.Done, "done")
		}
		if w.ctx.Err() != nil {
			w.outcome(d, "interrupted")
			return true
		}
		var wait time.Duration
		switch {
		case IsHeld(err):
			held++
			wait = w.backoff(held)
		case IsPermanent(err):
			return w.settle(d, store.Failed, "failed", slog.Int("attempts", attempt), slog.Bool("permanent", true), slog.String("error", err.Error()))
		case IsOutage(err):
			if w.clock().Sub(first) >= outageFor {
				return w.settle(d, store.Failed, "failed", slog.Int("attempts", attempt+outage), slog.Bool("outage", true), slog.String("error", err.Error()))
			}
			if outage == 0 {
				w.logOutage(d, err)
			}
			outage++
			wait = w.backoffTo(outage, outageMaxBackoff)
		case attempt >= attempts:
			return w.settle(d, store.Failed, "failed", slog.Int("attempts", attempt), slog.String("error", err.Error()))
		default:
			wait = w.backoff(attempt)
			attempt++
		}
		select {
		case <-time.After(wait):
		case <-w.stopping:
			w.outcome(d, "interrupted")
			return true
		}
	}
}

// logOutage logs, at most once each outageEvery, that a delivery met Qory Apiary's
// outage and is tried again for a day, with how many such lines were held back.
func (w *Worker) logOutage(d Delivery, err error) {
	ok, dropped := w.outages.allow()
	if !ok {
		return
	}
	attrs := append(deliveryAttrs(d.Event, d.Action, d.GUID, "retrying"), slog.Bool("outage", true), slog.String("error", err.Error()))
	if dropped > 0 {
		attrs = append(attrs, slog.Int("outages_dropped", dropped))
	}
	w.Log.LogAttrs(context.Background(), slog.LevelWarn, "delivery", attrs...)
}

// call calls h, and turns a panic into an error, so one handler's panic fails its
// delivery and stops nothing else. The error names the event alone: the panic's value
// may hold anything, the body's text among it, so it is never logged.
func call(ctx context.Context, h Handler, d Delivery) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("the handler for %s panicked", d.Event)
		}
	}()
	return h.HandleDelivery(ctx, d)
}

// settle marks d done or failed and logs the outcome. It returns false when the store
// failed, so d is still pending.
func (w *Worker) settle(d Delivery, state store.State, outcome string, more ...slog.Attr) bool {
	var err error
	if state == store.Done {
		err = w.Store.MarkDone(d.Seq)
	} else {
		err = w.Store.MarkFailed(d.Seq)
	}
	if err != nil {
		w.outcome(d, "store_failed", slog.String("error", err.Error()))
		return false
	}
	w.outcome(d, outcome, more...)
	return true
}

// outcome logs d's outcome, at the error level when it failed.
func (w *Worker) outcome(d Delivery, outcome string, more ...slog.Attr) {
	level := slog.LevelInfo
	if outcome == "failed" || outcome == "store_failed" {
		level = slog.LevelError
	}
	w.Log.LogAttrs(context.Background(), level, "delivery", append(deliveryAttrs(d.Event, d.Action, d.GUID, outcome), more...)...)
}

// backoff is the wait after the attempt numbered attempt failed.
func (w *Worker) backoff(attempt int) time.Duration { return w.backoffTo(attempt, maxBackoff) }

// backoffTo is the wait after the attempt numbered attempt failed, doubling to most.
func (w *Worker) backoffTo(attempt int, most time.Duration) time.Duration {
	if w.Backoff != nil {
		return w.Backoff(attempt)
	}
	b := firstBackoff
	for i := 1; i < attempt && b < most; i++ {
		b *= 2
	}
	return min(b, most)
}

func (w *Worker) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}
