package serve

import (
	"sync"
	"time"
)

// throttle lets a kind of line be logged once each every at most, so a sender with no
// secret cannot fill the log. A line it holds back is counted: the next line allowed
// says how many were dropped; when none comes, flush is called with the count once the
// period is over, and [throttle.stop] calls it with any count left, so a burst's count
// is logged before serve stops.
type throttle struct {
	// every is the period; now is the clock, nil time.Now; flush logs a count of the
	// lines dropped when no line came after them.
	every time.Duration
	now   func() time.Time
	flush func(dropped int)

	mu      sync.Mutex
	last    time.Time
	dropped int
	timer   *time.Timer
	// gen numbers the timer that is set; a tick of an earlier one does nothing.
	gen     uint64
	stopped bool
}

// allow is whether a line may be logged now, and how many were dropped since the last
// one when it may.
func (t *throttle) allow() (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	if !t.last.IsZero() && now.Sub(t.last) < t.every {
		t.dropped++
		if t.timer == nil && t.flush != nil && !t.stopped {
			t.gen++
			gen := t.gen
			t.timer = time.AfterFunc(t.last.Add(t.every).Sub(now), func() { t.tick(gen) })
		}
		return false, 0
	}
	t.cancel()
	dropped := t.dropped
	t.last, t.dropped = now, 0
	return true, dropped
}

// tick flushes the count of the lines dropped in the period that is over, if any,
// when gen is the timer that is set.
func (t *throttle) tick(gen uint64) {
	t.mu.Lock()
	if gen != t.gen || t.timer == nil {
		t.mu.Unlock()
		return
	}
	t.timer = nil
	dropped := t.dropped
	if dropped > 0 {
		t.last, t.dropped = t.clock(), 0
	}
	t.mu.Unlock()
	if dropped > 0 {
		t.flush(dropped)
	}
}

// stop stops the timer and flushes the count of the lines dropped, if any. A line
// held back after it is counted and never flushed.
func (t *throttle) stop() {
	t.mu.Lock()
	t.cancel()
	t.stopped = true
	dropped := t.dropped
	t.dropped = 0
	t.mu.Unlock()
	if dropped > 0 && t.flush != nil {
		t.flush(dropped)
	}
}

// cancel stops the timer that is set, if any, and makes a tick of it do nothing. t.mu
// is held.
func (t *throttle) cancel() {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	t.gen++
}

func (t *throttle) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}
