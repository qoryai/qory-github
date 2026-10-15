package serve

import (
	"sync"
	"time"
)

// throttle lets a kind of line be logged once each every at most, so a sender with no
// secret cannot fill the log. A line it holds back is counted: the next line allowed
// says how many were dropped, and when none comes, flush is called with the count once
// the period is over, so a burst's count is never lost.
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
}

// allow is whether a line may be logged now, and how many were dropped since the last
// one when it may.
func (t *throttle) allow() (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	if !t.last.IsZero() && now.Sub(t.last) < t.every {
		t.dropped++
		if t.timer == nil && t.flush != nil {
			t.timer = time.AfterFunc(t.last.Add(t.every).Sub(now), t.tick)
		}
		return false, 0
	}
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	dropped := t.dropped
	t.last, t.dropped = now, 0
	return true, dropped
}

// tick flushes the count of the lines dropped in the period that is over, if any.
func (t *throttle) tick() {
	t.mu.Lock()
	t.timer = nil
	dropped := t.dropped
	if dropped == 0 {
		t.mu.Unlock()
		return
	}
	t.last, t.dropped = t.clock(), 0
	t.mu.Unlock()
	t.flush(dropped)
}

func (t *throttle) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}
