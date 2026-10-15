package serve

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// maxConns is how many connections serve keeps open at once. A connection beyond it
// waits to be accepted until one closes. A connection pins no body's memory, see
// [readBudget], and an idle one is closed after [idleTimeout], so the bound is high.
const maxConns = 1024

// limitListener accepts a connection only while fewer than its bound are open, as
// golang.org/x/net/netutil's LimitListener does, without that module. When the bound is
// reached it logs so, once a second at most, with a count of the times it was reached
// in between.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
	log   *slog.Logger
	full  *throttle
}

// limit is ln accepting n connections at once at most, logging to log, when it is not
// nil, each time it is full, once a second at most.
func limit(ln net.Listener, n int, log *slog.Logger) net.Listener {
	l := &limitListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{}), log: log}
	l.full = &throttle{every: time.Second, flush: l.logFull}
	return l
}

// Accept waits for a free slot, then for a connection, which frees its slot when it is
// closed.
func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	default:
		if ok, dropped := l.full.allow(); ok {
			l.logFull(dropped)
		}
		select {
		case l.slots <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
}

// logFull logs that the connections are at the bound, and how many times more they
// were since the last such line.
func (l *limitListener) logFull(dropped int) {
	if l.log == nil {
		return
	}
	attrs := []any{slog.Int("max", cap(l.slots))}
	if dropped > 0 {
		attrs = append(attrs, slog.Int("dropped", dropped))
	}
	l.log.Warn("connections at the bound", attrs...)
}

// Close closes the listener, and wakes an Accept that waits for a slot.
func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// limitConn is an accepted connection, which frees its slot once, on its first close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close closes the connection and frees its slot.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite closes the connection's writing side when it has one to close, as a TCP
// connection has. net/http does so before it closes a connection after an answer such as
// 413, so the client reads the answer rather than a reset; without it net/http would
// not find the method on the wrapper.
func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
