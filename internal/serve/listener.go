package serve

import (
	"net"
	"sync"
)

// maxConns is how many connections serve keeps open at once. A connection beyond it
// waits to be accepted until one closes.
const maxConns = 128

// limitListener accepts a connection only while fewer than its bound are open, as
// golang.org/x/net/netutil's LimitListener does, without that module.
type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

// limit is ln accepting n connections at once at most.
func limit(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{})}
}

// Accept waits for a free slot, then for a connection, which frees its slot when it is
// closed.
func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
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
