package serve

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestAConnectionBeyondTheBoundWaitsForOneToClose(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limit(inner, 1, nil)
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 2 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first := <-accepted
	select {
	case <-accepted:
		t.Fatal("a second connection is accepted while the first is open")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	first.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the second connection is not accepted once the first is closed")
	}
}

func TestClosingTheListenerWakesAnAcceptThatWaits(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limit(inner, 1, nil)
	c, _ := net.Dial("tcp", inner.Addr().String())
	defer c.Close()
	held, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	done := make(chan error, 1)
	go func() { _, err := ln.Accept(); done <- err }()
	time.Sleep(20 * time.Millisecond)
	ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still waits")
	}
}

func TestAnAcceptedConnectionCanCloseItsWritingSide(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limit(inner, 1, nil)
	defer ln.Close()
	c, _ := net.Dial("tcp", inner.Addr().String())
	defer c.Close()
	got, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	cw, ok := got.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the connection has no CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("the client reads %v, want the end of the stream", err)
	}
}
