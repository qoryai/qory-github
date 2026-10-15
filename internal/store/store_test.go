package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a time a test sets and moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func open(t *testing.T, dir string, c *clock) *Store {
	t.Helper()
	s, err := Open(dir, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func delivery(guid string, installation int64) Delivery {
	return Delivery{GUID: guid, Event: "issues", Action: "opened", InstallationID: installation, Body: []byte(`{"action":"opened"}`)}
}

const (
	guid1 = "72d3162e-cc78-11e3-81ab-4c9367dc0958"
	guid2 = "8a1e6b40-0f6c-11ef-9d3a-0242ac120002"
	guid3 = "9b2f7c51-1a7d-11ef-8e4b-0242ac120003"
)

func TestADeliveryIsKeptOnceAndPendingUntilSettled(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "state"), c)
	d, added, err := s.AddDelivery(delivery(guid1, 7))
	if err != nil || !added || d.Seq != 1 || d.State != Pending || !d.Received.Equal(c.now) {
		t.Fatalf("%+v %v %v", d, added, err)
	}
	again, added, err := s.AddDelivery(delivery(guid1, 7))
	if err != nil || added || again.Seq != 1 {
		t.Fatalf("a repeat GUID: %+v %v %v", again, added, err)
	}
	s.AddDelivery(delivery(guid2, 8))
	s.AddDelivery(delivery(guid3, 7))
	pending, err := s.Pending()
	if err != nil || len(pending) != 3 || pending[0].GUID != guid1 || pending[1].GUID != guid2 || pending[2].GUID != guid3 || pending[0].Body != nil {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if err := s.MarkDone(1); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFailed(2); err != nil {
		t.Fatal(err)
	}
	if d, err := s.Load(1); err != nil || d.State != Done || d.Body != nil {
		t.Errorf("done: %+v %v", d, err)
	}
	if d, err := s.Load(2); err != nil || d.State != Failed || string(d.Body) != `{"action":"opened"}` {
		t.Errorf("failed: %+v %v", d, err)
	}
	if pending, _ := s.Pending(); len(pending) != 1 || pending[0].Seq != 3 {
		t.Errorf("pending %+v", pending)
	}
	if _, err := s.Load(42); !errors.Is(err, ErrNotFound) {
		t.Errorf("err %v", err)
	}
	if _, err := s.Lookup("none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err %v", err)
	}
}

func TestPendingDeliveriesSurviveAReopen(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	s.AddDelivery(delivery(guid1, 7))
	s.AddDelivery(delivery(guid2, 7))
	s.MarkDone(1)
	s.Close()
	s = open(t, dir, c)
	pending, err := s.Pending()
	if err != nil || len(pending) != 1 || pending[0].GUID != guid2 {
		t.Fatalf("pending %+v %v", pending, err)
	}
	if _, added, _ := s.AddDelivery(delivery(guid1, 7)); added {
		t.Error("a GUID kept before the reopen is taken again")
	}
	if d, _, _ := s.AddDelivery(delivery(guid3, 7)); d.Seq != 3 {
		t.Errorf("the next number is %d, want 3", d.Seq)
	}
}

func TestAGUIDExpiresSevenDaysAfterItIsReceived(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "state"), c)
	s.AddDelivery(delivery(guid1, 7))
	s.AddDelivery(delivery(guid2, 7))
	s.MarkDone(1)
	c.Add(DeliveryRetention - time.Second)
	if n, err := s.Sweep(); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if _, added, _ := s.AddDelivery(delivery(guid1, 7)); added {
		t.Error("a GUID is taken again before seven days")
	}
	c.Add(time.Second)
	if n, err := s.Sweep(); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := s.Lookup(guid1); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired GUID is found: %v", err)
	}
	if _, err := s.Lookup(guid2); err != nil {
		t.Errorf("a pending delivery expired: %v", err)
	}
	if d, added, err := s.AddDelivery(delivery(guid1, 7)); err != nil || !added || d.Seq != 3 {
		t.Errorf("an expired GUID is not taken again: %+v %v %v", d, added, err)
	}
}

func TestAValueIsKeptUnderItsNamespaceUntilItExpires(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "state"), c)
	if err := s.Put("tokens", "42", []byte("a"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("other", "42", []byte("b"), 0); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get("tokens", "42"); err != nil || string(v) != "a" {
		t.Errorf("%q %v", v, err)
	}
	if _, err := s.Get("tokens", "43"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err %v", err)
	}
	if _, err := s.Get("none", "42"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err %v", err)
	}
	c.Add(time.Hour)
	if _, err := s.Get("tokens", "42"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired value: %v", err)
	}
	if _, err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get("other", "42"); err != nil || string(v) != "b" {
		t.Errorf("a value with no expiry: %q %v", v, err)
	}
	if err := s.Delete("other", "42"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("other", "42"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a deleted value: %v", err)
	}
	if err := s.Put("", "k", nil, 0); err == nil {
		t.Error("an empty namespace is taken")
	}
	if err := s.Put("ns", "k", nil, -time.Second); err == nil {
		t.Error("a negative time to live is taken")
	}
}

func TestTheStoreIsOnlyItsOwners(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	c := &clock{now: time.Now()}
	s := open(t, dir, c)
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, FileName): 0o600} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %s", path, info.Mode().Perm(), err, want)
		}
	}
	if _, err := Open(dir, Options{}); err == nil || !strings.Contains(err.Error(), "open in another process") {
		t.Errorf("a second open: %v", err)
	}
	s.Close()

	open := filepath.Join(parent, "open")
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o755)
	if _, err := Open(open, Options{}); err == nil || !strings.Contains(err.Error(), "group or others have permissions on it; make it 0700") {
		t.Errorf("a directory others read: %v", err)
	}
	link := filepath.Join(parent, "link")
	os.Symlink(dir, link)
	if _, err := Open(link, Options{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a link: %v", err)
	}
	file := filepath.Join(parent, "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := Open(file, Options{}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file: %v", err)
	}
	loose := filepath.Join(parent, "loose")
	os.Mkdir(loose, 0o700)
	os.WriteFile(filepath.Join(loose, FileName), nil, 0o644)
	os.Chmod(filepath.Join(loose, FileName), 0o644)
	if _, err := Open(loose, Options{}); err == nil || !strings.Contains(err.Error(), "the store") || !strings.Contains(err.Error(), "make it 0600") {
		t.Errorf("a store file others read: %v", err)
	}
}
