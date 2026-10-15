package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the fake clock's start.
var t0 = time.Unix(1_790_000_000, 0)

// fakeClock is a pacer's clock and sleeper: a sleep records how long it was asked to
// wait and moves the clock on by as much, so a test never sleeps.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	slept  []time.Duration
	cancel bool // a sleep answers that its context is done
}

func (c *fakeClock) pacer() *Pacer {
	c.now = t0
	return &Pacer{
		Now: func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now },
		Sleep: func(_ context.Context, d time.Duration) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.slept = append(c.slept, d)
			if c.cancel {
				return context.Canceled
			}
			c.now = c.now.Add(d)
			return nil
		},
	}
}

// reply is one scripted answer of the API.
type reply struct {
	status  int
	headers map[string]string
	body    string
}

// scripted is GitHub's API answering requests in turn with replies, the last one
// again once they run out.
type scripted struct {
	mu      sync.Mutex
	replies []reply
	n       int
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	r := s.replies[min(s.n, len(s.replies)-1)]
	s.n++
	s.mu.Unlock()
	for k, v := range r.headers {
		w.Header().Set(k, v)
	}
	if r.status == 0 {
		r.status = 200
	}
	w.WriteHeader(r.status)
	if r.body == "" {
		r.body = "{}"
	}
	io.WriteString(w, r.body)
}

func (s *scripted) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func unix(d time.Duration) string { return strconv.FormatInt(t0.Add(d).Unix(), 10) }

func TestPacerWaitsOutGitHubsRateLimits(t *testing.T) {
	ok := reply{headers: map[string]string{"X-Ratelimit-Limit": "5000", "X-Ratelimit-Remaining": "4000", "X-Ratelimit-Reset": unix(time.Hour)}}
	for _, tc := range []struct {
		name     string
		replies  []reply
		listing  bool
		requests int
		slept    []time.Duration
		err      string
	}{
		{"no request remains: the next waits until the reset", []reply{
			{headers: map[string]string{"X-Ratelimit-Limit": "5000", "X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": unix(120 * time.Second)}}, ok,
		}, false, 2, []time.Duration{120 * time.Second}, ""},
		{"a 403 with no request remaining is sent again after the reset", []reply{
			{status: 403, headers: map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": unix(30 * time.Second)}, body: `{"message":"API rate limit exceeded"}`}, ok,
		}, false, 2, []time.Duration{30 * time.Second}, ""},
		{"a 429 with retry-after", []reply{{status: 429, headers: map[string]string{"Retry-After": "7"}}, ok}, false, 2, []time.Duration{7 * time.Second}, ""},
		{"a 403 with retry-after", []reply{{status: 403, headers: map[string]string{"Retry-After": "3"}, body: `{"message":"You have exceeded a secondary rate limit"}`}, ok}, false, 2, []time.Duration{3 * time.Second}, ""},
		{"a secondary rate limit without either header waits a minute", []reply{{status: 403, body: `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`}, ok}, false, 2, []time.Duration{time.Minute}, ""},
		{"a 429 without either header waits a minute", []reply{{status: 429}, ok}, false, 2, []time.Duration{time.Minute}, ""},
		{"a 403 that is no rate limit is the answer", []reply{{status: 403, body: `{"message":"Resource not accessible by integration"}`}}, false, 1, nil, "reading: GitHub answered 403: Resource not accessible by integration"},
		{"five refusals are the answer", []reply{{status: 429, headers: map[string]string{"Retry-After": "1"}, body: `{"message":"slow down"}`}}, false, 5, []time.Duration{time.Second, time.Second, time.Second, time.Second}, "reading: GitHub answered 429: slow down"},
		{"a listing pauses below a fifth of the limit until the reset", []reply{
			{headers: map[string]string{"X-Ratelimit-Limit": "5000", "X-Ratelimit-Remaining": "999", "X-Ratelimit-Reset": unix(600 * time.Second)}}, ok,
		}, true, 2, []time.Duration{600 * time.Second}, ""},
		{"a listing goes on at a fifth", []reply{
			{headers: map[string]string{"X-Ratelimit-Limit": "5000", "X-Ratelimit-Remaining": "1000", "X-Ratelimit-Reset": unix(600 * time.Second)}}, ok,
		}, true, 2, nil, ""},
		{"another request goes on below a fifth", []reply{
			{headers: map[string]string{"X-Ratelimit-Limit": "5000", "X-Ratelimit-Remaining": "10", "X-Ratelimit-Reset": unix(600 * time.Second)}}, ok,
		}, false, 2, nil, ""},
	} {
		s := &scripted{replies: tc.replies}
		srv := httptest.NewServer(s)
		clock := &fakeClock{}
		p := clock.pacer()
		c := Client{API: srv.URL}
		var out any
		_, err := c.get(context.Background(), p, tc.listing, "reading", "/a", fakeToken, &out)
		if err == nil && s.count() < tc.requests {
			_, err = c.get(context.Background(), p, tc.listing, "reading", "/b", fakeToken, &out)
		}
		srv.Close()
		if (err == nil) != (tc.err == "") || (err != nil && err.Error() != tc.err) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.err)
		}
		if s.count() != tc.requests || len(clock.slept) != len(tc.slept) {
			t.Errorf("%s: %d requests, slept %v; want %d, %v", tc.name, s.count(), clock.slept, tc.requests, tc.slept)
			continue
		}
		for i := range tc.slept {
			if clock.slept[i] != tc.slept[i] {
				t.Errorf("%s: slept %v, want %v", tc.name, clock.slept, tc.slept)
			}
		}
	}
}

// TestAWaitEndsWithItsContext has a request wait for the reset with a context that is
// done, and checks it fails without being sent.
func TestAWaitEndsWithItsContext(t *testing.T) {
	s := &scripted{replies: []reply{{headers: map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": unix(time.Hour)}}}}
	srv := httptest.NewServer(s)
	defer srv.Close()
	clock := &fakeClock{}
	p := clock.pacer()
	c := Client{API: srv.URL}
	var out any
	if _, err := c.get(context.Background(), p, false, "reading", "/a", fakeToken, &out); err != nil {
		t.Fatal(err)
	}
	clock.cancel = true
	if _, err := c.get(context.Background(), p, false, "reading", "/a", fakeToken, &out); err == nil || err.Error() != "reading: context canceled" || s.count() != 1 {
		t.Errorf("err %v, %d requests", err, s.count())
	}
}

// TestOneInstallationsRequestsGoOneAtATime sends requests from many goroutines through
// one pacer and checks GitHub never has two at once.
func TestOneInstallationsRequestsGoOneAtATime(t *testing.T) {
	var mu sync.Mutex
	inFlight, most := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		io.WriteString(w, "{}")
	}))
	defer srv.Close()
	p := &Pacer{}
	c := Client{API: srv.URL}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			var out any
			if _, err := c.get(context.Background(), p, false, "reading", "/a", fakeToken, &out); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if most != 1 {
		t.Errorf("%d requests at once", most)
	}
}

func TestTheNextPageIsOnTheAPIAlone(t *testing.T) {
	const base = "https://api.github.com"
	for _, tc := range []struct {
		link, next string
		ok         bool
	}{
		{"", "", true},
		{`<https://api.github.com/repositories/1/issues?page=2>; rel="next", <https://api.github.com/repositories/1/issues?page=5>; rel="last"`, "/repositories/1/issues?page=2", true},
		{`<https://api.github.com/repositories/1/issues?page=1>; rel="prev", <https://api.github.com/repositories/1/issues?page=1>; rel="first"`, "", true},
		{`<https://api.github.com:443/x?page=2>; rel="next"`, "/x?page=2", true},
		{`<https://elsewhere.example/x?page=2>; rel="next"`, "", false},
		{`<http://api.github.com/x?page=2>; rel="next"`, "", false},
		{`<https://user@api.github.com/x?page=2>; rel="next"`, "", false},
	} {
		next, ok := nextPage(tc.link, base)
		if next != tc.next || ok != tc.ok {
			t.Errorf("%s: %q %v, want %q %v", tc.link, next, ok, tc.next, tc.ok)
		}
	}
}

// TestAPageNeverSaysTheToken has GitHub refuse a page and checks the token is in no
// error.
func TestAPageNeverSaysTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()
	var out any
	_, err := Client{API: srv.URL}.get(context.Background(), &Pacer{}, true, "listing", "/repos/acme/widgets/issues", fakeToken, &out)
	if err == nil || err.Error() != "listing: GitHub answered 401: Bad credentials" {
		t.Errorf("err %v", err)
	}
	_, err = Client{API: unreachable(t)}.get(context.Background(), &Pacer{}, true, "listing", "/repos/acme/widgets/issues", fakeToken, &out)
	if err == nil || strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), "/repos/") {
		t.Errorf("err %v", err)
	}
}
