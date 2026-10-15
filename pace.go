package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// How a [Pacer] keeps within GitHub's rate limits.
const (
	// secondaryWait is how long a secondary rate limit is waited out when GitHub says
	// neither retry-after nor that no request remains.
	secondaryWait = 60 * time.Second
	// maxWait is the longest one wait lasts: a primary limit resets within an hour, so
	// a reset further away is a clock or a header that is wrong.
	maxWait = time.Hour
	// limitedTries is how many times a request GitHub refuses for a rate limit is sent
	// before the refusal is the answer.
	limitedTries = 5
	// pauseBelow is the share of the hour's requests, one in pauseBelow, below which a
	// listing pauses until the limit resets, so that events and writes keep the rest.
	pauseBelow = 5
)

// Pacer paces the requests made to GitHub for one installation of the App: one at a
// time, and within GitHub's rate limits. Every caller that reaches GitHub for the
// installation shares one, since the limits are the installation's.
//
//   - A response that says no request remains, x-ratelimit-remaining 0, holds every
//     request until x-ratelimit-reset.
//   - A 403 or a 429 for a rate limit is sent again after retry-after, when GitHub sets
//     it; else after the reset, when no request remains; else, a secondary rate limit,
//     after 60 seconds. After five refusals the refusal is the answer.
//   - A listing's request waits while fewer than a fifth of x-ratelimit-limit remain,
//     until the limit resets. It waits without the turn, so the installation's other
//     requests, events and writes, go on meanwhile; only the waits for a request that
//     GitHub refused or that has none remaining hold the turn.
//   - A reset or a retry-after further away than an hour is taken as an hour.
//
// The zero value is ready to use.
type Pacer struct {
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Sleep waits d or until ctx is done; nil waits on a timer. A test sets both, so it
	// never sleeps.
	Sleep func(ctx context.Context, d time.Duration) error

	once sync.Once
	turn chan struct{}
	// mu guards what GitHub last said, which a paused listing reads without the turn.
	mu               sync.Mutex
	limit, remaining int
	reset            time.Time
	until            time.Time
}

func (p *Pacer) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pacer) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// do sends one request when it has the turn and GitHub's limits allow it, and again
// while GitHub refuses it for a rate limit. listing marks a listing's request, which
// gives way to others when few requests remain.
func (p *Pacer) do(ctx context.Context, listing bool, send func(context.Context) (*http.Response, error)) (*http.Response, error) {
	p.once.Do(func() { p.turn = make(chan struct{}, 1) })
	for {
		// A listing pauses before it takes the turn, and looks again once it has it,
		// since a request that went meanwhile may have spent what remained.
		if listing {
			if d := p.paused().Sub(p.now()); d > 0 {
				if err := p.sleep(ctx, min(d, maxWait)); err != nil {
					return nil, err
				}
				continue
			}
		}
		select {
		case p.turn <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if listing && p.paused().After(p.now()) {
			<-p.turn
			continue
		}
		break
	}
	defer func() { <-p.turn }()
	for try := 1; ; try++ {
		if err := p.wait(ctx); err != nil {
			return nil, err
		}
		resp, err := send(ctx)
		if err != nil {
			return nil, err
		}
		if !p.observe(resp) || try == limitedTries {
			return resp, nil
		}
		resp.Body.Close()
	}
}

// paused is until when a listing pauses: the reset while fewer than a fifth of the
// limit remain, else the zero time.
func (p *Pacer) paused() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.limit > 0 && p.remaining*pauseBelow < p.limit {
		return p.reset
	}
	return time.Time{}
}

// wait waits, with the turn, until the next request may go: after the reset when none
// remains, or after GitHub's retry-after.
func (p *Pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	until := p.until
	p.mu.Unlock()
	d := until.Sub(p.now())
	if d <= 0 {
		return nil
	}
	return p.sleep(ctx, min(d, maxWait))
}

// observe reads GitHub's rate limit headers from a response and says whether GitHub
// refused the request for a rate limit, so it is to be sent again.
func (p *Pacer) observe(resp *http.Response) bool {
	// A 403's body is read before the lock, so a paused listing never waits on it.
	secondary := resp.StatusCode == http.StatusForbidden && secondaryLimit(resp)
	p.mu.Lock()
	defer p.mu.Unlock()
	h := resp.Header
	now := p.now()
	exhausted := false
	if n, err := strconv.Atoi(h.Get("X-Ratelimit-Limit")); err == nil {
		p.limit = n
	}
	if n, err := strconv.ParseInt(h.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
		p.reset = time.Unix(n, 0)
		if p.reset.After(now.Add(maxWait)) {
			p.reset = now.Add(maxWait)
		}
	}
	if n, err := strconv.Atoi(h.Get("X-Ratelimit-Remaining")); err == nil {
		p.remaining = n
		if n == 0 && p.reset.After(p.until) {
			p.until = p.reset
			exhausted = true
		}
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	if d, ok := retryAfter(h.Get("Retry-After"), now); ok {
		p.until = now.Add(d)
		return true
	}
	if exhausted || h.Get("X-Ratelimit-Remaining") == "0" {
		return true
	}
	if resp.StatusCode == http.StatusForbidden && !secondary {
		return false
	}
	p.until = now.Add(secondaryWait)
	return true
}

// retryAfter reads retry-after, seconds or an HTTP date, and takes more than an hour
// as an hour; the seconds are cut before they are multiplied, so they never overflow.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		return time.Duration(min(n, int64(maxWait/time.Second))) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(t.Sub(now), 0), maxWait), true
	}
	return 0, false
}

// secondaryLimit is whether a 403 is GitHub's secondary rate limit, which its message
// says, rather than a refusal of the request. The body is read and put back.
func secondaryLimit(resp *http.Response) bool {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	var e struct {
		Message string `json:"message"`
	}
	json.Unmarshal(b, &e)
	return strings.Contains(strings.ToLower(e.Message), "rate limit")
}

// maxAnswer is the largest answer [Client.send] reads, 64 MiB: a page of a hundred
// issues or comments of GitHub's longest, 65,536 characters, fits when no character
// takes more than ten bytes, which holds for UTF-8 and for a character of the Basic
// Multilingual Plane escaped as \uXXXX. A larger answer is refused, never read in part.
const maxAnswer = 64 << 20

// apiReply is GitHub's answer to one request [Client.send] made: its status, its header
// and its body.
type apiReply struct {
	status int
	header http.Header
	body   []byte
}

// err is the answer as an [answerError] for the request what names.
func (a *apiReply) err(what string) error {
	var e struct {
		Message string `json:"message"`
	}
	json.Unmarshal(a.body, &e)
	if e.Message == "" {
		e.Message = http.StatusText(a.status)
	}
	return &answerError{what: what, status: a.status, message: e.Message}
}

// send makes one request to the API with an installation token, paced by p, or by a new
// Pacer when p is nil, and returns GitHub's answer whatever its status, so the caller
// reads the status, and the Link header for a list's next page. listing marks a
// listing's request, see [Pacer]. It is [Client.call] with the answer handed back: it
// refuses an API [CheckAPIURL] refuses before anything is sent, follows no redirect,
// refuses an answer larger than [maxAnswer] having read at most one byte more, and its
// error begins with what and never says the request, its path, its header or its body.
func (c Client) send(ctx context.Context, p *Pacer, listing bool, what, method, path, tok string, body any) (*apiReply, error) {
	base := c.base()
	if err := CheckAPIURL(base); err != nil {
		return nil, err
	}
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	if p == nil {
		p = &Pacer{}
	}
	request := func(ctx context.Context) (*http.Response, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, r)
		if err != nil {
			return nil, fmt.Errorf("%s: the request could not be made: %w", what, unsent(err, path))
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "qory-github")
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		hc := http.Client{Timeout: 30 * time.Second}
		if c.HTTP != nil {
			hc = *c.HTTP
		}
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: GitHub's API could not be reached: %w", what, unsent(err, path))
		}
		return resp, nil
	}
	resp, err := p.do(ctx, listing, request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	a, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("%s: GitHub's answer could not be read: %w", what, unsent(err, path))
	}
	if len(a) > maxAnswer {
		return nil, fmt.Errorf("%s: GitHub's answer is larger than %d bytes", what, maxAnswer)
	}
	return &apiReply{status: resp.StatusCode, header: resp.Header, body: a}, nil
}

// get reads one page from the API with an installation token, paced by p, and decodes
// it into out. It returns the path and query of the next page, see [nextPage], or "" on
// the last page. Like [Client.send], it follows no redirect, and its error begins with
// what and never says the request, its path or its token.
func (c Client) get(ctx context.Context, p *Pacer, listing bool, what, path, token string, out any) (string, error) {
	a, err := c.send(ctx, p, listing, what, http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	if a.status != http.StatusOK {
		return "", a.err(what)
	}
	if err := json.Unmarshal(a.body, out); err != nil {
		return "", fmt.Errorf("%s: GitHub's answer: %w", what, err)
	}
	next, err := nextPage(a.header.Values("Link"), c.base())
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return next, nil
}

// errNextElsewhere refuses a next page that is not on the API.
var errNextElsewhere = errors.New("the next page GitHub names is not on the API, so it is not read")

// nextPage is the path and query of the next page that links, every Link header of an
// answer, name: the first entry whose rel, among the values it lists, is next in any
// case. It is "" when there is none. A next page on another scheme, host name or port
// than base's, with a user, opaque, or with a path that does not start with /, is
// [errNextElsewhere], so the token goes to GitHub's API alone; a port left out is the
// scheme's, so https://api.github.com and https://api.github.com:443 are the same.
func nextPage(links []string, base string) (string, error) {
	for _, l := range links {
		for part := range strings.SplitSeq(l, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
			if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
				continue
			}
			next := false
			for param := range strings.SplitSeq(params, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "rel") && slices.ContainsFunc(strings.Fields(strings.Trim(strings.TrimSpace(v), `"`)), func(r string) bool { return strings.EqualFold(r, "next") }) {
					next = true
				}
			}
			if !next {
				continue
			}
			u, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">"))
			b, berr := url.Parse(base)
			if err != nil || berr != nil || u.Scheme != b.Scheme || u.Hostname() != b.Hostname() || effectivePort(u) != effectivePort(b) || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.EscapedPath(), "/") {
				return "", errNextElsewhere
			}
			return u.RequestURI(), nil
		}
	}
	return "", nil
}

// effectivePort is the URL's port, or its scheme's when it names none: 80 for http,
// 443 for https and any other.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
