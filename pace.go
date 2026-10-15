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
//     until the limit resets.
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
	// What GitHub last said, read and written only while a request has the turn.
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
	select {
	case p.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.turn }()
	for try := 1; ; try++ {
		if err := p.wait(ctx, listing); err != nil {
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

// wait waits until the next request may go.
func (p *Pacer) wait(ctx context.Context, listing bool) error {
	until := p.until
	if listing && p.limit > 0 && p.remaining*pauseBelow < p.limit && p.reset.After(until) {
		until = p.reset
	}
	d := until.Sub(p.now())
	if d <= 0 {
		return nil
	}
	return p.sleep(ctx, min(d, maxWait))
}

// observe reads GitHub's rate limit headers from a response and says whether GitHub
// refused the request for a rate limit, so it is to be sent again.
func (p *Pacer) observe(resp *http.Response) bool {
	h := resp.Header
	now := p.now()
	exhausted := false
	if n, err := strconv.Atoi(h.Get("X-Ratelimit-Limit")); err == nil {
		p.limit = n
	}
	if n, err := strconv.ParseInt(h.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
		p.reset = time.Unix(n, 0)
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
	if resp.StatusCode == http.StatusForbidden && !secondaryLimit(resp) {
		return false
	}
	p.until = now.Add(secondaryWait)
	return true
}

// retryAfter reads retry-after, seconds or an HTTP date.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
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

// get reads one page from the API with an installation token, paced by p, and decodes
// it into out. It returns the path and query of the next page, from the Link header's
// next, or "" on the last page. A next page on another scheme or host than the API's
// is refused, so the token goes to GitHub's API alone. Like [Client.call], it follows
// no redirect, and its error begins with what and never says the request, its path or
// its token.
func (c Client) get(ctx context.Context, p *Pacer, listing bool, what, path, token string, out any) (string, error) {
	base := c.base()
	if err := CheckAPIURL(base); err != nil {
		return "", err
	}
	send := func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+path, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: the request could not be made: %w", what, unsent(err, path))
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "qory-github")
		req.Header.Set("Authorization", "Bearer "+token)
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
	resp, err := p.do(ctx, listing, send)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		return "", err
	}
	defer resp.Body.Close()
	// A page of a hundred issues with long bodies is a few megabytes at most.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("%s: GitHub's answer could not be read: %w", what, unsent(err, path))
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return "", &answerError{what: what, status: resp.StatusCode, message: e.Message}
	}
	if err := json.Unmarshal(b, out); err != nil {
		return "", fmt.Errorf("%s: GitHub's answer: %w", what, err)
	}
	next, ok := nextPage(resp.Header.Get("Link"), base)
	if !ok {
		return "", fmt.Errorf("%s: GitHub's next page is not on its API, so it is not read", what)
	}
	return next, nil
}

// nextPage is the path and query of the Link header's next page, "" when there is
// none, and false when it is on another scheme or host than base.
func nextPage(link, base string) (string, bool) {
	for part := range strings.SplitSeq(link, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		next := false
		for param := range strings.SplitSeq(params, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(param), "="); ok && strings.EqualFold(k, "rel") && strings.Contains(" "+strings.Trim(v, `"`)+" ", " next ") {
				next = true
			}
		}
		if !next {
			continue
		}
		u, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">"))
		b, berr := url.Parse(base)
		if err != nil || berr != nil || u.Scheme != b.Scheme || u.Hostname() != b.Hostname() || port(u) != port(b) || u.User != nil || !strings.HasPrefix(u.Path, "/") {
			return "", false
		}
		return u.RequestURI(), true
	}
	return "", true
}

// port is a URL's port, its scheme's when it says none.
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
