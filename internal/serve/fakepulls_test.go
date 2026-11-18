package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ghPullRec is a pull request of the stand-in GitHub: where it is, its head and base,
// and its state. headRepo is the repository the head branch is in, repo when empty, as
// for a pull request from a fork.
type ghPullRec struct {
	repo, headRepo, head, base string
	number                     int
	title, body                string
	draft, closed, merged      bool
}

// pullStore is the stand-in GitHub's pull requests, under f.mu, with what a test may
// change: pullFail answers a request, by its method and path, with a status and a body
// when it returns a status other than 0; goneBranches are the branches the repository
// has none of, by name; noInstallation are the repositories the App has no installation
// on, by owner/name.
type pullStore struct {
	pulls          []*ghPullRec
	pullFail       func(method, path string) (int, string)
	goneBranches   map[string]bool
	noInstallation map[string]bool
}

// pullsRoute reports whether path is one of the pull request API's of a repository the
// stand-in answers: the installation of the App, the pull requests, one pull request.
// acme/moved is left to the stand-in's redirect.
func pullsRoute(path string) (repo, rest string, ok bool) {
	p, found := strings.CutPrefix(path, "/repos/")
	if !found || strings.HasPrefix(p, "acme/moved/") {
		return "", "", false
	}
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 3 {
		return "", "", false
	}
	rest = parts[2]
	if rest != "installation" && rest != "pulls" && !strings.HasPrefix(rest, "pulls/") {
		return "", "", false
	}
	return parts[0] + "/" + parts[1], rest, true
}

// pullsAPI answers a request of the pull request API, see [pullsRoute], and the
// repository's installation. f.mu is held.
func (f *fakeGitHub) pullsAPI(w http.ResponseWriter, r *http.Request, b []byte, repo, rest string) {
	answer := func(status int, body string) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
	if f.pullFail != nil {
		if status, body := f.pullFail(r.Method, r.URL.Path); status != 0 {
			answer(status, body)
			return
		}
	}
	if rest == "installation" {
		if !strings.HasPrefix(repo, "acme/") || f.noInstallation[repo] {
			answer(404, `{"message":"Not Found"}`)
			return
		}
		answer(200, `{"id":42,"account":{"login":"acme"}}`)
		return
	}
	switch {
	case r.Method == http.MethodGet && rest == "pulls":
		head := r.URL.Query().Get("head")
		owner, ref, _ := strings.Cut(head, ":")
		out := []map[string]any{}
		for _, p := range f.pulls {
			if p.repo == repo && p.head == ref && strings.HasPrefix(p.headRepoName(), owner+"/") {
				out = append(out, p.json(false))
			}
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && rest == "pulls":
		f.openPull(w, repo, b)
	case strings.HasPrefix(rest, "pulls/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(rest, "pulls/"))
		var found *ghPullRec
		for _, p := range f.pulls {
			if p.repo == repo && p.number == n {
				found = p
			}
		}
		switch {
		case found == nil:
			answer(404, `{"message":"Not Found"}`)
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(found.json(true))
		case r.Method == http.MethodPatch:
			var req struct {
				Title *string `json:"title"`
				Body  *string `json:"body"`
			}
			json.Unmarshal(b, &req)
			if status, body := pullTextRefused(deref(req.Title), deref(req.Body)); status != 0 {
				answer(status, body)
				return
			}
			if req.Title != nil {
				found.title = *req.Title
			}
			if req.Body != nil {
				found.body = *req.Body
			}
			json.NewEncoder(w).Encode(found.json(true))
		default:
			answer(405, `{"message":"Method Not Allowed"}`)
		}
	default:
		answer(404, `{"message":"Not Found"}`)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// pullTextRefused is GitHub's 422 for a title or a description over its limits, 256
// and 65536 characters, or 0.
func pullTextRefused(title, body string) (int, string) {
	switch {
	case utf8.RuneCountInString(title) > 256:
		return 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"title","code":"custom","message":"title is too long (maximum is 256 characters)"}]}`
	case utf8.RuneCountInString(body) > 65536:
		return 422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"body","code":"custom","message":"body is too long (maximum is 65536 characters)"}]}`
	}
	return 0, ""
}

// openPull answers POST /repos/{repo}/pulls, as GitHub does for a draft pull request
// from a branch of the repository.
func (f *fakeGitHub) openPull(w http.ResponseWriter, repo string, b []byte) {
	var req struct {
		Title, Body, Head, Base string
		Draft                   bool
	}
	json.Unmarshal(b, &req)
	refuse := func(status int, body string) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
	switch {
	case f.goneBranches[req.Head]:
		refuse(422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}],"documentation_url":"https://docs.github.com/rest/pulls/pulls#create-a-pull-request"}`)
		return
	case f.goneBranches[req.Base]:
		refuse(422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"base","code":"invalid"}]}`)
		return
	}
	if status, body := pullTextRefused(req.Title, req.Body); status != 0 {
		refuse(status, body)
		return
	}
	n := 0
	for _, p := range f.pulls {
		if p.repo == repo {
			n = max(n, p.number)
			if p.head == req.Head && p.base == req.Base && p.headRepoName() == repo && !p.closed {
				refuse(422, `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"A pull request already exists for `+repo+`:`+req.Head+`."}]}`)
				return
			}
		}
	}
	p := &ghPullRec{repo: repo, head: req.Head, base: req.Base, number: n + 1, title: req.Title, body: req.Body, draft: req.Draft}
	f.pulls = append(f.pulls, p)
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(p.json(true))
}

// headRepoName is the repository the head branch is in.
func (p *ghPullRec) headRepoName() string {
	if p.headRepo != "" {
		return p.headRepo
	}
	return p.repo
}

// json is the pull request as GitHub writes it: a list's item has no merged, only
// merged_at.
func (p *ghPullRec) json(full bool) map[string]any {
	state := "open"
	if p.closed || p.merged {
		state = "closed"
	}
	var body any
	if p.body != "" {
		body = p.body
	}
	var mergedAt any
	if p.merged {
		mergedAt = "2026-11-17T00:00:00Z"
	}
	out := map[string]any{
		"number": p.number, "html_url": "https://github.com/" + p.repo + "/pull/" + strconv.Itoa(p.number),
		"state": state, "draft": p.draft, "title": p.title, "body": body, "merged_at": mergedAt,
		"head": map[string]any{"ref": p.head, "repo": map[string]any{"full_name": p.headRepoName()}},
		"base": map[string]any{"ref": p.base},
	}
	if full {
		out["merged"] = p.merged
	}
	return out
}

// pullRequests are the pull requests of the repository the stand-in holds, as copies.
func (f *fakeGitHub) pullRequests(repo string) []ghPullRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ghPullRec
	for _, p := range f.pulls {
		if p.repo == repo {
			out = append(out, *p)
		}
	}
	return out
}

// pullCalls are the requests the stand-in answered under /repos/ for pull requests and
// installations, as METHOD path, with the query, in order.
func (f *fakeGitHub) pullCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if _, uri, _ := strings.Cut(r, " "); strings.HasPrefix(uri, "/repos/") {
			u, _ := url.Parse(uri)
			if _, _, ok := pullsRoute(u.Path); ok {
				out = append(out, r)
			}
		}
	}
	return out
}
