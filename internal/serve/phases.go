package serve

import (
	"net/http"
	"sync/atomic"
)

// healthPath is where serve answers a load balancer's health check, on any host: 200
// from the moment serve listens, in each of its phases, with a line that names the
// phase.
const healthPath = "/health"

// The lines of serve's phases: /health's in each, and the line every other request is
// answered 503 with before serve serves it.
const (
	healthEnrolling = "enrolling in Qory Apiary"
	healthLoading   = "reading the GitHub App from Qory Apiary"
	healthAppCheck  = "waiting for GitHub to answer the App check"
	healthNoApp     = "waiting for the GitHub App's setup"
	healthServing   = "serving"

	unavailableEnrolling = "This adapter is not enrolled in Qory Apiary yet."
	unavailableLoading   = "This adapter is starting. It is reading its GitHub App from Qory Apiary. Try again in a few minutes. If this message stays, the adapter's log shows the error."
	unavailableAppCheck  = "This adapter is starting. It is waiting for GitHub to answer a check of its GitHub App. Try again in a few minutes. If this message stays, the adapter's log shows GitHub's error."
	unavailableNoApp     = "This adapter's GitHub App is not set up yet. An instance admin sets it up with Set up on the adapter's page in Qory Apiary."
)

// phase is what serve answers in one of its phases, which go forward only: enrolling in
// Qory Apiary, reading the App from Qory Apiary, the App check, with no App, and
// serving. A start goes through the App
// check or the no-App phase, never both. /health is answered 200 with health; the App
// setup's paths by setup, when it is set; and every other request by next, when it is
// set, or else 503 with unavailable. Each answer serve makes here is text, kept by no
// cache, not sniffed, and sent with no referrer, as a setup pass in its address is
// sent nowhere.
type phase struct {
	health      string
	unavailable string
	setup       *appSetup
	next        http.Handler
}

func (p *phase) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == healthPath:
		phaseLine(w, http.StatusOK, p.health)
	case p.setup != nil && p.setup.owns(r.URL.Path):
		p.setup.ServeHTTP(w, r)
	case p.next != nil:
		p.next.ServeHTTP(w, r)
	default:
		phaseLine(w, http.StatusServiceUnavailable, p.unavailable)
	}
}

// phaseLine answers status with line, as text no cache keeps, which sends no referrer.
func phaseLine(w http.ResponseWriter, status int, line string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	plainPage(w, status, line)
}

// router answers each request with the phase in place as the request comes: one
// listener serves every phase, and a phase is put in place whole, with one store.
type router struct{ h atomic.Pointer[phase] }

// set puts p in place.
func (rt *router) set(p *phase) { rt.h.Store(p) }

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.h.Load().ServeHTTP(w, r) }
