package starter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/integrations/contracts"
	"github.com/qoryai/qory-github"
	"github.com/qoryai/qory-github/internal/ownerfile"
)

const (
	// stepExplore is the one step the starter starts a job for, the provisioner
	// contract's step explore. A run claimed for another step is released with retry
	// false.
	stepExplore = "explore"
	// jobSystem is external.type of each job the starter starts, the provisioner
	// contract's job_system.
	jobSystem = "github-actions"
	// claimWaitSeconds is how long Qory Apiary may hold a claim while no run can be
	// claimed, the contract's most.
	claimWaitSeconds = 25
	// pollInterval is the time between two reads of a job's workflow run.
	pollInterval = 15 * time.Second
	// firstBackoff and maxBackoff bound the waits before a claim is sent again after a
	// failure, and before the next claim after a job could not be started.
	firstBackoff = time.Second
	maxBackoff   = time.Minute
	// maxHandoverWait is the longest wait before a handover is sent again after a
	// transient failure; the waits double from firstBackoff up to it.
	maxHandoverWait = 30 * time.Second
	// maxStops is how many times a job is asked to stop, one read of its workflow run
	// apart, before the starter stops asking: GitHub answers 409 to a cancel of a run
	// it cannot cancel, so a run is read again after each cancel to learn whether it
	// ended.
	maxStops = 20
	// maxRateLimited is how many signed 429s a release or dispatched waits out before
	// the starter gives up on it.
	maxRateLimited = 3
	// instanceFile is the file in state_dir that holds the starter's instance id.
	instanceFile = "instance-id"
	// maxInstanceFile is the most the instance id file may hold.
	maxInstanceFile = 256
)

// The reasons a release gives, display text in Qory Apiary.
const (
	reasonStep           = "the starter runs only the explore step"
	reasonLeasePassed    = "the lease ended before the job could be started"
	reasonNotStarted     = "the job could not be started"
	reasonNotRecorded    = "the job's start could not be recorded"
	reasonEndedBeforeAsk = "the job ended before it asked for the run key"
	reasonNoAsk          = "no job asked for the run key before the lease ended"
	reasonHandedOver     = "the run was handed over before, so its job was stopped"
	reasonLeaseHanding   = "the run key could not be handed over before the lease ended"
	reasonJobLeft        = "the job went away while the run key was being handed over"
	reasonNotHanded      = "the run key could not be handed over"
	reasonNoSuccess      = "the job ended without success"
)

// Deps are what [Run] reaches the world through, so a test replaces each.
type Deps struct {
	// Now is the clock; nil is time.Now. It is Qory Apiary's client's and the
	// verifier's clock too, so it must advance across Sleep.
	Now func() time.Time
	// Sleep waits d or until ctx is done; nil waits on a timer. Every wait before a
	// request is sent again goes through it.
	Sleep func(ctx context.Context, d time.Duration) error
	// Poll waits between two reads of a job's workflow run: d, until wake receives, or
	// until ctx is done, whose error it then returns; nil waits on a timer.
	Poll func(ctx context.Context, d time.Duration, wake <-chan struct{}) error
	// Log takes the starter's lines; nil logs nothing. No line holds a run key, a
	// token, a handover's inputs or a work item's title.
	Log *slog.Logger
	// ApiaryHTTP is the client of Qory Apiary; nil is one with no other setting.
	ApiaryHTTP *http.Client
	// GitHub reaches GitHub's API; its API is set to the settings' api_url.
	GitHub github.Client
	// Verifier checks a job's OIDC token; nil is [NewVerifier].
	Verifier *Verifier
	// Listener is where the pass-through is served; nil listens on the settings'
	// listen.
	Listener net.Listener
}

// Run is the starter: it claims the node pool's runs from Qory Apiary, starts the
// workflow the settings name for each run claimed for the explore step, says so with
// dispatched, and serves the pass-through on listen, through which the job, once its
// GitHub Actions OIDC token passes its check, gets the run key and the run's inputs
// from the handover. It watches each job's workflow run: before the handover, a run
// that ends, or no job asking before the lease ends, releases the run with retry true;
// after it, a run that succeeded posts the run's outcome alone, and any other end
// releases the run with retry true, then posts its outcome.
//
// It reads the access key's secret and the App's private key from the files the
// settings name, and keeps the instance id in state_dir; it writes nothing else to
// disk. A run key is kept in memory alone, from the handover's answer until it is
// written to the job, and never logged. Run returns once ctx is done, nil then, or
// when the pass-through cannot be served or the starter cannot start.
func Run(ctx context.Context, s Settings, d Deps) error {
	key, err := ReadAccessKeySecret(s.AccessKeySecretFile)
	if err != nil {
		return err
	}
	appKey, err := ReadPrivateKey(s.PrivateKeyFile)
	if err != nil {
		return err
	}
	repos, err := github.ParseRepositories(s.Repository)
	if err != nil || len(repos) != 1 {
		return errors.New("the settings' repository is not one repository, owner/name")
	}
	instance, err := instanceID(s.StateDir)
	if err != nil {
		return err
	}
	st := &starter{
		settings:   s,
		now:        d.Now,
		sleep:      d.Sleep,
		poll:       d.Poll,
		log:        d.Log,
		verifier:   d.Verifier,
		dispatches: map[string]*dispatch{},
	}
	if st.now == nil {
		st.now = time.Now
	}
	if st.sleep == nil {
		st.sleep = sleepTimer
	}
	if st.poll == nil {
		st.poll = pollTimer
	}
	if st.log == nil {
		st.log = slog.New(slog.DiscardHandler)
	}
	if st.verifier == nil {
		st.verifier = NewVerifier()
	}
	st.apiary = &Apiary{
		URL: s.ApiaryURL, KeyID: s.AccessKeyID, Key: key, Pin: s.ApiaryPublicKey, InstanceID: instance,
		PoolID: s.PoolID, HTTP: d.ApiaryHTTP, Now: st.now, Sleep: st.sleepWithinLease, Log: d.Log,
	}
	gh := d.GitHub
	gh.API = s.APIURL
	st.actions = &github.Actions{Client: gh, AppID: s.AppID, Key: appKey, Pacer: &github.Pacer{Now: st.now, Sleep: st.sleep}}
	if st.repo, err = st.actions.FindRepository(ctx, repos[0]); err != nil {
		return fmt.Errorf("the settings' repository: %w", err)
	}
	ln := d.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", s.Listen); err != nil {
			return fmt.Errorf("the settings' listen: %w", err)
		}
	}
	return st.run(ctx, ln)
}

// run serves the pass-through on ln and claims runs until ctx is done or the
// pass-through fails, then stops the pass-through and waits for every job's watch to
// end.
func (st *starter) run(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	srv := &http.Server{
		Handler:           st,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    maxJobHeader,
		ErrorLog:          slog.NewLogLogger(st.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			cancel(fmt.Errorf("the pass-through: %w", err))
		}
	}()
	st.claimLoop(ctx)
	stop, stopped := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	_ = srv.Shutdown(stop)
	stopped()
	<-served
	st.wg.Wait()
	if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// starter is one running starter: its clients, its clock and the dispatches it holds.
type starter struct {
	settings Settings
	apiary   *Apiary
	actions  *github.Actions
	repo     github.ActionsRepository
	verifier *Verifier
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
	poll     func(ctx context.Context, d time.Duration, wake <-chan struct{}) error
	log      *slog.Logger

	// mu guards dispatches, each dispatch whose job the starter started and whose
	// watch has not ended, by its dispatch id.
	mu         sync.Mutex
	dispatches map[string]*dispatch
	// wg counts the watches that run.
	wg sync.WaitGroup
}

// The states of a dispatch.
const (
	// stateStarting is a job started and dispatched not answered yet.
	stateStarting = iota
	// stateWaiting is dispatched answered, and no handover sent.
	stateWaiting
	// stateAsking is the handover being sent for the job whose token passed its check.
	stateAsking
	// stateHanded is the handover answered with the signed 200 and the run key passed
	// on to the job.
	stateHanded
	// stateEnded is the dispatch over before its handover, or after a handover that
	// gave the job no run key.
	stateEnded
)

// ending is what ends a dispatch before its job has the run key: whether the job is
// stopped, and whether the run is released with retry true, for reason.
type ending struct {
	cancel  bool
	release bool
	reason  string
}

// dispatch is one dispatch whose job the starter started. Its id, its run, its lease
// and its workflow run never change; its state is guarded by mu. It never holds a run
// key.
type dispatch struct {
	id          string
	runID       string
	lease       time.Time
	workflowRun int64
	// ready is closed once dispatched is answered, or given up.
	ready chan struct{}
	// wake tells the watch that the state changed.
	wake chan struct{}

	mu    sync.Mutex
	state int
	end   ending
	// asked is whether a job's request whose token passed its check came: one request
	// is taken per dispatch, and so per workflow run.
	asked bool
}

// settle sets the state dispatched leaves, stateWaiting or stateEnded with end, and
// closes ready.
func (d *dispatch) settle(state int, end ending) {
	d.mu.Lock()
	d.state, d.end = state, end
	d.mu.Unlock()
	close(d.ready)
}

// finish ends the dispatch with end, and wakes its watch.
func (d *dispatch) finish(end ending) {
	d.mu.Lock()
	d.state, d.end = stateEnded, end
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// claimLoop claims runs and starts a job for each until ctx is done. A claim that
// fails is sent again after a wait: a signed 429's Retry-After, or a wait that doubles
// from [firstBackoff] up to [maxBackoff], after a 409 no_gateway, an answer not signed
// under the pin, a 401 among them, which never means the access key is revoked, or no
// answer. A job that could not be started makes the next claim wait the same way.
func (st *starter) claimLoop(ctx context.Context) {
	claimWait, startWait := firstBackoff, firstBackoff
	for ctx.Err() == nil {
		claimed, ok, err := st.apiary.Claim(ctx, claimWaitSeconds)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			wait := claimWait
			var r *Refusal
			if errors.Is(err, ErrRateLimited) && errors.As(err, &r) {
				wait = r.RetryAfter
			} else {
				claimWait = min(claimWait*2, maxBackoff)
			}
			st.log.Warn("the claim failed, so it is sent again after a wait", slog.Duration("wait", wait), slog.String("error", err.Error()))
			if st.sleep(ctx, wait) != nil {
				return
			}
			continue
		}
		claimWait = firstBackoff
		if !ok {
			continue
		}
		if st.start(ctx, claimed) {
			startWait = firstBackoff
			continue
		}
		if ctx.Err() != nil || st.sleep(ctx, startWait) != nil {
			return
		}
		startWait = min(startWait*2, maxBackoff)
	}
}

// start starts the job for the run claimed, and reports whether nothing failed on the
// way. A run for another step than explore is released with retry false. The workflow
// is dispatched once, and never again for the same claim, since a dispatch GitHub took
// may run though its answer failed: any failure releases the run with retry true, and
// a job is watched, its token checked and its handover sent only for a workflow run
// whose id is above 0.
func (st *starter) start(ctx context.Context, c Claimed) bool {
	st.log.Info("claimed a run", slog.String("dispatch_id", c.DispatchID), slog.String("run_id", c.RunID), slog.String("step", c.Step))
	if c.Step != stepExplore {
		st.release(ctx, c.DispatchID, c.RunID, reasonStep, false)
		return true
	}
	lease, err := time.Parse(time.RFC3339, c.LeaseUntil)
	if err != nil || !st.now().Before(lease) {
		st.release(ctx, c.DispatchID, c.RunID, reasonLeasePassed, true)
		return false
	}
	run, err := st.actions.DispatchWorkflow(ctx, st.repo.Installation, st.repo.ID, st.settings.Workflow, st.settings.Ref, c.DispatchID)
	if err == nil && run.ID <= 0 {
		err = errors.New("GitHub named no workflow run above 0")
	}
	if err != nil {
		st.log.Warn("the job could not be started", slog.String("dispatch_id", c.DispatchID), slog.String("run_id", c.RunID), slog.String("error", err.Error()))
		st.release(ctx, c.DispatchID, c.RunID, reasonNotStarted, true)
		return false
	}
	st.log.Info("started the job", slog.String("dispatch_id", c.DispatchID), slog.String("run_id", c.RunID), slog.Int64("workflow_run_id", run.ID))
	d := &dispatch{
		id: c.DispatchID, runID: c.RunID, lease: lease, workflowRun: run.ID,
		ready: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	st.mu.Lock()
	st.dispatches[d.id] = d
	st.mu.Unlock()
	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		st.watch(ctx, d)
	}()
	return st.dispatched(ctx, d, run.HTMLURL)
}

// dispatched sends dispatched for d, naming its workflow run when GitHub gave its page
// as an https URL, and reports whether it was answered. A signed 429 is waited out
// while the lease lasts. On 409 lease_expired or 410 gone the job is stopped; on any
// other failure the job is stopped and the run released with retry true.
func (st *starter) dispatched(ctx context.Context, d *dispatch, htmlURL string) bool {
	var external *contracts.External
	if u, err := url.Parse(htmlURL); err == nil && u.Scheme == "https" && u.Host != "" && len(htmlURL) <= 2048 && strings.HasPrefix(htmlURL, "https://") {
		external = &contracts.External{Type: jobSystem, Ref: strconv.FormatInt(d.workflowRun, 10), URL: htmlURL}
	}
	for limited := 0; ; limited++ {
		err := st.apiary.Dispatched(ctx, d.id, external)
		var r *Refusal
		switch {
		case err == nil:
			d.settle(stateWaiting, ending{})
			return true
		case ctx.Err() != nil:
			d.settle(stateEnded, ending{})
			return false
		case errors.Is(err, ErrRateLimited) && errors.As(err, &r) && limited < maxRateLimited && st.now().Add(r.RetryAfter).Before(d.lease):
			if st.sleep(ctx, r.RetryAfter) != nil {
				d.settle(stateEnded, ending{})
				return false
			}
			continue
		}
		end := ending{cancel: true, release: true, reason: reasonNotRecorded}
		if errors.Is(err, ErrLeaseExpired) || errors.Is(err, ErrGone) {
			end = ending{cancel: true}
		}
		st.log.Warn("Qory Apiary did not record the job's start", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.Int64("workflow_run_id", d.workflowRun), slog.String("error", err.Error()))
		d.settle(stateEnded, end)
		return false
	}
}

// watch follows d's job until the dispatch is over: it reads the job's workflow run
// every [pollInterval], and at once when the pass-through ends the dispatch. Before
// the handover, a run that ends releases the run with retry true, and so does the
// lease ending with no job asking, once the job is stopped. After the handover, a run
// that succeeded posts the run's outcome alone; any other end releases the run with
// retry true first, then posts the outcome. A dispatch ended with a stop is followed
// until its run ends, with a cancel sent again after each read that finds it going on,
// up to [maxStops].
func (st *starter) watch(ctx context.Context, d *dispatch) {
	defer func() {
		st.mu.Lock()
		delete(st.dispatches, d.id)
		st.mu.Unlock()
	}()
	select {
	case <-d.ready:
	case <-ctx.Done():
		return
	}
	completed, conclusion := false, ""
	acted, stops := false, 0
	for {
		d.mu.Lock()
		state, end := d.state, d.end
		d.mu.Unlock()
		if state == stateEnded {
			switch {
			case !acted:
				acted = true
				if end.cancel && !completed {
					st.stop(ctx, d)
					stops++
				}
				if end.release {
					st.release(ctx, d.id, d.runID, end.reason, true)
				}
				if !end.cancel || completed {
					return
				}
			case completed:
				return
			case stops >= maxStops:
				st.log.Warn("the job did not stop", slog.String("dispatch_id", d.id), slog.Int64("workflow_run_id", d.workflowRun))
				return
			default:
				st.stop(ctx, d)
				stops++
			}
		}
		if st.poll(ctx, pollInterval, d.wake) != nil {
			return
		}
		run, err := st.actions.ReadWorkflowRun(ctx, st.repo.Installation, st.repo.ID, d.workflowRun)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			completed, conclusion = run.Status == "completed", run.Conclusion
		case errors.Is(err, github.ErrActionsTransient):
			st.log.Warn("the job's workflow run could not be read", slog.String("dispatch_id", d.id), slog.Int64("workflow_run_id", d.workflowRun), slog.String("error", err.Error()))
		default:
			// A run deleted, or out of the App's reach, is taken as ended, with no
			// conclusion.
			st.log.Warn("the job's workflow run can no longer be read", slog.String("dispatch_id", d.id), slog.Int64("workflow_run_id", d.workflowRun), slog.String("error", err.Error()))
			completed, conclusion = true, ""
		}
		d.mu.Lock()
		switch d.state {
		case stateWaiting:
			if completed {
				d.state, d.end = stateEnded, ending{release: true, reason: reasonEndedBeforeAsk}
			} else if !st.now().Before(d.lease) {
				d.state, d.end = stateEnded, ending{cancel: true, release: true, reason: reasonNoAsk}
			}
		case stateHanded:
			if completed {
				d.mu.Unlock()
				st.concluded(ctx, d, conclusion)
				return
			}
		}
		d.mu.Unlock()
	}
}

// concluded closes a handed-over run whose job's workflow run ended with conclusion:
// success posts the outcome succeeded alone; any other conclusion releases the run with
// retry true first, then posts the outcome [OutcomeOf] gives.
func (st *starter) concluded(ctx context.Context, d *dispatch, conclusion string) {
	if conclusion == "success" {
		st.outcome(ctx, d, Outcome{State: StateSucceeded})
		return
	}
	st.release(ctx, d.id, d.runID, reasonNoSuccess, true)
	st.outcome(ctx, d, OutcomeOf(conclusion))
}

// outcome posts the outcome o of d's run to the run endpoint of the configuration
// document Qory Apiary answers now, [Apiary.Configuration]; no other run endpoint is
// ever posted to.
func (st *starter) outcome(ctx context.Context, d *dispatch, o Outcome) {
	conf, err := st.apiary.Configuration(ctx)
	if err == nil {
		err = st.apiary.PostOutcome(ctx, conf.RunURL, d.runID, o)
	}
	if err != nil {
		st.log.Warn("the run's outcome could not be posted", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.String("error", err.Error()))
		return
	}
	state := o.State
	if state == "" {
		state = StateCancelled
	}
	st.log.Info("posted the run's outcome", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.String("state", state))
}

// stop asks GitHub to cancel d's workflow run.
func (st *starter) stop(ctx context.Context, d *dispatch) {
	if err := st.actions.CancelWorkflowRun(ctx, st.repo.Installation, st.repo.ID, d.workflowRun); err != nil {
		st.log.Warn("the job could not be stopped", slog.String("dispatch_id", d.id), slog.Int64("workflow_run_id", d.workflowRun), slog.String("error", err.Error()))
		return
	}
	st.log.Info("stopped the job", slog.String("dispatch_id", d.id), slog.String("run_id", d.runID), slog.Int64("workflow_run_id", d.workflowRun))
}

// release gives the run of the dispatch id back, for reason, with retry. A signed 429
// is waited out up to [maxRateLimited] times. A 409 lease_expired or a 410 gone is the
// dispatch over already, the end the contract expects of a stale dispatch, and nothing
// is sent again.
func (st *starter) release(ctx context.Context, id, runID, reason string, retry bool) {
	for limited := 0; ; limited++ {
		err := st.apiary.Release(ctx, id, reason, retry)
		var r *Refusal
		switch {
		case err == nil:
			st.log.Info("released the run", slog.String("dispatch_id", id), slog.String("run_id", runID), slog.String("reason", reason), slog.Bool("retry", retry))
		case ctx.Err() != nil:
		case errors.Is(err, ErrLeaseExpired) || errors.Is(err, ErrGone):
			st.log.Info("the dispatch was over already, so nothing was released", slog.String("dispatch_id", id), slog.String("run_id", runID), slog.String("answer", err.Error()))
		case errors.Is(err, ErrRateLimited) && errors.As(err, &r) && limited < maxRateLimited:
			if st.sleep(ctx, r.RetryAfter) != nil {
				return
			}
			continue
		default:
			st.log.Warn("the release failed", slog.String("dispatch_id", id), slog.String("run_id", runID), slog.String("error", err.Error()))
		}
		return
	}
}

// instanceID is the starter's instance id, which every request to Qory Apiary is
// signed with: for display, audit and per-instance events, never a secret. It is made
// once with [accesskey.NewInstanceID], i_ and 22 characters, and kept in the file
// instance-id in the state directory, 0600, so the starter is the same instance after
// a restart. The directory is made 0700 when it does not exist, and it and the file
// must be the user's the starter runs as and grant group and others no permission. A
// file that holds no instance id is written anew.
func instanceID(dir string) (string, error) {
	if err := ownerfile.Dir(dir, "the state directory"); err != nil {
		return "", err
	}
	path := filepath.Join(dir, instanceFile)
	b, err := ownerfile.ReadFile(path, maxInstanceFile, "the instance id file", "an instance id")
	switch {
	case err == nil:
		id := strings.TrimSuffix(string(b), "\n")
		if strings.HasPrefix(id, accesskey.InstancePrefix) && accesskey.CheckInstanceID(id) == nil {
			return id, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return "", err
	}
	id, err := accesskey.NewInstanceID()
	if err != nil {
		return "", err
	}
	f, err := ownerfile.Open(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600, "the instance id file")
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(id + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("the instance id file %s: %w", path, err)
	}
	return id, nil
}

// leaseKey is the key of the lease a context carries: a request sent with it is never
// sent again at or after that time.
type leaseKey struct{}

// errLeaseEnded is a wait refused because the lease would end before it does.
var errLeaseEnded = errors.New("the lease ends before the request could be sent again")

// sleepWithinLease is the wait of Qory Apiary's client: [starter.sleep], but refused
// with [errLeaseEnded] when ctx carries a lease that ends before the wait does, so a
// handover is never sent again at or after lease_until, by the client's tries either.
func (st *starter) sleepWithinLease(ctx context.Context, d time.Duration) error {
	if until, ok := ctx.Value(leaseKey{}).(time.Time); ok && !st.now().Add(d).Before(until) {
		return errLeaseEnded
	}
	return st.sleep(ctx, d)
}

// sleepTimer waits d or until ctx is done.
func sleepTimer(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// pollTimer waits d, until wake receives, or until ctx is done.
func pollTimer(ctx context.Context, d time.Duration, wake <-chan struct{}) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-wake:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
