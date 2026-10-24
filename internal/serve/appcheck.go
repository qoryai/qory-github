package serve

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/qoryai/qory-github"
)

// checkApp asks GitHub which App a is, GET /app under a's token, once, as serve starts
// with the App of the settings or the one kept in the state directory, before it
// serves with it, see [Run]; the App the App setup keeps is GitHub's answer of seconds
// before, and is not asked for. It returns the App serve serves with, or the error that
// refuses the start.
//
// For the settings' App the slug is compared: GitHub's answer must name a slug, see
// [github.CheckSlug], and the same one as app_slug. For the kept App the id is
// compared: GitHub's answer must name a positive id, and the same one as app.json. A
// new slug for the same id is kept in app.json in place of the old one, see
// [keepSlug], a line says so, and serve serves with the App read back, its bot
// <slug>[bot]. A 401 refuses, since GitHub does not take the App's token and asking
// again does not change that. Any other answer, or no answer, is asked again after a
// wait that doubles, as the change feed's reader waits, with a line at the first
// failure and then once each [feedMaxBackoff] at most. serve listens in the App-check
// phase before the first ask, see [Run]. When ctx is done it returns ctx's error.
func (r *runner) checkApp(ctx context.Context, a *app) (*app, error) {
	gh := github.Client{API: r.s.APIURL}
	waits := &feed{sleep: r.opts.feedSleep}
	failed := &throttle{every: feedMaxBackoff}
	backoff := feedFirstBackoff
	for {
		got, err := gh.App(ctx, a.id, a.key)
		switch {
		case err == nil:
			return r.compareApp(a, got)
		case github.Unauthorized(err):
			return nil, fmt.Errorf("checking the App with GitHub: GitHub does not take the App's token, made from app_id and the App's private key: %w", err)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		}
		if ok, dropped := failed.allow(); ok {
			attrs := []slog.Attr{slog.String("error", err.Error())}
			if dropped > 0 {
				attrs = append(attrs, slog.Int("failed_dropped", dropped))
			}
			r.log.LogAttrs(ctx, slog.LevelWarn, "checking the App with GitHub failed, and is tried again", attrs...)
		}
		if waits.wait(ctx, backoff) != nil {
			return nil, ctx.Err()
		}
		backoff = min(2*backoff, feedMaxBackoff)
	}
}

// compareApp compares a with got, GitHub's answer of which App a is, as [runner.checkApp]
// says, and returns the App serve serves with.
func (r *runner) compareApp(a *app, got github.AppIdentity) (*app, error) {
	noSlug := fmt.Errorf("checking the App with GitHub: GitHub's answer names no slug for the App with app_id %s", a.id)
	if !a.kept {
		switch {
		case github.CheckSlug(got.Slug) != nil:
			return nil, noSlug
		case got.Slug != a.slug:
			return nil, fmt.Errorf("app_slug is %s, and GitHub answers that the App with app_id %s is %s; set app_slug to %s", a.slug, a.id, got.Slug, got.Slug)
		}
		return a, nil
	}
	switch {
	case got.ID <= 0:
		return nil, fmt.Errorf("checking the App with GitHub: GitHub's answer names no id for the App with app_id %s", a.id)
	case got.ID != a.numericID:
		return nil, fmt.Errorf("the App file app.json names the App with app_id %d, and GitHub answers for another App", a.numericID)
	case got.Slug == a.slug:
		return a, nil
	case github.CheckSlug(got.Slug) != nil:
		return nil, noSlug
	}
	kept, err := keepSlug(r.s.StateDir, got.Slug)
	if err != nil {
		return nil, fmt.Errorf("keeping the App's new slug %s in the App file app.json: %w", got.Slug, err)
	}
	id := strconv.FormatInt(a.numericID, 10)
	r.log.Info("GitHub names the App with app_id " + id + " " + got.Slug + " now, so serve keeps " + got.Slug + " in place of " + a.slug)
	return kept, nil
}

// keepSlug keeps slug in place of the slug of the App kept in the state directory dir,
// app.json written again as [rewriteApp] writes it with that alone changed, and reads
// the App back as a start reads it, see [loadApp].
func keepSlug(dir, slug string) (*app, error) {
	if err := rewriteApp(dir, func(k *keptApp) { k.AppSlug = slug }); err != nil {
		return nil, err
	}
	return loadApp(dir)
}
