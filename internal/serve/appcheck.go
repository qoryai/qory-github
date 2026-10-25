package serve

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/qoryai/qory-github"
)

// checkApp asks GitHub which App a is, GET /app under a's token, once, as serve starts
// with the App Qory Apiary delivered, before it serves with it, see [Run]; the App the
// App setup creates is GitHub's answer of seconds before, and is not asked for. It
// returns the App serve serves with, or the error that refuses the start.
//
// GitHub's answer must name a positive id, and the same one as the App's. A new slug
// for the same id is used in place of the old one, a line says so, and serve uploads
// the App with the new slug to Qory Apiary, see [runner.keepSlug]; its bot is
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
			return r.compareApp(ctx, a, got)
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
func (r *runner) compareApp(ctx context.Context, a *app, got github.AppIdentity) (*app, error) {
	switch {
	case got.ID <= 0:
		return nil, fmt.Errorf("checking the App with GitHub: GitHub's answer names no id for the App with app_id %s", a.id)
	case got.ID != a.numericID:
		return nil, fmt.Errorf("Qory Apiary stores the App with app_id %d, and GitHub's answer is for another App", a.numericID)
	case got.Slug == a.slug:
		return a, nil
	case github.CheckSlug(got.Slug) != nil:
		return nil, fmt.Errorf("checking the App with GitHub: GitHub's answer has no slug for the App with app_id %s", a.id)
	}
	r.log.Info("GitHub's answer has the slug " + got.Slug + " for the App with app_id " + a.id + " now, so serve uses " + got.Slug + " in place of " + a.slug)
	renamed := a.with(func(c *app) { c.slug = got.Slug })
	r.keepSlug(ctx, renamed)
	return renamed, nil
}

// keepSlug uploads the App a, with its new slug, to Qory Apiary, once, see
// [Apiary.UploadSecrets]. When the upload fails, a line says so, and serve goes on with
// the new slug: the next start finds the old one again and uploads again.
func (r *runner) keepSlug(ctx context.Context, a *app) {
	if err := r.upload(ctx, a); err != nil {
		r.log.Warn("storing the App's new slug in Qory Apiary failed; serve stores it again at its next start", slog.String("slug", a.slug), slog.String("error", err.Error()))
	}
}
