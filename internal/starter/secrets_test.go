package starter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// The markers seeded where a secret goes: a run key, a handover's inputs and a work
// item's title. Each is unique to this test, so finding one anywhere is a leak.
const (
	runKeyMarker = "qrk_RunKeyMarker7xQ.SignatureMarker9zW"
	inputsMarker = "InputsMarker5qT"
	titleMarker  = "TitleMarker3wK"
)

// leaks names which secret s holds, or "" for none: never the secret itself, so a test
// failure message quotes nothing.
func leaks(s, accessKeySecret string) string {
	var found []string
	low := strings.ToLower(s)
	for name, m := range map[string]string{
		"the access key secret": accessKeySecret,
		"the run key":           runKeyMarker,
		"part of the run key":   "runkeymarker",
		"the inputs":            inputsMarker,
		"the title":             titleMarker,
		"qrk_":                  "qrk_",
		"qak_":                  "qak_",
	} {
		if strings.Contains(low, strings.ToLower(m)) {
			found = append(found, name)
		}
	}
	return strings.Join(found, ", ")
}

// TestNoSecretLeaks answers the claim and the handover with answers that hold the
// markers, used, refused and unsigned, and checks that no error, no line of the log and
// nothing the client shows of a result holds the access key secret, the run key, the
// inputs or the title; nor does any request the client sends.
func TestNoSecretLeaks(t *testing.T) {
	ctx := context.Background()
	claim := strings.Replace(fixture(t, "claim-answer/explore.json"), "Checkout fails on an empty cart", titleMarker, 1)
	edit := func(doc string, fn func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		out, _ := json.Marshal(m)
		return string(out)
	}
	handover := edit(fixture(t, "handover-answer/explore.json"), func(m map[string]any) {
		m["run_key"] = runKeyMarker
		m["work_item"].(map[string]any)["title"] = titleMarker
		m["inputs"].(map[string]any)["instruction"].(map[string]any)["text"] = inputsMarker
	})
	answers := []reply{
		{status: http.StatusOK, body: handover},
		{status: http.StatusOK, body: handover, unsigned: true},
		{status: http.StatusOK, body: handover, wrongKey: true},
		{status: http.StatusUnauthorized, body: handover, unsigned: true},
		{status: http.StatusBadRequest, body: handover, unsigned: true},
		{status: http.StatusConflict, body: `{"error":"qrk_runkeymarker"}`},
		{status: http.StatusConflict, body: `{"error":"handed_over","` + runKeyMarker + `":"` + inputsMarker + `"}`},
		{status: http.StatusInternalServerError, body: handover},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) { m["revision"] = 2 })},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) { m["run_id"] = otherRun })},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) { m[runKeyMarker] = inputsMarker })},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) { m["run_key"] = runKeyMarker + "!" })},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) {
			m["work_item"].(map[string]any)["title"] = titleMarker + strings.Repeat("x", 1024)
		})},
		{status: http.StatusOK, body: edit(handover, func(m map[string]any) {
			m["inputs"].(map[string]any)["filler"] = inputsMarker + strings.Repeat("x", 800<<10)
		})},
		{status: http.StatusOK, body: strings.Replace(handover, `"version":1`, `"version":1,"version":1`, 1)},
		{status: http.StatusOK, body: handover + strings.Repeat(" ", 1<<20)},
		{status: http.StatusOK, body: claim},
		{status: http.StatusOK, body: edit(claim, func(m map[string]any) { m["pool_id"] = "np_0000000000000000" })},
		{status: http.StatusOK, body: edit(claim, func(m map[string]any) { m["revision"] = 7 })},
	}
	var logs bytes.Buffer
	var shown []string
	for i, rep := range answers {
		f := newFake(t, func(int, seen) reply { return rep })
		a := f.client(&sleeps{}, &logs)
		a.PoolID = testPool
		secret := a.Key.Secret()
		var errs []error
		if strings.Contains(rep.body, `"lease_until"`) {
			c, ok, err := a.Claim(ctx, 0)
			if rep.body == claim && (!ok || c.WorkItem.Title.Value() != titleMarker) {
				t.Fatal("the signed claim that holds the title is not used, so the test proves nothing of a result")
			}
			errs = append(errs, err)
			a.Log.Info("claimed", "claim", c)
			shown = append(shown, fmt.Sprint(c), fmt.Sprintf("%+v %#v %q", c, c, c), fmt.Sprintf("%+v %#v", struct{ c Claimed }{c}, struct{ c Claimed }{c}))
		} else {
			h, err := a.Handover(ctx, testDispatch, testRun)
			if i == 0 && (err != nil || h.RunKey.Value() != runKeyMarker || !strings.Contains(h.Inputs.Value(), inputsMarker)) {
				t.Fatal("the signed handover that holds the markers is not used, so the test proves nothing of a result")
			}
			errs = append(errs, err)
			a.Log.Info("handed over", "handover", h)
			js, _ := json.Marshal(h)
			shown = append(shown, fmt.Sprint(h), fmt.Sprintf("%+v %#v %q", h, h, h), string(js), fmt.Sprintf("%+v %#v", struct{ h Handed }{h}, struct{ h Handed }{h}))
		}
		errs = append(errs, a.Release(ctx, testDispatch, "the job could not start", true))
		for _, err := range errs {
			if err == nil {
				continue
			}
			if l := leaks(err.Error(), secret); l != "" {
				t.Errorf("answer %d: an error holds %s", i, l)
			}
		}
		for _, s := range shown {
			if l := leaks(s, secret); l != "" {
				t.Errorf("answer %d: a result shows %s", i, l)
			}
		}
		if l := leaks(logs.String(), secret); l != "" {
			t.Errorf("answer %d: the log holds %s", i, l)
		}
		for _, r := range f.requests() {
			if strings.Contains(string(r.body), secret) || strings.Contains(fmt.Sprint(r.header), secret) {
				t.Errorf("answer %d: a request holds the access key secret", i)
			}
		}
	}
	if !strings.Contains(logs.String(), "sent again") {
		t.Error("the log holds no try sent again, so the test proves nothing of it")
	}
}

// TestLeaksFinds checks the marker test finds each marker, so it cannot pass by
// finding nothing.
func TestLeaksFinds(t *testing.T) {
	for _, s := range []string{runKeyMarker, inputsMarker, titleMarker, "qak_x"} {
		if leaks("…"+s+"…", "qak_secret") == "" {
			t.Error("a marker is not found")
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "k", runKeyMarker)
	if leaks(buf.String(), "qak_secret") == "" {
		t.Error("a marker in a log line is not found")
	}
}
