package serve

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/qoryai/qory-github"
)

// TestPublicRefsIsSafeForConcurrentCalls pins the cache of the anonymous ref list under
// concurrent calls for one repository, with names kept before and new names, which
// read and extend the entry at once. Run with -race, a map that two calls share fails.
func TestPublicRefsIsSafeForConcurrentCalls(t *testing.T) {
	rig := newCallsRig(t)
	rig.pub.set(func() { rig.pub.public = map[string]bool{"acme/tools": true} })
	repo := github.Repository{Owner: "acme", Name: "tools"}
	if _, err := rig.calls.publicRefs(context.Background(), repo, "main"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				if refs, err := rig.calls.publicRefs(context.Background(), repo, "main"); err != nil || refs.Commit != widgetsCommit {
					t.Errorf("main: %+v, %v", refs, err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := range 5 {
				if refs, err := rig.calls.publicRefs(context.Background(), repo, "dev"); err != nil || refs.Commit != devCommit {
					t.Errorf("dev: %+v, %v", refs, err)
				}
				if refs, err := rig.calls.publicRefs(context.Background(), repo, "n"+strconv.Itoa(i)+"-"+strconv.Itoa(j)); err != nil || !refs.Public || refs.Found {
					t.Errorf("a new name: %+v, %v", refs, err)
				}
			}
		}()
	}
	wg.Wait()
}
