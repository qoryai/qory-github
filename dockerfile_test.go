package github

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// stage is one stage of the Dockerfile: its FROM line and the instructions after it,
// each a line that is not blank and not a comment.
type stage struct {
	from  string
	lines []string
}

// stages reads the Dockerfile's stages, in order.
func stages(t *testing.T) []stage {
	t.Helper()
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var all []stage
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "FROM "):
			all = append(all, stage{from: line})
		case len(all) > 0:
			all[len(all)-1].lines = append(all[len(all)-1].lines, line)
		}
	}
	return all
}

// TestDockerfileBuildsTheServerByDefaultAndTheStarterAsATarget pins the Dockerfile's
// two images: the server's is the last stage, so docker build with no --target builds
// it, and the starter's is the stage starter. Each is built from the same pinned base,
// with the same build flags, runs as 65532:65532, sets QORY_FEATURES=factory and keeps
// its state directory in a volume.
func TestDockerfileBuildsTheServerByDefaultAndTheStarterAsATarget(t *testing.T) {
	all := stages(t)
	const base = "FROM gcr.io/distroless/static-debian13:nonroot@sha256:"
	var images []stage
	for _, s := range all {
		if strings.HasPrefix(s.from, base) {
			images = append(images, s)
		}
	}
	if len(images) != 2 || len(all) == 0 {
		t.Fatalf("the Dockerfile has %d images in %d stages, want 2", len(images), len(all))
	}
	server, starter := all[len(all)-1], images[0]
	if !strings.HasSuffix(server.from, " AS server") || !strings.HasSuffix(starter.from, " AS starter") {
		t.Fatalf("the images are %q and %q; want starter first and server last", starter.from, server.from)
	}
	if strings.TrimSuffix(server.from, " AS server") != strings.TrimSuffix(starter.from, " AS starter") {
		t.Errorf("the images have different bases: %q and %q", server.from, starter.from)
	}
	for _, c := range []struct {
		name  string
		image stage
		want  []string
	}{
		{"server", server, []string{
			"COPY --from=build /out/qory-github-server /qory-github-server",
			`VOLUME ["/var/lib/qory-github"]`,
			"ENV QORY_FEATURES=factory",
			"USER 65532:65532",
			`ENTRYPOINT ["/qory-github-server"]`,
		}},
		{"starter", starter, []string{
			"COPY --from=starter-build /starter/qory-github-starter /qory-github-starter",
			"COPY --from=starter-build --chown=65532:65532 /starter/var/lib/ /var/lib/",
			`VOLUME ["/var/lib/qory-github-starter"]`,
			"ENV QORY_FEATURES=factory",
			"USER 65532:65532",
			`ENTRYPOINT ["/qory-github-starter"]`,
		}},
	} {
		for _, line := range c.want {
			if !slices.Contains(c.image.lines, line) {
				t.Errorf("the %s's image has no %s", c.name, line)
			}
		}
	}
	// Each program is built with the release's flags.
	const flags = `RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \`
	var builds int
	for _, s := range all {
		for _, line := range s.lines {
			if strings.Contains(line, "go build") {
				builds++
				if line != flags {
					t.Errorf("%s builds with %q, not %q", s.from, line, flags)
				}
			}
		}
	}
	if builds != 2 {
		t.Errorf("the Dockerfile has %d builds, want 2", builds)
	}
}
