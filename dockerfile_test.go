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

// TestDockerfileBuildsTheServerByDefault pins the Dockerfile's one image, the
// server's: it is the last stage, so docker build with no --target builds it. It is
// built from the pinned base, with the release's build flags, runs as 65532:65532, sets
// QORY_FEATURES=factory, keeps its state directory in a volume, sets the state
// directory and the address serve reads from the environment, and exposes that port.
// The program is cross-compiled on the platform of the machine that builds for the
// image's platform, so one build makes the images of linux/amd64 and linux/arm64.
func TestDockerfileBuildsTheServerByDefault(t *testing.T) {
	all := stages(t)
	const base = "FROM gcr.io/distroless/static-debian13:nonroot@sha256:"
	var images []stage
	for _, s := range all {
		if strings.HasPrefix(s.from, base) {
			images = append(images, s)
		}
	}
	if len(images) != 1 || len(all) != 2 {
		t.Fatalf("the Dockerfile has %d images in %d stages, want 1 in 2", len(images), len(all))
	}
	server := all[len(all)-1]
	if !strings.HasSuffix(server.from, " AS server") || server.from != images[0].from {
		t.Fatalf("the last stage is %q; want the server's image", server.from)
	}
	for _, line := range []string{
		"COPY --from=build /out/qory-github-server /qory-github-server",
		"COPY --from=build --chown=65532:65532 /out/var/lib/ /var/lib/",
		`VOLUME ["/var/lib/qory-github"]`,
		"ENV QORY_FEATURES=factory",
		"ENV QORY_GITHUB_STATE_DIR=/var/lib/qory-github",
		"ENV QORY_GITHUB_LISTEN=:8080",
		"EXPOSE 8080",
		"USER 65532:65532",
		`ENTRYPOINT ["/qory-github-server"]`,
	} {
		if !slices.Contains(server.lines, line) {
			t.Errorf("the server's image has no %s", line)
		}
	}
	// The stage the program is built in runs on the platform of the machine that builds.
	if !strings.HasPrefix(all[0].from, "FROM --platform=$BUILDPLATFORM golang:") || !strings.HasSuffix(all[0].from, " AS build") {
		t.Errorf("the first stage is %q, want the build stage on $BUILDPLATFORM", all[0].from)
	}
	// The program is built with the release's flags, for the image's platform, which
	// the build stage declares.
	const flags = `RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \`
	var builds int
	for _, s := range all {
		for _, line := range s.lines {
			if strings.Contains(line, "go build") {
				builds++
				if line != flags {
					t.Errorf("%s builds with %q, not %q", s.from, line, flags)
				}
				for _, arg := range []string{"ARG TARGETOS", "ARG TARGETARCH"} {
					if !slices.Contains(s.lines, arg) {
						t.Errorf("%s builds without %s", s.from, arg)
					}
				}
			}
		}
	}
	if builds != 1 {
		t.Errorf("the Dockerfile has %d builds, want 1", builds)
	}
}
