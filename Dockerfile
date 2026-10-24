# The container image of qory-github-server, the server that connects a GitHub App to
# Qory Apiary, built from cmd/qory-github-server. The program qory-github, which qory's
# gateway runs, is released as archives and is not in the image.
#
# The image is private: it exists only for the feature factory, which is off by default
# and switched on by QORY_FEATURES, so the image sets QORY_FEATURES=factory below.
#
# Build from the repository's root. The server's image is the default target, the last
# stage below:
#
#   docker build --build-arg VERSION=dev -t qory-github-server .
#
# Build both platforms at once with docker buildx build --platform
# linux/amd64,linux/arm64. The build stage runs on the building machine's platform, and
# Go cross-compiles the program, so nothing runs under emulation.
#
# Pull the server's pre-release image by its digest from
# ghcr.io/qoryai/qory-github-server-prerelease. .github/workflows/prerelease.yml
# publishes it for both platforms, tags it only sha-<the commit's first 7 characters>,
# and prints the digest in the run's summary.
#
# Give the server its settings in a mounted serve.json with --settings, or, with no
# --settings, in QORY_GITHUB_* environment variables: each is a serve.json setting's
# name in upper case, such as QORY_GITHUB_PUBLIC_URL for public_url. With --settings,
# serve reads no QORY_GITHUB_* variable. Give the access key's secret as a value or as
# a file, never both: QORY_GITHUB_ACCESS_KEY_SECRET, or QORY_GITHUB_ACCESS_KEY_SECRET_FILE
# for a file that contains it. No setting contains the GitHub App: serve stores it in Qory
# Apiary, and keeps it in memory alone.
#
# For the server from a file, and the server from the environment:
#
#   docker run -v /etc/qory-github:/etc/qory-github:ro -v qory-github-state:/var/lib/qory-github \
#     qory-github-server serve --settings /etc/qory-github/serve.json
#   docker run --env-file /etc/qory-github/server.env -v qory-github-state:/var/lib/qory-github \
#     -p 8080:8080 qory-github-server serve
#
# serve listens on plain HTTP on the settings' listen: public_url must be served over
# HTTPS by a proxy in front of listen that terminates TLS. The server's image sets
# QORY_GITHUB_LISTEN=:8080 and QORY_GITHUB_STATE_DIR=/var/lib/qory-github. To change
# them for a server run from the environment, set them in the environment you give
# docker run. With --settings, the server uses listen and state_dir from serve.json.
#
# The image contains no secret, and no setting except the server's listen and state_dir
# in its environment. When the settings point to a secret file, in serve.json or in
# QORY_GITHUB_ACCESS_KEY_SECRET_FILE, mount it. serve refuses a file that does not
# belong to the user it runs as, or that grants group or others any permission. The
# program runs as distroless's nonroot user, uid 65532 and gid 65532, so on the host:
#
#   chown 65532:65532 FILE && chmod 0600 FILE
#
# or run the container with --user set to the uid and gid that own the file. The state
# directory must then belong to that uid too: the image's /var/lib/qory-github is
# 65532's, and serve refuses a state directory that belongs to another user, so mount
# there, or at the settings' state_dir, a directory that uid owns, 0700. A volume
# mechanism that adds group permission to the files it mounts, such as Kubernetes'
# fsGroup, makes serve refuse them.
#
# The base images are pinned by version tag and by digest; distroless publishes no
# version tags, so its tag names the Debian release and the user. Pin each base image by
# its image index digest, not by one platform's image digest: the image is built for
# linux/amd64 and linux/arm64 from these pins.

# The build stage runs on the platform of the machine that builds, BUILDPLATFORM, which
# docker buildx sets, and cross-compiles for the platform of the image, TARGETOS and
# TARGETARCH below.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# The version the program reports: sha-<the commit's first 7 characters> for a
# pre-release image, and dev when none is given.
ARG VERSION=dev
# The platform of the image, which docker buildx sets from --platform, or to the platform
# of the machine that builds when no --platform is given.
ARG TARGETOS
ARG TARGETARCH
# The same build flags as the release's archives of qory-github, for the image's
# platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/qory-github-server ./cmd/qory-github-server

# The state directory, 0700 as serve makes it; it is given to the nonroot user below.
# /out/var/lib/ is copied whole, so the directory keeps its mode.
RUN mkdir -p /out/var/lib/qory-github && chmod 0700 /out/var/lib/qory-github

# The server's image, the last stage, so the default target: docker build with no
# --target builds it.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS server

COPY --from=build /out/qory-github-server /qory-github-server

# serve's state, the settings' state_dir: the store of webhook deliveries and what serve
# keeps between runs. It must belong to the user serve runs as, and grant group and
# others no permission; a named volume mounted here starts as a copy of this directory.
COPY --from=build --chown=65532:65532 /out/var/lib/ /var/lib/
VOLUME ["/var/lib/qory-github"]

# The image exists only for the feature factory, see above: without it the program
# knows no command.
ENV QORY_FEATURES=factory

# The state directory and the address serve listens on when it runs with no --settings
# and reads its settings from the environment, see above; with --settings, serve.json
# sets them and these are not read.
ENV QORY_GITHUB_STATE_DIR=/var/lib/qory-github
ENV QORY_GITHUB_LISTEN=:8080
EXPOSE 8080

USER 65532:65532
ENTRYPOINT ["/qory-github-server"]
