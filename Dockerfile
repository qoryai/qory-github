# The container images of qory-github-server, the server that connects a GitHub App to
# Qory Apiary, built from cmd/qory-github-server, and of qory-github-starter, the
# starter of a node pool of Qory Apiary, built from cmd/qory-github-starter. The program
# qory-github, which qory's gateway runs, is released as archives and is in neither
# image.
#
# The images are private: they exist only for the feature factory, which is off by
# default and switched on by QORY_FEATURES, so each image sets QORY_FEATURES=factory
# below.
#
# Build from the repository's root. The server's image is the default target, the last
# stage below; the starter's is the target starter:
#
#   docker build --build-arg VERSION=dev -t qory-github-server .
#   docker build --build-arg VERSION=dev --target starter -t qory-github-starter .
#
# Run, with the settings and the secret files mounted by the operator:
#
#   docker run -v /etc/qory-github:/etc/qory-github:ro -v qory-github-state:/var/lib/qory-github \
#     qory-github-server serve --settings /etc/qory-github/serve.json
#   docker run -v /etc/qory-github-starter:/etc/qory-github-starter:ro \
#     -v qory-github-starter-state:/var/lib/qory-github-starter \
#     qory-github-starter serve --settings /etc/qory-github-starter/starter.json
#
# Each serve listens on plain HTTP on the settings' listen: public_url must be served
# over HTTPS by a proxy in front of listen that terminates TLS, and the starter's
# public_url must be reachable by GitHub's runners.
#
# The images hold no secret and no settings. The secret files the settings name are
# mounted by the operator: the server's private_key_file, webhook_secret_file,
# access_key_secret_file and client_secret_file, and the starter's
# access_key_secret_file and private_key_file. serve refuses each one that does not
# belong to the user it runs as, or that grants group or others any permission. Each
# program runs as distroless's nonroot user, uid 65532 and gid 65532, so on the host:
#
#   chown 65532:65532 FILE && chmod 0600 FILE   # for each secret file
#
# or run the container with --user set to the uid and gid that own the files. The state
# directory must then belong to that uid too: the images' /var/lib/qory-github and
# /var/lib/qory-github-starter are 65532's, and serve refuses a state directory that
# belongs to another user, so mount there, or at the settings' state_dir, a directory
# that uid owns, 0700. A volume mechanism that adds group permission to the files it
# mounts, such as Kubernetes' fsGroup, makes serve refuse them.
#
# The base images are pinned by version tag and by digest; distroless publishes no
# version tags, so its tag names the Debian release and the user.

FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# The version the program reports, as the release's tag without its v; dev when none is
# given.
ARG VERSION=dev
# The same build flags as the release's archives of qory-github.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/qory-github-server ./cmd/qory-github-server

# The state directory, 0700 as serve makes it; it is given to the nonroot user below.
# /out/var/lib/ is copied whole, so the directory keeps its mode.
RUN mkdir -p /out/var/lib/qory-github && chmod 0700 /out/var/lib/qory-github

# The starter's build, from the server's: the same source, toolchain and build flags.
# The server's image is built without it.
FROM build AS starter-build

# The version the program reports, as in the server's build.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /starter/qory-github-starter ./cmd/qory-github-starter

# The starter's state directory, 0700 as serve makes it; it is given to the nonroot
# user below. /starter/var/lib/ is copied whole, so the directory keeps its mode.
RUN mkdir -p /starter/var/lib/qory-github-starter && chmod 0700 /starter/var/lib/qory-github-starter

# The starter's image: docker build --target starter.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS starter

COPY --from=starter-build /starter/qory-github-starter /qory-github-starter

# serve's state, the settings' state_dir: the instance id. It must belong to the user
# serve runs as, and grant group and others no permission; a named volume mounted here
# starts as a copy of this directory.
COPY --from=starter-build --chown=65532:65532 /starter/var/lib/ /var/lib/
VOLUME ["/var/lib/qory-github-starter"]

# The image exists only for the feature factory, see above: without it the program
# knows no command.
ENV QORY_FEATURES=factory

USER 65532:65532
ENTRYPOINT ["/qory-github-starter"]

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

USER 65532:65532
ENTRYPOINT ["/qory-github-server"]
