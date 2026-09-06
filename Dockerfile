# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/spki-fingerprint-exporter .

FROM scratch

COPY <<EOT /etc/passwd
spki-exporter:x:1000:1000:spki-exporter:/app:/sbin/nologin
EOT

COPY <<EOT /etc/group
spki-exporter:x:1000:
EOT

COPY --from=build /out/spki-fingerprint-exporter /spki-fingerprint-exporter

USER 1000:1000
EXPOSE 3000/tcp

ENTRYPOINT ["/spki-fingerprint-exporter"]
