# Google's mirror of the Docker Hub image (same digest): Docker Hub rate-limits CI runners.
FROM mirror.gcr.io/library/golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mail-setup-links . \
    && mkdir /out/data

# Alpine instead of a distroless image: a host that runs its own health check inside the
# container (Podman's HealthCmd) needs a shell and wget. The same mirror as above.
FROM mirror.gcr.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=build /out/mail-setup-links /mail-setup-links
# ACME account key and signing certificate; mount a volume here to keep them across restarts.
COPY --from=build --chown=65532:65532 /out/data /data
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 3000
# No user of Alpine: the UID the distroless image ran as, so existing volumes stay writable.
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/mail-setup-links", "healthcheck"]
ENTRYPOINT ["/mail-setup-links"]
