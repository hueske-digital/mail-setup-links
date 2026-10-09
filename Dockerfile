FROM golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mail-setup-links . \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/mail-setup-links /mail-setup-links
# ACME account key and signing certificate; mount a volume here to keep them across restarts.
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 3000
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["/mail-setup-links", "healthcheck"]
ENTRYPOINT ["/mail-setup-links"]
