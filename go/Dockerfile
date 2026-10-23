# Two binaries (tremor, loadgen) in a small non-root image.
FROM golang:1.26.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tremor ./cmd/tremor && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loadgen ./cmd/loadgen

FROM alpine:3.22
RUN adduser -D -u 10001 tremor && mkdir -p /data /etc/tremor && chown tremor /data
COPY --from=build /out/tremor /out/loadgen /usr/local/bin/
COPY deploy/tremor.yaml /etc/tremor/tremor.yaml
USER tremor
VOLUME /data
# ingest HTTP, OTLP/gRPC, OTLP/HTTP, Prometheus metrics
EXPOSE 8080 4317 4318 2112
ENTRYPOINT ["tremor", "-config", "/etc/tremor/tremor.yaml"]
