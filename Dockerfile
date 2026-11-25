# ---- build ----
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/coffer ./cmd/coffer

# ---- run ----
FROM alpine:3.20
RUN adduser -D -u 10001 coffer && mkdir -p /data && chown coffer /data
COPY --from=build /out/coffer /usr/local/bin/coffer
USER coffer
VOLUME ["/data"]
# API + UI, S3, master, volume
EXPOSE 8200 8333 9333 8080
ENTRYPOINT ["coffer"]
CMD ["server", "-dir=/data", "-ip=0.0.0.0"]
