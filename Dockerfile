# Stage 1: build the web UI from source so the image never depends on a
# stale committed web/dist.
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build the static server binary. The build context excludes .git
# (see .dockerignore), so the version arrives as a build arg: `make
# docker-build` passes `git describe --tags --always`, and the compose file
# forwards $VERSION from the host environment when set.
FROM golang:1.26.8-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/cutsheet ./cmd/cutsheet

# Stage 3: runtime. Alpine instead of distroless on purpose: the compose
# healthcheck needs an in-container HTTP probe (busybox wget) and first-run
# token bootstrap is friendlier with a shell available for `docker compose
# exec`. The binary itself is static; the base adds ~8 MB.
FROM alpine:3.21
RUN addgroup -S cutsheet && adduser -S -G cutsheet cutsheet \
    && mkdir /data && chown cutsheet:cutsheet /data
COPY --from=build /out/cutsheet /usr/local/bin/cutsheet
USER cutsheet
VOLUME /data
EXPOSE 8633
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD wget -q -O /dev/null http://127.0.0.1:8633/healthz || exit 1
# ENTRYPOINT/CMD split on purpose: the default `docker compose up` serves,
# while one-shot subcommands stay easy, e.g.
#   docker compose run --rm cutsheet demo --data-dir /data
#   docker compose exec cutsheet cutsheet token create --data-dir /data --name admin
ENTRYPOINT ["cutsheet"]
CMD ["serve", "--data-dir", "/data", "--listen", "0.0.0.0:8633"]
