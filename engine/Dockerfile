# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/weedout-engine ./cmd/weedout-engine

FROM scratch
COPY --from=build /out/weedout-engine /weedout-engine
USER 65532:65532
EXPOSE 8080
ENV ENGINE_ADDR=:8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 CMD ["/weedout-engine", "healthcheck"]
ENTRYPOINT ["/weedout-engine"]
