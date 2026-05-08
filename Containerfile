FROM docker.io/library/golang:1.25-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/indieauth-bridge ./cmd/indieauth-bridge

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="indieauth-bridge" \
      org.opencontainers.image.description="Self-hostable IndieAuth-to-OIDC bridge with first-class authentik support" \
      org.opencontainers.image.source="https://github.com/OWNER/indieauth-bridge" \
      org.opencontainers.image.licenses="MIT"

USER nonroot:nonroot
WORKDIR /
COPY --from=build /out/indieauth-bridge /indieauth-bridge

EXPOSE 8080
VOLUME ["/data"]
ENV IAB_CONFIG=/config/config.yaml
ENTRYPOINT ["/indieauth-bridge"]
