FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/worker ./cmd/worker

FROM alpine:3.20
RUN adduser -D -H bedemwaf
COPY --from=build /out/worker /usr/local/bin/bedemwaf-worker
USER bedemwaf
ENTRYPOINT ["/usr/local/bin/bedemwaf-worker"]
