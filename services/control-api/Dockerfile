FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/control-api ./cmd/control-api

FROM alpine:3.20
RUN adduser -D -H bedemwaf
COPY --from=build /out/control-api /usr/local/bin/bedemwaf-control-api
USER bedemwaf
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/bedemwaf-control-api"]
