FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway

FROM alpine:3.20
RUN adduser -D -H bedemwaf
WORKDIR /app
COPY --from=build /out/gateway /usr/local/bin/bedemwaf-gateway
COPY rules ./rules
USER bedemwaf
EXPOSE 8080
ENTRYPOINT ["bedemwaf-gateway"]
