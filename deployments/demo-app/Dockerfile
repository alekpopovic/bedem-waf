FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/demo-app .

FROM alpine:3.20
RUN adduser -D -H demo
COPY --from=build /out/demo-app /usr/local/bin/demo-app
USER demo
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/demo-app"]
