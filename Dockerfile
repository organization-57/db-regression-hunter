FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hunter ./cmd/hunter
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /demo ./cmd/demo

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 hunter
USER hunter
COPY --from=build /hunter /usr/local/bin/hunter
COPY --from=build /demo /usr/local/bin/demo
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hunter"]
