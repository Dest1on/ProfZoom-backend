FROM golang:1.22-alpine AS build

ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=off
ENV GOPROXY=$GOPROXY
ENV GOSUMDB=$GOSUMDB

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/otp_bot ./cmd/server

FROM alpine:3.19
RUN adduser -D -g '' appuser
USER appuser
COPY --from=build /out/otp_bot /usr/local/bin/otp_bot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/otp_bot"]
