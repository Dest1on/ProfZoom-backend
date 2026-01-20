FROM golang:1.24-alpine

ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=off
ENV GOPROXY=$GOPROXY
ENV GOSUMDB=$GOSUMDB

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o api ./cmd/api

EXPOSE 8080

CMD ["./api"]
