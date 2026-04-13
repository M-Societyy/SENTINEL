# sentinel crawler - go build
# m-society & c1q_

FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o sentinel-crawler ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/sentinel-crawler /usr/local/bin/
EXPOSE 8081 50051
CMD ["sentinel-crawler"]
