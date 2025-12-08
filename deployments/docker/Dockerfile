FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o waf cmd/waf/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/waf .
COPY --from=builder /app/configs ./configs

EXPOSE 8080
CMD ["./waf", "-config", "configs/config.yaml"]