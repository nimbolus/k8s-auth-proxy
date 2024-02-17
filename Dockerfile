FROM golang:1.21 as builder

COPY go.mod go.sum main.go /app/

WORKDIR /app

RUN CGO_ENABLED=0 go build -o /app/k8s-auth-proxy

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/k8s-auth-proxy /k8s-auth-proxy

ENTRYPOINT ["/k8s-auth-proxy"]
