FROM golang:latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./

RUN CGO_ENABLED=0 GOOS=linux go build -o auth-app ./cmd/api

CMD ["/app/auth-app"]