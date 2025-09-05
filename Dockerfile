# Многоэтапная сборка для минимального размера образа
FROM golang:1.21-alpine AS builder

# Установка зависимостей для сборки
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Копирование файлов зависимостей
COPY go.mod go.sum ./

# Загрузка зависимостей
RUN go mod download

# Копирование исходного кода
COPY main.go ./

# Сборка приложения с оптимизациями
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o servercore-webhook .

# Финальный образ - используем distroless для минимального размера
FROM gcr.io/distroless/static-debian11:nonroot

# Копирование исполняемого файла
COPY --from=builder /app/servercore-webhook /servercore-webhook

# Открытие порта
EXPOSE 8080

# Запуск приложения
ENTRYPOINT ["/servercore-webhook"]
