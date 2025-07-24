# Сервис аутентификации

Микросервис для управления аутентификацией с использованием JWT и refresh токенов.

## Использованные технологии

- **Go 1.23.11** - основной язык разработки
- **PostgreSQL** - хранение данных
- **Gin** - веб-фреймворк
- **JWT** - аутентификация
- **Docker** - контейнеризация
- **Swagger** - документация API

## Запуск сервиса(вместе с бд)

### Требования
- Docker
- Docker Compose v2

### Инструкция

1. Склонируйте репозиторий
2. Измените .env файл(при необходимости)
3. Запустите сервис и бд одной командой"
```bash
docker compose -f docker-compose.yml up -d
```
4. Сервис доступен локально, по ссылке http://localhost:8080 (или другой порт, указанный в .env файле, во всех последующих ссылках тоже стоит порт 8080)

## Документация API

Доступно 4 роута API, а так же [swagger документация](http://localhost:8080/swagger/index.html).

### Описание эндпоинтов и примеры запросов

1. http://localhost:8080/api/auth - POST запрос на получение access и refresh токенов по GUID.

Пример запроса:

```bash
curl -X POST http://localhost:8080/api/auth \
  -H "Content-Type: application/json" \
  -d '{"GUID": "026b1196-05fa-49ec-acad-bb09ad170148"}'
```

2. http://localhost:8080/api/currentUser - GET запрос, на получение GUID текущего пользователя, требует Access токен в хедере(при тестировании в swagger'e используйте кнопку Authorize для установления Access хедера).

Пример запроса:

```bash
curl -X GET http://localhost:8080/api/currentUser \
  -H 'Access: Bearer *ВАШ ТОКЕН*'
```

3. http://localhost:8080/api/refresh - POST запрос, обновляет access и refresh токены, требует access токен в хедере, и refresh токен в теле запроса.

Пример запроса:

```bash
curl -X 'POST' \
  'http://localhost:8080/api/refresh' \
  -H 'Access: Bearer *ВАШ ACCESS ТОКЕН*' \
  -H 'Content-Type: application/json' \
  -d '{
  "refresh_token": "*ВАШ REFRESH ТОКЕН*"
}'
```

4. http://localhost:8080/api/deauthorize - POST запрос, запрещает текущему пользователю /currenUser и /refresh роуты, для *всех* его access токенов.

Пример запроса:

```bash
curl -X 'POST' \
  'http://localhost:8080/api/deauthorize' \
  -H "Authorization: Bearer *ВАШ ТОКЕН*"
```

Все запросы так же можно протестировать используя swagger.