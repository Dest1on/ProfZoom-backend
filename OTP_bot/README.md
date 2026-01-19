# ProfZoom OTP Bot

OTP_bot — это сервис доставки и привязки Telegram. Он НЕ генерирует, не проверяет и не хранит OTP коды. Он только отправляет предоставленные OTP коды в Telegram и управляет привязкой аккаунтов Telegram к `user_id`.

## Обязанности

- Доставка OTP через Telegram.
- Привязка Telegram по link‑коду (`user_id` + token).
- Один HTTP сервер публикует эндпоинты: `/telegram/webhook`, `/telegram/link-token`, `/telegram/status`, `/otp/send`, `/health`.

## Переменные окружения

Требуются:

```
TELEGRAM_BOT_TOKEN=replace_me
OTP_BOT_INTERNAL_KEY=replace_me
```

Опционально (показаны значения по умолчанию):

```
DATABASE_URL=postgres://user:pass@localhost:5432/profzoom?sslmode=disable
DB_DRIVER=pgx
TELEGRAM_WEBHOOK_SECRET=replace_me
TELEGRAM_LINK_TTL=10m
LINK_TOKEN_RATE_LIMIT_PER_MIN=5
LINK_TOKEN_RATE_LIMIT_IP_PER_MIN=5
LINK_TOKEN_RATE_LIMIT_BOT_PER_MIN=5
PORT=8080
LOG_LEVEL=info
TELEGRAM_TIMEOUT=5s
TELEGRAM_POLLING_ENABLED=true
TELEGRAM_POLLING_TIMEOUT=25s
TELEGRAM_POLLING_INTERVAL=1s
TELEGRAM_POLLING_LIMIT=50
TELEGRAM_POLLING_DROP_PENDING=true
TELEGRAM_POLLING_DROP_WEBHOOK=true
TELEGRAM_INBOUND_RATE_LIMIT_PER_MIN=30
OTP_RATE_LIMIT_PER_MIN=2
OTP_RATE_LIMIT_IP_PER_MIN=2
OTP_RATE_LIMIT_BOT_PER_MIN=60
```

For local development without a public webhook URL, enable polling so Telegram updates are handled immediately.


Лимиты per‑IP/per‑bot по умолчанию используют их текущие значения per‑minute, если переменные не заданы.
`TELEGRAM_LINK_TTL` должен быть между 5m и 10m.
Если `DATABASE_URL` не задан, сервис использует in‑memory хранилища.

## Миграции

Запустите SQL из каталога `migrations/` в вашей базе Postgres.
Таблицы, используемые этим сервисом: `telegram_links`, `telegram_link_tokens`.
`telegram_links` принадлежит этому сервису; если основной бэкенд зеркалит ее, синхронизируйте схемы.

## HTTP эндпоинты

Спецификация OpenAPI доступна в `openapi.yaml`.

### POST /telegram/link-token

Регистрация одноразового токена привязки Telegram.

Headers:

```
X-Internal-Key: ${OTP_BOT_INTERNAL_KEY}
```

Body:

```
{ "user_id": "<uuid>", "token": "PZ-XXXXXXX" }
```

Response:

```
{ "success": true }
```

### GET /telegram/status

Возвращает статус привязки Telegram.

Headers:

```
X-Internal-Key: ${OTP_BOT_INTERNAL_KEY}
```

Query (любой из вариантов):

```
/telegram/status?user_id=<uuid>
/telegram/status?chat_id=123456789
```

Response:

```
{ "linked": true|false }
```

### POST /telegram/webhook

Эндпоинт Telegram webhook.

Headers:

```
X-Telegram-Bot-Api-Secret-Token: ${TELEGRAM_WEBHOOK_SECRET}
```

Поддерживает `/start <link_code>`, `/help`, `/status`, `/code`, а также отправку link‑кода в виде обычного сообщения.

### POST /otp/send (legacy)

Эндпоинт только для доставки OTP по телефону (legacy).

Headers:

```
X-Internal-Key: ${OTP_BOT_INTERNAL_KEY}
```

Body:

```
{ "phone": "+15551234567", "code": "834291" }
```

Responses:

- `200` `{ "sent": true }`
- `400` `{ "error": "invalid_payload" }` или `{ "error": "phone_not_linked" }`
- `401` `{ "error": "unauthorized" }`
- `429` `{ "error": "rate_limited" }`
- `500` `{ "error": "telegram_failed" }`

### GET /health

Эндпоинт проверки здоровья.

Response:

```
{ "status": "ok" }
```

## Процесс привязки

1. Приложение вызывает `POST /auth/register` в основном API и получает `user_id` + `link_code`.
2. Основной бэкенд регистрирует `link_code` через `POST /telegram/link-token`.
3. Пользователь отправляет `link_code` боту (или `/start <link_code>`).
4. OTP_bot связывает чат с `user_id` и запрашивает OTP через `POST /auth/request-code`.
5. Пользователь вводит OTP в приложении через `POST /auth/verify-code`.

## Запуск локально

```
go run ./cmd/server
```

## CI

```
go test ./...
```
