# Production Checklist

## Core configuration
- Set required API env vars: `DATABASE_URL`, `JWT_SECRET`, `OTP_BOT_BASE_URL`, `OTP_BOT_INTERNAL_KEY`, `REDIS_URL`.
- Set required OTP bot env vars: `TELEGRAM_BOT_TOKEN`, `API_BASE_URL`, `API_INTERNAL_KEY`, `OTP_BOT_INTERNAL_KEY`, `REDIS_URL`.
- Store secrets outside the repo and rotate defaults.

## Database and migrations
- Run migrations (migrator container or `migrate` job).
- Verify connection pool settings and database availability.

## Redis rate limiting
- Provision Redis and ensure `REDIS_URL` is reachable from API and OTP bot.
- Confirm rate limit keys expire as expected.

## Telegram webhook
- Set `TELEGRAM_POLLING_ENABLED=false` in production.
- Configure `TELEGRAM_WEBHOOK_URL` to the public HTTPS endpoint `/telegram/webhook`.
- Set `TELEGRAM_WEBHOOK_SECRET` and verify it matches inbound requests.
- Validate webhook delivery with a `/start` message.

## Monitoring and logs
- Scrape API `/metrics` and OTP bot `/metrics`.
- Add checks for API `/health` and OTP bot `/health`.
- Alert on 5xx responses and unexpected OTP/authorization failures.

## Security and auth
- Validate OTP TTLs and rate limits for abuse resistance.
- Rotate `JWT_SECRET` and internal service keys.

## Deployment checks
- Verify service restart policies and resource limits.
- Run a smoke test for auth, profile, vacancies, applications, and chat.
