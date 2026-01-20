package middleware

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const rateLimitScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
if current > tonumber(ARGV[2]) then
  return 0
end
return 1
`

type RedisLimiter struct {
	client *redis.Client
	script *redis.Script
}

func NewRedisLimiter(client *redis.Client) *RedisLimiter {
	if client == nil {
		return nil
	}
	return &RedisLimiter{
		client: client,
		script: redis.NewScript(rateLimitScript),
	}
}

func (l *RedisLimiter) Allow(key string, limit int, window time.Duration) bool {
	if l == nil || l.client == nil {
		return true
	}
	if key == "" || limit <= 0 || window <= 0 {
		return true
	}
	ttl := window.Milliseconds()
	if ttl <= 0 {
		ttl = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	allowed, err := l.script.Run(ctx, l.client, []string{key}, ttl, limit).Int64()
	if err != nil {
		return true
	}
	return allowed == 1
}
