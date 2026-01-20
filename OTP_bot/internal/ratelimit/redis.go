package ratelimit

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
	limit  int
	window time.Duration
	prefix string
	script *redis.Script
}

func NewRedisLimiter(client *redis.Client, limit int, window time.Duration, prefix string) *RedisLimiter {
	if client == nil {
		return nil
	}
	return &RedisLimiter{
		client: client,
		limit:  limit,
		window: window,
		prefix: prefix,
		script: redis.NewScript(rateLimitScript),
	}
}

func (l *RedisLimiter) Allow(key string) bool {
	if l == nil || l.client == nil {
		return true
	}
	if l.limit <= 0 || l.window <= 0 {
		return true
	}
	if key == "" {
		return true
	}
	redisKey := key
	if l.prefix != "" {
		redisKey = l.prefix + ":" + key
	}
	ttl := l.window.Milliseconds()
	if ttl <= 0 {
		ttl = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	allowed, err := l.script.Run(ctx, l.client, []string{redisKey}, ttl, l.limit).Int64()
	if err != nil {
		return true
	}
	return allowed == 1
}
