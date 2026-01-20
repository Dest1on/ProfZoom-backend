package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type Limiter interface {
	Allow(key string, limit int, window time.Duration) bool
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

type rateBucket struct {
	count     int
	windowEnd time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*rateBucket)}
}

func (r *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	bucket, ok := r.buckets[key]
	if !ok || now.After(bucket.windowEnd) {
		r.buckets[key] = &rateBucket{count: 1, windowEnd: now.Add(window)}
		return true
	}
	if bucket.count >= limit {
		return false
	}
	bucket.count++
	return true
}

func RateLimit(limiter Limiter, keyFn func(*http.Request) string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if limiter == nil {
				next.ServeHTTP(w, r)
				return
			}
			if !limiter.Allow(key, limit, window) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
