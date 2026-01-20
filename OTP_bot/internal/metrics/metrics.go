package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Collector struct {
	requests uint64
	errors   uint64
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) IncRequests() {
	atomic.AddUint64(&c.requests, 1)
}

func (c *Collector) IncErrors() {
	atomic.AddUint64(&c.errors, 1)
}

func (c *Collector) Snapshot() (uint64, uint64) {
	return atomic.LoadUint64(&c.requests), atomic.LoadUint64(&c.errors)
}

type Handler struct {
	collector *Collector
}

func NewHandler(collector *Collector) *Handler {
	return &Handler{collector: collector}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var requests uint64
	var errors uint64
	if h.collector != nil {
		requests, errors = h.collector.Snapshot()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "# HELP otp_bot_requests_total Total number of HTTP requests.\n")
	_, _ = fmt.Fprintf(w, "# TYPE otp_bot_requests_total counter\n")
	_, _ = fmt.Fprintf(w, "otp_bot_requests_total %d\n", requests)
	_, _ = fmt.Fprintf(w, "# HELP otp_bot_errors_total Total number of 5xx HTTP responses.\n")
	_, _ = fmt.Fprintf(w, "# TYPE otp_bot_errors_total counter\n")
	_, _ = fmt.Fprintf(w, "otp_bot_errors_total %d\n", errors)
}
