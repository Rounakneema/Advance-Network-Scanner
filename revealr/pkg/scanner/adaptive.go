// pkg/scanner/adaptive.go
package scanner

import (
	"context"
	"time"
)

// AdaptiveScanner manages adaptive behavior for scans (e.g., rate limiting, timeouts).
type AdaptiveScanner struct {
	rateLimiter chan struct{} // Channel to control rate limit
	config      *AdaptiveConfig
}

// AdaptiveConfig holds configuration for adaptive scanning.
type AdaptiveConfig struct {
	Timeout   time.Duration // Default timeout for operations
	Retries   int           // Number of retries for failed operations
	RateLimit int           // Max operations per second (0 for no limit)
}

// NewAdaptiveScanner creates a new AdaptiveScanner.
func NewAdaptiveScanner(cfg *AdaptiveConfig) *AdaptiveScanner {
	as := &AdaptiveScanner{
		config: cfg,
	}
	if cfg.RateLimit > 0 {
		as.rateLimiter = make(chan struct{}, cfg.RateLimit)
		go as.startRateLimiter()
	}
	return as
}

// startRateLimiter continuously feeds tokens into the rateLimiter channel.
func (as *AdaptiveScanner) startRateLimiter() {
	if as.config.RateLimit <= 0 {
		return // No rate limit
	}
	interval := time.Second / time.Duration(as.config.RateLimit)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case as.rateLimiter <- struct{}{}:
			// Token added successfully
		default:
			// Channel full, indicating rate limit is hit.
			// This typically means the consumer is not fast enough.
		}
	}
}

// Acquire blocks until a token is available or context is done.
// Returns true if token acquired, false if context done.
func (as *AdaptiveScanner) Acquire(ctx context.Context) bool {
	if as.rateLimiter == nil {
		return true // No rate limit
	}
	select {
	case <-ctx.Done():
		return false
	case <-as.rateLimiter:
		return true
	}
}

// GetTimeout returns the configured timeout.
func (as *AdaptiveScanner) GetTimeout() time.Duration {
	return as.config.Timeout
}

// GetRetries returns the configured retries.
func (as *AdaptiveScanner) GetRetries() int {
	return as.config.Retries
}
