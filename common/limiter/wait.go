package limiter

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

// WaitN accounts for large I/O buffers without exceeding the limiter's burst.
func WaitN(ctx context.Context, limiter *rate.Limiter, n int) error {
	if limiter.Limit() == rate.Inf {
		return limiter.WaitN(ctx, n)
	}
	for n > 0 {
		burst := limiter.Burst()
		if burst <= 0 {
			return fmt.Errorf("rate limiter burst must be positive")
		}
		chunk := min(n, burst)
		if err := limiter.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
