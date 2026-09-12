package limiter

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestWaitLargeBuffer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := WaitN(ctx, rate.NewLimiter(1000000, 8), 64); err != nil {
		t.Fatal(err)
	}
}

func TestWaitCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WaitN(ctx, rate.NewLimiter(1, 8), 64); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestWaitZeroBurst(t *testing.T) {
	if err := WaitN(context.Background(), rate.NewLimiter(1, 0), 1); err == nil {
		t.Fatal("expected invalid burst error")
	}
}

func TestWaitUnlimited(t *testing.T) {
	if err := WaitN(context.Background(), rate.NewLimiter(rate.Inf, 0), 65536); err != nil {
		t.Fatal(err)
	}
}
