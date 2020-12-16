package limit

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test read multiple for race conditions
func TestMultipleGetVisitor(t *testing.T) {
	limitConfig := Config{
		BucketSize:          3,
		RefillRate:          1,
		CleanupInterval:     3 * time.Minute,
		VisitorOldTimeLimit: 5 * time.Minute,
	}
	limiter := NewLimiter(limitConfig)
	wg := &sync.WaitGroup{}

	for i := 0; i < 30; i++ {
		wg.Add(2)

		go func(wg *sync.WaitGroup, limiter *Limiter) {
			limiter.GetVisitor(uuid.New().String())
			wg.Done()
		}(wg, limiter)

		go func(wg *sync.WaitGroup, limiter *Limiter) {
			limiter.GetVisitor(uuid.New().String())
			wg.Done()
		}(wg, limiter)
	}
	wg.Wait()
}

// TestIsAllowedVisitor tests three times in a row if a visitor with a bucket
// size of two is allowed.
func TestIsAllowedVisitor(t *testing.T) {
	limitConfig := Config{
		BucketSize:          2,
		RefillRate:          0.1,
		CleanupInterval:     3 * time.Minute,
		VisitorOldTimeLimit: 5 * time.Minute,
	}
	limiter := NewLimiter(limitConfig)
	ip := "127.0.0.1"

	got := []bool{}

	for i := 0; i < 3; i++ {
		got = append(got, limiter.GetVisitor(ip).IsAllowed())
	}
	expected := true
	if got[0] != expected || got[1] != expected {
		// first two should be allowed
		t.Errorf("Got %t and %t, Expected both to be %t", got[0], got[1], expected)
		t.Logf("Got %+v", got)
	}

	expected = false
	if got[2] != expected {
		// Third should be false since bucketsize is 2 (and the refill is very
		// slow).
		t.Errorf("Got %t, expected %t", got[2], expected)
		t.Logf("Got %+v", got)
	}
}
