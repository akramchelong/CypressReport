// package limit is a rate-limiting package based on golang.org/x/time, which
// in turn implements a token bucket.

package limit

import (
	"sync"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"golang.org/x/time/rate"
)

type Config struct {
	// BucketSize is the max amount of tokens inside the bucket
	BucketSize int

	// RefillRate is how many tokens that are refilled per second
	RefillRate rate.Limit

	// CleanupInterval is how often the cleanup of old visitors should run
	CleanupInterval time.Duration

	// VisitorOldTimeLimit is the time limit for when a visitor can be deleted
	VisitorOldTimeLimit time.Duration
}

type Limiter struct {
	Config   Config
	visitors map[string]*Visitor
	mux      sync.Mutex
}

type Visitor struct {
	lastVisit time.Time
	bucket    *rate.Limiter
}

// IsAllowed returns true if the visitor is allowed to access the resource, and
// will consume one token if access is granted.
//
// In other words, will return true if there are any tokens left in the bucket,
// as well as decrease the amount of token inside the bucket by one.
func (v *Visitor) IsAllowed() bool {
	return v.bucket.Allow()
}

// NewLimiter will create a new limiter based on the provided configuration.
// A goroutine will be started in the background that will cleanup old
// visitors.
func NewLimiter(c Config) *Limiter {
	validateConfig(c)
	data := make(map[string]*Visitor)
	l := &Limiter{
		Config:   c,
		visitors: data,
	}

	go l.cleanupVisitor()

	return l
}

// GetVisitor will always return a visitor. If the visitor is new a new visitor
// object will be created. key is the value to rate limit on, e.g. clientIp + path.
// Example: "127.0.0.1/v1/keys"
func (l *Limiter) GetVisitor(key string) *Visitor {
	l.mux.Lock()
	defer l.mux.Unlock()
	v, ok := l.visitors[key]
	if !ok {
		logger.Debug("New visitor with key %q", key)
		v = &Visitor{
			lastVisit: time.Now(),
			bucket:    rate.NewLimiter(l.Config.RefillRate, l.Config.BucketSize),
		}
		l.visitors[key] = v
		return v
	}
	v.lastVisit = time.Now()

	return v
}

// validateConfig validates the configuration and throws a fatal log message if
// it fails.
func validateConfig(c Config) {
	if c.RefillRate <= 0 {
		logger.Fatal("Limiter: RefillRate must be larger than zero.")
	}

	if c.BucketSize < 0 {
		logger.Fatal("Limiter: BucketSize must be >= zero.")
	}
}

// cleanupVisitor will remove a visitor from the map at interval set by the
// limit config.
func (l *Limiter) cleanupVisitor() {
	logger.Info("Will cleanup old visitors at an interval of %s", l.Config.CleanupInterval.String())
	for {
		time.Sleep(l.Config.CleanupInterval)
		logger.Debug("Running cleanupVisitor (time limit is %s)", l.Config.VisitorOldTimeLimit.String())

		l.mux.Lock()
		for key, v := range l.visitors {
			if time.Since(v.lastVisit) > l.Config.VisitorOldTimeLimit {
				logger.Debug("Cleaning up visitor with key %q", key)
				delete(l.visitors, key)
			}
		}
		l.mux.Unlock()
	}
}
