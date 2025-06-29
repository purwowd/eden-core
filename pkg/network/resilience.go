package network

import (
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerConfig represents configuration for circuit breaker
type CircuitBreakerConfig struct {
	MaxFailures      int           // Maximum number of failures before opening
	ResetTimeout     time.Duration // How long to wait before attempting reset
	HalfOpenMaxTries int           // Maximum tries in half-open state
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config      CircuitBreakerConfig
	failures    int
	lastFailure time.Time
	state       CBState
	mu          sync.RWMutex
}

// CBState represents circuit breaker states
type CBState int

const (
	CBClosed   CBState = iota // Normal operation
	CBOpen                    // Circuit is open, failing fast
	CBHalfOpen                // Testing if service is healthy
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  CBClosed,
	}
}

// Execute runs an operation with circuit breaker protection
func (cb *CircuitBreaker) Execute(operation func() error) error {
	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	// Check if circuit is open
	if state == CBOpen {
		if !cb.shouldAttemptReset() {
			return fmt.Errorf("circuit breaker is open")
		}
		// Try half-open state
		cb.mu.Lock()
		cb.state = CBHalfOpen
		cb.mu.Unlock()
	}

	// Execute operation
	err := operation()

	// Handle result
	if err != nil {
		cb.recordFailure()
		return fmt.Errorf("operation failed: %v", err)
	}

	// Success - close circuit if in half-open
	if state == CBHalfOpen {
		cb.mu.Lock()
		cb.state = CBClosed
		cb.failures = 0
		cb.mu.Unlock()
	}

	return nil
}

// RetryConfig represents configuration for retry mechanism
type RetryConfig struct {
	MaxAttempts     int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
}

// RetryWithBackoff implements exponential backoff retry
func RetryWithBackoff(config RetryConfig, operation func() error) error {
	var lastErr error
	interval := config.InitialInterval

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}
		lastErr = err

		// Don't sleep if this was the last attempt
		if attempt == config.MaxAttempts {
			break
		}

		// Calculate next interval with exponential backoff
		interval = time.Duration(float64(interval) * config.Multiplier)
		if interval > config.MaxInterval {
			interval = config.MaxInterval
		}

		time.Sleep(interval)
	}

	return fmt.Errorf("operation failed after %d attempts: %v", config.MaxAttempts, lastErr)
}

// Internal helper functions

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.config.MaxFailures {
		cb.state = CBOpen
	}
}

func (cb *CircuitBreaker) shouldAttemptReset() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Check if enough time has passed since last failure
	if time.Since(cb.lastFailure) > cb.config.ResetTimeout {
		return true
	}

	return false
}

// NetworkResilience combines circuit breaker and retry mechanisms
type NetworkResilience struct {
	circuitBreaker *CircuitBreaker
	retryConfig    RetryConfig
}

// NewNetworkResilience creates a new network resilience system
func NewNetworkResilience(cbConfig CircuitBreakerConfig, retryConfig RetryConfig) *NetworkResilience {
	return &NetworkResilience{
		circuitBreaker: NewCircuitBreaker(cbConfig),
		retryConfig:    retryConfig,
	}
}

// ExecuteWithResilience executes an operation with full resilience patterns
func (nr *NetworkResilience) ExecuteWithResilience(operation func() error) error {
	return nr.circuitBreaker.Execute(func() error {
		return RetryWithBackoff(nr.retryConfig, operation)
	})
}
