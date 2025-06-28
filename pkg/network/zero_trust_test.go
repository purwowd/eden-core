package network

import (
	"testing"
	"time"
)

func TestZeroTrustNetwork(t *testing.T) {
	config := &ZeroTrustConfig{
		TokenExpiry:    time.Hour,
		MaxRetries:     3,
		RetryInterval:  time.Second,
		AllowedDomains: []string{"example.com"},
	}

	network, err := NewZeroTrustNetwork(config)
	if err != nil {
		t.Fatalf("Failed to create network: %v", err)
	}

	t.Run("Authentication", func(t *testing.T) {
		token, err := network.Authenticate("test-user", "test-pass")
		if err != nil {
			t.Fatalf("Authentication failed: %v", err)
		}
		if token == "" {
			t.Error("Authentication token should not be empty")
		}

		// Test invalid credentials
		_, err = network.Authenticate("invalid", "invalid")
		if err == nil {
			t.Error("Authentication should fail with invalid credentials")
		}
	})

	t.Run("Authorization", func(t *testing.T) {
		token, _ := network.Authenticate("test-user", "test-pass")

		// Test valid token
		authorized, err := network.Authorize(token, "example.com")
		if err != nil {
			t.Fatalf("Authorization check failed: %v", err)
		}
		if !authorized {
			t.Error("Valid token should be authorized")
		}

		// Test invalid domain
		authorized, _ = network.Authorize(token, "invalid.com")
		if authorized {
			t.Error("Invalid domain should not be authorized")
		}

		// Test invalid token
		authorized, _ = network.Authorize("invalid-token", "example.com")
		if authorized {
			t.Error("Invalid token should not be authorized")
		}
	})

	t.Run("TokenExpiry", func(t *testing.T) {
		config := &ZeroTrustConfig{
			TokenExpiry: time.Millisecond * 100,
		}
		network, err := NewZeroTrustNetwork(config)
		if err != nil {
			t.Fatalf("Failed to create network: %v", err)
		}

		token, _ := network.Authenticate("test-user", "test-pass")
		time.Sleep(time.Millisecond * 150)

		authorized, _ := network.Authorize(token, "example.com")
		if authorized {
			t.Error("Expired token should not be authorized")
		}
	})

	t.Run("RetryMechanism", func(t *testing.T) {
		config := &ZeroTrustConfig{
			MaxRetries:    2,
			RetryInterval: time.Millisecond * 100,
		}
		network, err := NewZeroTrustNetwork(config)
		if err != nil {
			t.Fatalf("Failed to create network: %v", err)
		}

		start := time.Now()
		network.simulateFailure = true // Mock failure for testing
		_, err = network.Authenticate("test-user", "test-pass")
		duration := time.Since(start)

		if err == nil {
			t.Error("Authentication should fail after retries")
		}
		if duration < time.Millisecond*200 {
			t.Error("Retry mechanism not working as expected")
		}
	})
}
