package monitoring

import (
	"testing"
	"time"
)

func TestPerformanceMonitor(t *testing.T) {
	monitor := NewPerformanceMonitor()

	t.Run("StartStop", func(t *testing.T) {
		monitor.Start("test_operation")
		time.Sleep(100 * time.Millisecond)
		duration := monitor.Stop("test_operation")

		if duration < 100*time.Millisecond {
			t.Errorf("Duration should be at least 100ms, got %v", duration)
		}
	})

	t.Run("MultipleOperations", func(t *testing.T) {
		monitor.Start("op1")
		time.Sleep(50 * time.Millisecond)
		monitor.Start("op2")
		time.Sleep(50 * time.Millisecond)

		dur2 := monitor.Stop("op2")
		dur1 := monitor.Stop("op1")

		if dur2 < 50*time.Millisecond {
			t.Errorf("Operation 2 duration should be at least 50ms, got %v", dur2)
		}
		if dur1 < 100*time.Millisecond {
			t.Errorf("Operation 1 duration should be at least 100ms, got %v", dur1)
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		monitor.Start("stats_test")
		time.Sleep(100 * time.Millisecond)
		monitor.Stop("stats_test")

		stats := monitor.GetStats()
		if len(stats) == 0 {
			t.Error("Stats should not be empty")
		}

		if _, exists := stats["stats_test"]; !exists {
			t.Error("Stats should contain 'stats_test' operation")
		}
	})

	t.Run("Reset", func(t *testing.T) {
		monitor.Start("to_reset")
		time.Sleep(50 * time.Millisecond)
		monitor.Stop("to_reset")

		monitor.Reset()
		stats := monitor.GetStats()
		if len(stats) > 0 {
			t.Error("Stats should be empty after reset")
		}
	})

	t.Run("InvalidOperation", func(t *testing.T) {
		duration := monitor.Stop("nonexistent")
		if duration != 0 {
			t.Error("Stopping nonexistent operation should return zero duration")
		}
	})

	t.Run("GetMetrics", func(t *testing.T) {
		monitor.Reset()

		// Record a custom metric
		monitor.RecordMetric("test_metric", 42.0, map[string]string{"tag": "value"})

		// Record an operation
		monitor.Start("test_operation")
		time.Sleep(50 * time.Millisecond)
		monitor.Stop("test_operation")

		metrics := monitor.GetMetrics()

		// Should have at least 2 metrics (custom metric + operation stats)
		if len(metrics) < 2 {
			t.Errorf("Expected at least 2 metrics, got %d", len(metrics))
		}

		// Verify custom metric
		var foundCustomMetric bool
		var foundOperationMetric bool

		for _, metric := range metrics {
			switch metric.Name {
			case "test_metric":
				foundCustomMetric = true
				if metric.Value != 42.0 {
					t.Errorf("Expected test_metric value to be 42.0, got %f", metric.Value)
				}
				if metric.Tags["tag"] != "value" {
					t.Errorf("Expected test_metric tag 'tag' to be 'value', got '%s'", metric.Tags["tag"])
				}
			case "test_operation_stats":
				foundOperationMetric = true
				if metric.Count != 1 {
					t.Errorf("Expected operation count to be 1, got %d", metric.Count)
				}
				if metric.Tags["operation"] != "test_operation" {
					t.Errorf("Expected operation tag to be 'test_operation', got '%s'", metric.Tags["operation"])
				}
				if metric.Unit != "milliseconds" {
					t.Errorf("Expected unit to be 'milliseconds', got '%s'", metric.Unit)
				}
			}
		}

		if !foundCustomMetric {
			t.Error("Custom metric not found in GetMetrics output")
		}
		if !foundOperationMetric {
			t.Error("Operation metric not found in GetMetrics output")
		}
	})
}
