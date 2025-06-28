// Package monitoring provides performance tracking and metrics collection
package monitoring

import (
	"sync"
	"time"

	"github.com/purwowd/eden-core/internal/interfaces"
)

// PerformanceMonitor tracks operation durations
type PerformanceMonitor struct {
	mu            sync.RWMutex
	startTime     time.Time
	operations    int64
	totalDuration time.Duration
	maxDuration   time.Duration
	minDuration   time.Duration
	starts        map[string]time.Time
	stats         map[string][]time.Duration
	metrics       map[string]*Metric
}

// Metric represents a performance metric
type Metric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Unit      string            `json:"unit"`
	Tags      map[string]string `json:"tags"`
	Timestamp time.Time         `json:"timestamp"`
	Count     int64             `json:"count"`
	Sum       float64           `json:"sum"`
	Min       float64           `json:"min"`
	Max       float64           `json:"max"`
	Avg       float64           `json:"avg"`
}

// OperationTracker tracks individual operation performance
type OperationTracker struct {
	name      string
	startTime time.Time
	metadata  map[string]interface{}
	monitor   *PerformanceMonitor
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		startTime:   time.Now(),
		minDuration: time.Hour, // Initialize with high value
		starts:      make(map[string]time.Time),
		stats:       make(map[string][]time.Duration),
		metrics:     make(map[string]*Metric),
	}
}

// Start begins timing an operation
func (pm *PerformanceMonitor) Start(operation string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.starts[operation] = time.Now()
}

// Stop ends timing an operation and returns its duration
func (pm *PerformanceMonitor) Stop(operation string) time.Duration {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	start, exists := pm.starts[operation]
	if !exists {
		return 0
	}

	duration := time.Since(start)
	delete(pm.starts, operation)

	if _, exists := pm.stats[operation]; !exists {
		pm.stats[operation] = make([]time.Duration, 0)
	}
	pm.stats[operation] = append(pm.stats[operation], duration)

	// Update overall statistics
	pm.operations++
	pm.totalDuration += duration
	if duration > pm.maxDuration {
		pm.maxDuration = duration
	}
	if duration < pm.minDuration {
		pm.minDuration = duration
	}

	return duration
}

// GetStats returns all operation statistics
func (pm *PerformanceMonitor) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]interface{})

	// Only include stats if there are operations
	if len(pm.stats) > 0 || pm.operations > 0 {
		for op, durations := range pm.stats {
			var total time.Duration
			for _, d := range durations {
				total += d
			}
			avg := time.Duration(0)
			lastDuration := time.Duration(0)
			if len(durations) > 0 {
				avg = total / time.Duration(len(durations))
				lastDuration = durations[len(durations)-1]
			}

			stats[op] = map[string]interface{}{
				"count":         len(durations),
				"total":         total.String(),
				"average":       avg.String(),
				"last_duration": lastDuration.String(),
				"all_durations": durations,
			}
		}

		stats["uptime"] = time.Since(pm.startTime).String()
		stats["operations"] = pm.operations
		stats["total_duration"] = pm.totalDuration.String()
		stats["max_duration"] = pm.maxDuration.String()
		stats["min_duration"] = pm.minDuration.String()
		if pm.operations > 0 {
			stats["avg_duration"] = time.Duration(int64(pm.totalDuration) / pm.operations).String()
		} else {
			stats["avg_duration"] = "0s"
		}
	}

	return stats
}

// Reset clears all statistics
func (pm *PerformanceMonitor) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.startTime = time.Now()
	pm.operations = 0
	pm.totalDuration = 0
	pm.maxDuration = 0
	pm.minDuration = time.Hour
	pm.starts = make(map[string]time.Time)
	pm.stats = make(map[string][]time.Duration)
	pm.metrics = make(map[string]*Metric)
}

// OperationTracker methods

// End completes the operation tracking and records metrics
func (ot *OperationTracker) End() time.Duration {
	duration := time.Since(ot.startTime)

	ot.monitor.mu.Lock()
	defer ot.monitor.mu.Unlock()

	// Update global statistics
	ot.monitor.operations++

	// Update duration statistics
	if ot.monitor.totalDuration == 0 {
		ot.monitor.totalDuration = duration
	} else {
		ot.monitor.totalDuration = (ot.monitor.totalDuration + duration) / 2
	}

	if duration > ot.monitor.maxDuration {
		ot.monitor.maxDuration = duration
	}

	if duration < ot.monitor.minDuration {
		ot.monitor.minDuration = duration
	}

	// Record operation-specific metrics
	ot.monitor.RecordMetric(ot.name+"_duration", float64(duration.Milliseconds()), map[string]string{
		"operation": ot.name,
		"status":    "completed",
	})

	// Record throughput metrics
	if bytes, ok := ot.metadata["bytes_processed"].(int64); ok {
		throughput := float64(bytes) / duration.Seconds()
		ot.monitor.RecordMetric("throughput", throughput, map[string]string{
			"operation": ot.name,
			"unit":      "bytes/sec",
		})
	}

	// Clean up completed operation
	for key, op := range ot.monitor.stats {
		if op[len(op)-1] == duration {
			ot.monitor.stats[key] = op[:len(op)-1]
			break
		}
	}

	return duration
}

// AddMetadata adds metadata to the operation tracker
func (ot *OperationTracker) AddMetadata(key string, value interface{}) {
	ot.metadata[key] = value
}

// GetDuration returns the current duration of the operation
func (ot *OperationTracker) GetDuration() time.Duration {
	return time.Since(ot.startTime)
}

// MarkSuccess marks the operation as successful
func (ot *OperationTracker) MarkSuccess() {
	ot.monitor.mu.Lock()
	defer ot.monitor.mu.Unlock()
	ot.monitor.operations++
}

// MarkFailure marks the operation as failed
func (ot *OperationTracker) MarkFailure(err error) {
	ot.monitor.mu.Lock()
	defer ot.monitor.mu.Unlock()
	ot.metadata["error"] = err.Error()
}

// Helper methods

// GetTopMetrics returns the top N metrics by value
func (pm *PerformanceMonitor) GetTopMetrics(n int) []*Metric {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	metrics := make([]*Metric, 0, len(pm.stats))
	for op, durations := range pm.stats {
		metrics = append(metrics, &Metric{
			Name:      op,
			Value:     float64(len(durations)),
			Unit:      "ops",
			Timestamp: time.Now(),
		})
	}

	// Sort metrics by value (descending)
	for i := 0; i < len(metrics)-1; i++ {
		for j := i + 1; j < len(metrics); j++ {
			if metrics[i].Value < metrics[j].Value {
				metrics[i], metrics[j] = metrics[j], metrics[i]
			}
		}
	}

	if n > len(metrics) {
		n = len(metrics)
	}

	return metrics[:n]
}

// GetMetrics returns all recorded metrics and operation statistics
func (pm *PerformanceMonitor) GetMetrics() []*Metric {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Get metrics from the metrics map
	metrics := make([]*Metric, 0, len(pm.metrics)+len(pm.stats))
	for _, metric := range pm.metrics {
		metrics = append(metrics, metric)
	}

	// Convert operation statistics to metrics
	for op, durations := range pm.stats {
		var total time.Duration
		for _, d := range durations {
			total += d
		}

		avg := time.Duration(0)
		lastDuration := time.Duration(0)
		if len(durations) > 0 {
			avg = total / time.Duration(len(durations))
			lastDuration = durations[len(durations)-1]
		}

		metric := &Metric{
			Name:      op + "_stats",
			Value:     float64(lastDuration.Milliseconds()),
			Unit:      "milliseconds",
			Tags:      map[string]string{"operation": op},
			Timestamp: time.Now(),
			Count:     int64(len(durations)),
			Sum:       float64(total.Milliseconds()),
			Min:       float64(pm.minDuration.Milliseconds()),
			Max:       float64(pm.maxDuration.Milliseconds()),
			Avg:       float64(avg.Milliseconds()),
		}
		metrics = append(metrics, metric)
	}

	return metrics
}

// GetMetricsByTag returns metrics filtered by tag
func (pm *PerformanceMonitor) GetMetricsByTag(tagKey, tagValue string) map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	metrics := make(map[string]interface{})
	for op, durations := range pm.stats {
		if op == tagKey {
			var total time.Duration
			for _, d := range durations {
				total += d
			}
			avg := time.Duration(0)
			lastDuration := time.Duration(0)
			if len(durations) > 0 {
				avg = total / time.Duration(len(durations))
				lastDuration = durations[len(durations)-1]
			}

			metrics[op] = map[string]interface{}{
				"count":         len(durations),
				"total":         total.String(),
				"average":       avg.String(),
				"last_duration": lastDuration.String(),
				"all_durations": durations,
			}
		}
	}

	return metrics
}

// ExportPrometheusFormat exports metrics in Prometheus format
func (pm *PerformanceMonitor) ExportPrometheusFormat() map[string]float64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	prometheus := make(map[string]float64)
	prometheus["eden_uptime_seconds"] = time.Since(pm.startTime).Seconds()
	prometheus["eden_operations_total"] = float64(pm.operations)
	prometheus["eden_total_duration_seconds"] = pm.totalDuration.Seconds()
	prometheus["eden_max_duration_seconds"] = pm.maxDuration.Seconds()
	prometheus["eden_min_duration_seconds"] = pm.minDuration.Seconds()

	if pm.operations > 0 {
		prometheus["eden_avg_duration_seconds"] = pm.totalDuration.Seconds() / float64(pm.operations)
	}

	return prometheus
}

// ExportGrafanaFormat exports metrics in Grafana format
func (pm *PerformanceMonitor) ExportGrafanaFormat() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	grafana := make(map[string]interface{})
	grafana["uptime"] = time.Since(pm.startTime).String()
	grafana["operations"] = pm.operations
	grafana["total_duration"] = pm.totalDuration.String()
	grafana["max_duration"] = pm.maxDuration.String()
	grafana["min_duration"] = pm.minDuration.String()

	if pm.operations > 0 {
		grafana["avg_duration"] = time.Duration(int64(pm.totalDuration) / pm.operations).String()
	} else {
		grafana["avg_duration"] = "0s"
	}

	return grafana
}

// StartOperation starts tracking a new operation
func (pm *PerformanceMonitor) StartOperation(name string) interfaces.PerformanceTracker {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	tracker := &OperationTracker{
		name:      name,
		startTime: time.Now(),
		metadata:  make(map[string]interface{}),
		monitor:   pm,
	}

	return tracker
}

// RecordMetric records a performance metric
func (pm *PerformanceMonitor) RecordMetric(name string, value float64, tags map[string]string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	metric, exists := pm.metrics[name]
	if !exists {
		metric = &Metric{
			Name:      name,
			Tags:      make(map[string]string),
			Min:       value,
			Max:       value,
			Timestamp: time.Now(),
		}
		pm.metrics[name] = metric
	}

	// Update metric statistics
	metric.Count++
	metric.Sum += value
	metric.Value = value
	metric.Avg = metric.Sum / float64(metric.Count)
	metric.Timestamp = time.Now()

	if value < metric.Min {
		metric.Min = value
	}
	if value > metric.Max {
		metric.Max = value
	}

	// Update tags
	for k, v := range tags {
		metric.Tags[k] = v
	}

	// Determine unit based on metric name
	switch name {
	case "file_size", "bytes_processed", "memory_usage":
		metric.Unit = "bytes"
	case "operation_duration", "response_time":
		metric.Unit = "milliseconds"
	case "throughput", "operations_per_second":
		metric.Unit = "ops/sec"
	case "cpu_usage", "success_rate":
		metric.Unit = "percent"
	default:
		metric.Unit = "count"
	}
}
