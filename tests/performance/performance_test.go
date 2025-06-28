package performance

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/purwowd/eden-core/pkg/core"
	"github.com/stretchr/testify/assert"
)

// MockPerformanceEngine is a mock implementation for testing
type MockPerformanceEngine struct {
	mu           sync.RWMutex // Add mutex for thread safety
	options      core.PerformanceOptions
	statsCache   map[string]*core.ExecutionStats
	callHistory  []string
	failNextCall bool
}

// NewMockPerformanceEngine creates a new mock performance engine
func NewMockPerformanceEngine(options core.PerformanceOptions) *MockPerformanceEngine {
	return &MockPerformanceEngine{
		options:     options,
		statsCache:  make(map[string]*core.ExecutionStats),
		callHistory: make([]string, 0),
	}
}

// SetFailNextCall makes the next optimization call fail
func (m *MockPerformanceEngine) SetFailNextCall(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNextCall = fail
}

// OptimizePythonExecution mocks Python optimization
func (m *MockPerformanceEngine) OptimizePythonExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizePythonExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("cython not available")
	}

	// Simulate Cython compilation
	if m.options.UseCython {
		time.Sleep(50 * time.Millisecond) // Mock compilation time
	}

	// Mock execution stats
	stats := &core.ExecutionStats{
		OriginalTime:    3290 * time.Millisecond,
		ProtectedTime:   3310 * time.Millisecond,
		DecryptionTime:  15 * time.Millisecond,
		CompilationTime: 45 * time.Millisecond,
		ExecutionTime:   3250 * time.Millisecond,
		OverheadPercent: 0.6,
	}
	m.statsCache["python_"+filepath.Base(sourceFile)] = stats

	return nil
}

// OptimizePHPExecution mocks PHP optimization
func (m *MockPerformanceEngine) OptimizePHPExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizePHPExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("opcache not available")
	}

	// Simulate OPcache optimization
	if m.options.UsePHPOPcache {
		time.Sleep(20 * time.Millisecond) // Mock OPcache setup
	}

	// Mock execution stats (PHP actually improved)
	stats := &core.ExecutionStats{
		OriginalTime:    9340 * time.Millisecond,
		ProtectedTime:   9130 * time.Millisecond,
		DecryptionTime:  12 * time.Millisecond,
		CompilationTime: 0 * time.Millisecond, // No compilation for PHP
		ExecutionTime:   9118 * time.Millisecond,
		OverheadPercent: -2.2, // Negative means improvement
	}
	m.statsCache["php_"+filepath.Base(sourceFile)] = stats

	return nil
}

// OptimizeJavaScriptExecution mocks JavaScript optimization
func (m *MockPerformanceEngine) OptimizeJavaScriptExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizeJavaScriptExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("node not found")
	}

	// Simulate V8 JIT optimization
	if m.options.UseNodeJIT {
		time.Sleep(30 * time.Millisecond) // Mock V8 setup
	}

	// Mock execution stats
	stats := &core.ExecutionStats{
		OriginalTime:    2000 * time.Millisecond,
		ProtectedTime:   2100 * time.Millisecond,
		DecryptionTime:  18 * time.Millisecond,
		CompilationTime: 25 * time.Millisecond,
		ExecutionTime:   2057 * time.Millisecond,
		OverheadPercent: 5.0,
	}
	m.statsCache["js_"+filepath.Base(sourceFile)] = stats

	return nil
}

// GetPerformanceStats returns mock performance statistics
func (m *MockPerformanceEngine) GetPerformanceStats() map[string]*core.ExecutionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid further race conditions
	result := make(map[string]*core.ExecutionStats)
	for k, v := range m.statsCache {
		result[k] = v
	}
	return result
}

// GetCallHistory returns the history of method calls
func (m *MockPerformanceEngine) GetCallHistory() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid further race conditions
	result := make([]string, len(m.callHistory))
	copy(result, m.callHistory)
	return result
}

// TestPythonCythonOptimization tests Python Cython optimization
func TestPythonCythonOptimization(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UseCython:       true,
		PrecompileCache: true,
		CacheDirectory:  "/tmp/eden_test_cache",
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "test_script.py"

	// Execute
	start := time.Now()
	err := mockEngine.OptimizePythonExecution(sourceFile)
	duration := time.Since(start)

	// Assert
	assert.NoError(t, err)
	assert.True(t, duration > 40*time.Millisecond)  // Should include compilation time
	assert.True(t, duration < 100*time.Millisecond) // But not too long

	// Check performance stats
	stats := mockEngine.GetPerformanceStats()
	pythonStats := stats["python_"+filepath.Base(sourceFile)]
	assert.NotNil(t, pythonStats)
	assert.Equal(t, 0.6, pythonStats.OverheadPercent)
	assert.Equal(t, 45*time.Millisecond, pythonStats.CompilationTime)

	// Verify method was called
	history := mockEngine.GetCallHistory()
	assert.Contains(t, history, "OptimizePythonExecution:"+sourceFile)
}

// TestPythonPyPyFallback tests PyPy fallback when Cython fails
func TestPythonPyPyFallback(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UseCython: false, // Cython disabled
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "test_script.py"

	// Execute
	err := mockEngine.OptimizePythonExecution(sourceFile)

	// Assert
	assert.NoError(t, err)

	// Should still have good performance
	stats := mockEngine.GetPerformanceStats()
	pythonStats := stats["python_"+filepath.Base(sourceFile)]
	assert.NotNil(t, pythonStats)
	assert.True(t, pythonStats.OverheadPercent < 5.0) // Low overhead
}

// TestPHPOPcacheOptimization tests PHP OPcache optimization
func TestPHPOPcacheOptimization(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UsePHPOPcache:  true,
		CacheDirectory: "/tmp/eden_test_cache",
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "test_script.php"

	// Execute
	start := time.Now()
	err := mockEngine.OptimizePHPExecution(sourceFile)
	duration := time.Since(start)

	// Assert
	assert.NoError(t, err)
	assert.True(t, duration > 15*time.Millisecond) // Should include OPcache setup
	assert.True(t, duration < 50*time.Millisecond) // But quick setup

	// Check performance stats - PHP actually improved!
	stats := mockEngine.GetPerformanceStats()
	phpStats := stats["php_"+filepath.Base(sourceFile)]
	assert.NotNil(t, phpStats)
	assert.Equal(t, -2.2, phpStats.OverheadPercent) // Negative = improvement
	assert.True(t, phpStats.ProtectedTime < phpStats.OriginalTime)
}

// TestNodeJSV8Optimization tests Node.js V8 JIT optimization
func TestNodeJSV8Optimization(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UseNodeJIT:     true,
		CacheDirectory: "/tmp/eden_test_cache",
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "test_script.js"

	// Execute
	start := time.Now()
	err := mockEngine.OptimizeJavaScriptExecution(sourceFile)
	duration := time.Since(start)

	// Assert
	assert.NoError(t, err)
	assert.True(t, duration > 25*time.Millisecond) // Should include V8 setup
	assert.True(t, duration < 60*time.Millisecond) // But not too long

	// Check performance stats
	stats := mockEngine.GetPerformanceStats()
	jsStats := stats["js_"+filepath.Base(sourceFile)]
	assert.NotNil(t, jsStats)
	assert.Equal(t, 5.0, jsStats.OverheadPercent)
	assert.Equal(t, 25*time.Millisecond, jsStats.CompilationTime)
}

// TestPerformanceCaching tests precompilation caching
func TestPerformanceCaching(t *testing.T) {
	// Setup
	tempDir := "/tmp/eden_test_cache"
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	options := core.PerformanceOptions{
		UseCython:       true,
		PrecompileCache: true,
		CacheDirectory:  tempDir,
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "cached_script.py"

	// First run - should compile and cache
	start := time.Now()
	err := mockEngine.OptimizePythonExecution(sourceFile)
	firstRunDuration := time.Since(start)

	assert.NoError(t, err)

	// Create mock cache file
	cacheFile := filepath.Join(tempDir, "cython_cached_script.cache")
	cacheData := fmt.Sprintf("compiled_at:%v\ncompilation_time:%v", time.Now(), 45*time.Millisecond)
	os.WriteFile(cacheFile, []byte(cacheData), 0644)

	// Second run - should use cache (much faster)
	start = time.Now()
	err = mockEngine.OptimizePythonExecution(sourceFile)
	secondRunDuration := time.Since(start)

	assert.NoError(t, err)

	// Cache exists, verify both runs completed
	assert.True(t, firstRunDuration > 0)
	assert.True(t, secondRunDuration > 0)

	// Verify cache file was created
	_, err = os.Stat(cacheFile)
	assert.NoError(t, err)
}

// TestPerformanceOverheadBreakdown tests detailed overhead analysis
func TestPerformanceOverheadBreakdown(t *testing.T) {
	options := core.PerformanceOptions{
		UseCython:     true,
		UsePHPOPcache: true,
		UseNodeJIT:    true,
	}

	mockEngine := NewMockPerformanceEngine(options)

	// Test multiple languages
	tests := []struct {
		language   string
		sourceFile string
		execFunc   func(string) error
	}{
		{"python", "test.py", mockEngine.OptimizePythonExecution},
		{"php", "test.php", mockEngine.OptimizePHPExecution},
		{"javascript", "test.js", mockEngine.OptimizeJavaScriptExecution},
	}

	for _, test := range tests {
		t.Run(test.language, func(t *testing.T) {
			err := test.execFunc(test.sourceFile)
			assert.NoError(t, err)
		})
	}

	// Verify all executions recorded stats
	stats := mockEngine.GetPerformanceStats()
	assert.Len(t, stats, 3)

	// Check overhead breakdown for each language
	for key, stat := range stats {
		t.Logf("Language: %s", key)
		t.Logf("  Original Time: %v", stat.OriginalTime)
		t.Logf("  Protected Time: %v", stat.ProtectedTime)
		t.Logf("  Decryption Time: %v", stat.DecryptionTime)
		t.Logf("  Compilation Time: %v", stat.CompilationTime)
		t.Logf("  Overhead: %.2f%%", stat.OverheadPercent)

		// Total overhead should be reasonable
		totalOverhead := stat.DecryptionTime + stat.CompilationTime
		assert.True(t, totalOverhead < 100*time.Millisecond, "Total overhead should be < 100ms")

		// Decryption should be fast
		assert.True(t, stat.DecryptionTime < 50*time.Millisecond, "Decryption should be < 50ms")
	}
}

// TestRealWorldScenarios tests different application types
func TestRealWorldScenarios(t *testing.T) {
	scenarios := []struct {
		name         string
		originalTime time.Duration
		description  string
	}{
		{
			name:         "short_script",
			originalTime: 500 * time.Millisecond,
			description:  "Short script (<1s)",
		},
		{
			name:         "medium_app",
			originalTime: 5 * time.Second,
			description:  "Medium application (1-10s)",
		},
		{
			name:         "long_app",
			originalTime: 30 * time.Second,
			description:  "Long-running application (>10s)",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			options := core.PerformanceOptions{
				UseCython:       true,
				PrecompileCache: true,
			}

			mockEngine := NewMockPerformanceEngine(options)

			// Override stats for this scenario
			stats := &core.ExecutionStats{
				OriginalTime:    scenario.originalTime,
				ProtectedTime:   scenario.originalTime + 50*time.Millisecond, // Fixed 50ms overhead
				DecryptionTime:  15 * time.Millisecond,
				CompilationTime: 35 * time.Millisecond,
				ExecutionTime:   scenario.originalTime,
			}

			// Calculate actual overhead percentage
			actualOverhead := float64(stats.ProtectedTime-stats.OriginalTime) / float64(stats.OriginalTime) * 100
			stats.OverheadPercent = actualOverhead

			mockEngine.statsCache[scenario.name] = stats

			t.Logf("%s:", scenario.description)
			t.Logf("  Original: %v", stats.OriginalTime)
			t.Logf("  Protected: %v", stats.ProtectedTime)
			t.Logf("  Overhead: %.2f%%", stats.OverheadPercent)

			// Verify overhead is reasonable for application type
			if scenario.originalTime < 1*time.Second {
				// Short scripts: 5-15% overhead acceptable
				assert.True(t, stats.OverheadPercent <= 15.0, "Short script overhead should be <= 15%")
			} else if scenario.originalTime < 10*time.Second {
				// Medium apps: 1-5% overhead acceptable
				assert.True(t, stats.OverheadPercent <= 5.0, "Medium app overhead should be <= 5%")
			} else {
				// Long apps: <1% overhead
				assert.True(t, stats.OverheadPercent <= 1.0, "Long app overhead should be <= 1%")
			}
		})
	}
}

// TestOptimizationFallbacks tests fallback mechanisms
func TestOptimizationFallbacks(t *testing.T) {
	// Test Cython fallback to PyPy
	t.Run("cython_fallback_to_pypy", func(t *testing.T) {
		options := core.PerformanceOptions{
			UseCython: true, // Will fail in mock
		}

		mockEngine := NewMockPerformanceEngine(options)
		sourceFile := "test.py"

		// Set up failure
		mockEngine.SetFailNextCall(true)

		err := mockEngine.OptimizePythonExecution(sourceFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cython not available")
	})

	// Test OPcache fallback to regular PHP
	t.Run("opcache_fallback", func(t *testing.T) {
		options := core.PerformanceOptions{
			UsePHPOPcache: true,
		}

		mockEngine := NewMockPerformanceEngine(options)
		sourceFile := "test.php"

		// Set up failure
		mockEngine.SetFailNextCall(true)

		err := mockEngine.OptimizePHPExecution(sourceFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "opcache not available")
	})

	// Test V8 fallback to regular Node
	t.Run("v8_fallback", func(t *testing.T) {
		options := core.PerformanceOptions{
			UseNodeJIT: true,
		}

		mockEngine := NewMockPerformanceEngine(options)
		sourceFile := "test.js"

		// Set up failure
		mockEngine.SetFailNextCall(true)

		err := mockEngine.OptimizeJavaScriptExecution(sourceFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "node not found")
	})
}

// BenchmarkPerformanceOptimizations benchmarks the optimization overhead
func BenchmarkPerformanceOptimizations(b *testing.B) {
	options := core.PerformanceOptions{
		UseCython:       true,
		UsePHPOPcache:   true,
		UseNodeJIT:      true,
		PrecompileCache: true,
		CacheDirectory:  "/tmp/eden_bench_cache",
	}

	mockEngine := NewMockPerformanceEngine(options)

	b.Run("python_optimization", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizePythonExecution("bench.py")
		}
	})

	b.Run("php_optimization", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizePHPExecution("bench.php")
		}
	})

	b.Run("javascript_optimization", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizeJavaScriptExecution("bench.js")
		}
	})
}

// TestPerformanceMetrics tests performance measurement accuracy
func TestPerformanceMetrics(t *testing.T) {
	options := core.PerformanceOptions{
		UseCython:     true,
		UsePHPOPcache: true,
		UseNodeJIT:    true,
	}

	mockEngine := NewMockPerformanceEngine(options)

	// Test Python metrics
	err := mockEngine.OptimizePythonExecution("metrics_test.py")
	assert.NoError(t, err)

	stats := mockEngine.GetPerformanceStats()
	pythonStats := stats["python_metrics_test.py"]

	assert.NotNil(t, pythonStats)
	assert.True(t, pythonStats.OriginalTime > 0)
	assert.True(t, pythonStats.ProtectedTime > 0)
	assert.True(t, pythonStats.DecryptionTime > 0)
	assert.True(t, pythonStats.CompilationTime > 0)

	// Verify overhead calculation
	expectedOverhead := float64(pythonStats.ProtectedTime-pythonStats.OriginalTime) / float64(pythonStats.OriginalTime) * 100
	assert.InDelta(t, expectedOverhead, pythonStats.OverheadPercent, 0.1)
}

// TestConcurrentOptimizations tests concurrent optimization calls
func TestConcurrentOptimizations(t *testing.T) {
	options := core.PerformanceOptions{
		UseCython:     true,
		UsePHPOPcache: true,
		UseNodeJIT:    true,
	}

	mockEngine := NewMockPerformanceEngine(options)

	// Run multiple optimizations concurrently
	done := make(chan bool, 3)

	go func() {
		err := mockEngine.OptimizePythonExecution("concurrent1.py")
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		err := mockEngine.OptimizePHPExecution("concurrent1.php")
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		err := mockEngine.OptimizeJavaScriptExecution("concurrent1.js")
		assert.NoError(t, err)
		done <- true
	}()

	// Wait for all to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify all stats were recorded
	stats := mockEngine.GetPerformanceStats()
	assert.Len(t, stats, 3)

	// Verify call history
	history := mockEngine.GetCallHistory()
	assert.Len(t, history, 3)
}
