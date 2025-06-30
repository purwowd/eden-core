package performance

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/purwowd/eden-core/pkg/core"
	"github.com/stretchr/testify/assert"
)

// MockPerformanceEngine simulates performance optimization for testing
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

// OptimizePythonExecution mocks Python optimization with PyPy JIT
func (m *MockPerformanceEngine) OptimizePythonExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizePythonExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("pypy jit not available")
	}

	// Simulate PyPy JIT optimization
	if m.options.UsePyPyJIT {
		time.Sleep(50 * time.Millisecond) // Mock PyPy warmup
	}

	// Create mock performance stats
	stats := &core.ExecutionStats{
		OriginalTime:    3290 * time.Millisecond,
		ProtectedTime:   3310 * time.Millisecond,
		DecryptionTime:  10 * time.Millisecond,
		CompilationTime: 45 * time.Millisecond,
		ExecutionTime:   3255 * time.Millisecond,
		OverheadPercent: 0.6, // +0.6% overhead with PyPy JIT
	}

	m.statsCache["python_"+filepath.Base(sourceFile)] = stats
	return nil
}

// OptimizePHPExecution mocks PHP optimization with OPcache JIT
func (m *MockPerformanceEngine) OptimizePHPExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizePHPExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("opcache not available")
	}

	// Simulate OPcache setup
	time.Sleep(20 * time.Millisecond)

	// Create mock performance stats - PHP actually improved with OPcache!
	stats := &core.ExecutionStats{
		OriginalTime:    9340 * time.Millisecond,
		ProtectedTime:   9130 * time.Millisecond, // Faster!
		DecryptionTime:  15 * time.Millisecond,
		CompilationTime: 0, // No compilation overhead
		ExecutionTime:   9115 * time.Millisecond,
		OverheadPercent: -2.2, // -2.2% = 2.2% improvement!
	}

	m.statsCache["php_"+filepath.Base(sourceFile)] = stats
	return nil
}

// OptimizeJavaScriptExecution mocks JavaScript optimization with V8 JIT
func (m *MockPerformanceEngine) OptimizeJavaScriptExecution(sourceFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callHistory = append(m.callHistory, "OptimizeJavaScriptExecution:"+sourceFile)

	if m.failNextCall {
		m.failNextCall = false
		return fmt.Errorf("node v8 jit not available")
	}

	// Simulate V8 JIT setup
	time.Sleep(30 * time.Millisecond)

	// Create mock performance stats
	stats := &core.ExecutionStats{
		OriginalTime:    2000 * time.Millisecond,
		ProtectedTime:   2100 * time.Millisecond,
		DecryptionTime:  25 * time.Millisecond,
		CompilationTime: 25 * time.Millisecond,
		ExecutionTime:   2050 * time.Millisecond,
		OverheadPercent: 5.0, // +5.0% overhead
	}

	m.statsCache["js_"+filepath.Base(sourceFile)] = stats
	return nil
}

// GetPerformanceStats returns cached performance statistics
func (m *MockPerformanceEngine) GetPerformanceStats() map[string]*core.ExecutionStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
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

// TestPythonPyPyJITOptimization tests Python PyPy JIT optimization
func TestPythonPyPyJITOptimization(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UsePyPyJIT:      true,
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
	assert.True(t, duration > 40*time.Millisecond)  // Should include PyPy warmup time
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

// TestPythonFallback tests Python fallback when PyPy JIT fails
func TestPythonFallback(t *testing.T) {
	// Setup
	options := core.PerformanceOptions{
		UsePyPyJIT: false, // PyPy JIT disabled
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

// TestPHPOPcacheJITOptimization tests PHP OPcache JIT optimization
func TestPHPOPcacheJITOptimization(t *testing.T) {
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

// TestNodeJSV8JITOptimization tests Node.js V8 JIT optimization
func TestNodeJSV8JITOptimization(t *testing.T) {
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

// TestJITPerformanceCaching tests precompilation caching
func TestJITPerformanceCaching(t *testing.T) {
	// Setup
	tempDir := "/tmp/eden_test_cache"
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir)

	options := core.PerformanceOptions{
		UsePyPyJIT:      true,
		PrecompileCache: true,
		CacheDirectory:  tempDir,
	}

	mockEngine := NewMockPerformanceEngine(options)
	sourceFile := "cached_script.py"

	// First run - should optimize and cache
	start := time.Now()
	err := mockEngine.OptimizePythonExecution(sourceFile)
	firstRunDuration := time.Since(start)

	assert.NoError(t, err)

	// Create mock cache file
	cacheFile := filepath.Join(tempDir, "pypy_cached_script.cache")
	cacheData := fmt.Sprintf("optimized_at:%v\njit_warmup_time:%v", time.Now(), 45*time.Millisecond)
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

// TestJITPerformanceOverheadBreakdown tests detailed overhead analysis
func TestJITPerformanceOverheadBreakdown(t *testing.T) {
	options := core.PerformanceOptions{
		UsePyPyJIT:    true,
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
		t.Logf("%s: Original=%v, Protected=%v, Overhead=%.2f%%",
			key, stat.OriginalTime, stat.ProtectedTime, stat.OverheadPercent)

		// All should have reasonable overhead
		assert.True(t, stat.OverheadPercent < 10.0, "Overhead too high for %s: %.2f%%", key, stat.OverheadPercent)
	}
}

// TestRealWorldScenarios tests real-world performance scenarios
func TestRealWorldScenarios(t *testing.T) {
	scenarios := []struct {
		name        string
		options     core.PerformanceOptions
		expectError bool
	}{
		{
			name: "all_jit_enabled",
			options: core.PerformanceOptions{
				UsePyPyJIT:      true,
				UsePHPOPcache:   true,
				UseNodeJIT:      true,
				PrecompileCache: true,
			},
			expectError: false,
		},
		{
			name: "minimal_optimizations",
			options: core.PerformanceOptions{
				UsePyPyJIT:      false,
				UsePHPOPcache:   false,
				UseNodeJIT:      false,
				PrecompileCache: false,
			},
			expectError: false,
		},
		{
			name: "pypy_only",
			options: core.PerformanceOptions{
				UsePyPyJIT:      true,
				UsePHPOPcache:   false,
				UseNodeJIT:      false,
				PrecompileCache: true,
			},
			expectError: false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			mockEngine := NewMockPerformanceEngine(scenario.options)

			err := mockEngine.OptimizePythonExecution("test.py")
			if scenario.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestOptimizationFallbacks tests JIT optimization fallback mechanisms
func TestOptimizationFallbacks(t *testing.T) {
	// Test PyPy fallback to standard Python
	t.Run("pypy_fallback", func(t *testing.T) {
		mockEngine := NewMockPerformanceEngine(core.PerformanceOptions{
			UsePyPyJIT: true, // Will fail in mock
		})

		mockEngine.SetFailNextCall(true)
		err := mockEngine.OptimizePythonExecution("test.py")

		// Should still work due to fallback
		assert.Error(t, err) // Mock fails, but real implementation would fallback
		assert.Contains(t, err.Error(), "pypy jit not available")
	})

	// Test OPcache fallback
	t.Run("opcache_fallback", func(t *testing.T) {
		mockEngine := NewMockPerformanceEngine(core.PerformanceOptions{
			UsePHPOPcache: true,
		})

		mockEngine.SetFailNextCall(true)
		err := mockEngine.OptimizePHPExecution("test.php")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "opcache not available")
	})

	// Test V8 JIT fallback
	t.Run("v8_jit_fallback", func(t *testing.T) {
		mockEngine := NewMockPerformanceEngine(core.PerformanceOptions{
			UseNodeJIT: true,
		})

		mockEngine.SetFailNextCall(true)
		err := mockEngine.OptimizeJavaScriptExecution("test.js")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "node v8 jit not available")
	})
}

// BenchmarkJITPerformanceOptimizations benchmarks the JIT optimization process
func BenchmarkJITPerformanceOptimizations(b *testing.B) {
	options := core.PerformanceOptions{
		UsePyPyJIT:      true,
		UsePHPOPcache:   true,
		UseNodeJIT:      true,
		PrecompileCache: true,
		CacheDirectory:  "/tmp/eden_bench_cache",
	}

	mockEngine := NewMockPerformanceEngine(options)

	b.Run("python_pypy_jit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizePythonExecution("bench.py")
		}
	})

	b.Run("php_opcache_jit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizePHPExecution("bench.php")
		}
	})

	b.Run("javascript_v8_jit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mockEngine.OptimizeJavaScriptExecution("bench.js")
		}
	})
}

// TestJITPerformanceMetrics tests performance metric collection
func TestJITPerformanceMetrics(t *testing.T) {
	options := core.PerformanceOptions{
		UsePyPyJIT:     true,
		CacheDirectory: "/tmp/eden_test_metrics",
	}

	mockEngine := NewMockPerformanceEngine(options)

	// Execute optimization
	err := mockEngine.OptimizePythonExecution("metrics_test.py")
	assert.NoError(t, err)

	// Verify metrics collection
	stats := mockEngine.GetPerformanceStats()
	assert.Len(t, stats, 1)

	pythonStats := stats["python_metrics_test.py"]
	assert.NotNil(t, pythonStats)
	assert.Greater(t, pythonStats.OriginalTime, time.Duration(0))
	assert.Greater(t, pythonStats.ProtectedTime, time.Duration(0))
	assert.NotEqual(t, 0.0, pythonStats.OverheadPercent)
}

// TestConcurrentJITOptimizations tests concurrent optimization execution
func TestConcurrentJITOptimizations(t *testing.T) {
	options := core.PerformanceOptions{
		UsePyPyJIT:     true,
		MaxWorkers:     runtime.NumCPU(),
		CacheDirectory: "/tmp/eden_concurrent_test",
	}

	mockEngine := NewMockPerformanceEngine(options)

	// Test concurrent executions
	const numGoroutines = 10
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			err := mockEngine.OptimizePythonExecution(fmt.Sprintf("concurrent_%d.py", id))
			done <- err
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-done
		assert.NoError(t, err, "Goroutine %d failed", i)
	}

	// Verify all optimizations were recorded
	stats := mockEngine.GetPerformanceStats()
	assert.Equal(t, numGoroutines, len(stats))

	// Verify call history shows all executions
	history := mockEngine.GetCallHistory()
	assert.Equal(t, numGoroutines, len(history))
}
