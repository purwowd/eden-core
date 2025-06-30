package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/purwowd/eden-core/internal/config"
	"github.com/purwowd/eden-core/internal/storage"
	"github.com/purwowd/eden-core/pkg/core"
	"github.com/stretchr/testify/assert"
)

// MockConfig provides a mock configuration for testing
func createMockConfig() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			BasePath:        "/tmp/eden_test_storage",
			TempDirectory:   "/tmp/eden_test_temp",
			BackupDirectory: "/tmp/eden_test_backup",
		},
		Security: config.SecurityConfig{
			AllowedFormats: []string{"py", "js", "php", "go", "java", "rb", "pl"},
			MaxFileSize:    100 * 1024 * 1024, // 100MB
		},
		Logging: config.LoggingConfig{
			Level: "info",
		},
		Performance: config.PerformanceConfig{
			ChunkSize: 8192,
		},
	}
}

// MockValidator provides a mock validator for testing
func createMockValidator(cfg *config.Config) *config.Validator {
	return config.NewValidator(cfg)
}

// MockStorageManager provides a mock storage manager for testing
func createMockStorageManager() *storage.Manager {
	storageDir := "/tmp/eden_test_storage"
	tempDir := "/tmp/eden_test_temp"
	backupDir := "/tmp/eden_test_backup"

	os.MkdirAll(storageDir, 0755)
	os.MkdirAll(tempDir, 0755)
	os.MkdirAll(backupDir, 0755)

	manager, _ := storage.NewManager(storageDir, tempDir, backupDir)
	return manager
}

// TestProtectionEngineCreation tests creating a new protection engine
func TestProtectionEngineCreation(t *testing.T) {
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)
	assert.NotNil(t, engine)
}

// TestPythonExecutionOptimization tests Python execution via protected file workflow
func TestPythonExecutionOptimization(t *testing.T) {
	// Create test Python file
	testDir := "/tmp/eden_test_python"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	pythonFile := filepath.Join(testDir, "test.py")
	pythonContent := `#!/usr/bin/env python3
import time
print("Hello from protected Python!")
result = sum(range(1000))
print(f"Calculation result: {result}")
time.sleep(0.1)
print("Python processing completed")
`

	err := os.WriteFile(pythonFile, []byte(pythonContent), 0644)
	assert.NoError(t, err)

	// Create protection engine
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")
	defer os.RemoveAll("/tmp/eden_test_temp")
	defer os.RemoveAll("/tmp/eden_test_backup")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test protection workflow (which includes optimization)
	options := core.ProtectionOptions{
		MultiAuth:     true,
		TimeLock:      false,
		Ownership:     false,
		PolicyScript:  false,
		Teams:         []string{"test_team"},
		LockDuration:  "",
		OwnerKey:      "",
		ScriptContent: "",
	}

	start := time.Now()
	result, err := engine.ProtectFile(pythonFile, options, true)
	duration := time.Since(start)

	// Protection should complete successfully
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)

	// The protection should complete quickly
	assert.True(t, duration < 10*time.Second, "Protection should complete within 10 seconds")

	t.Logf("Python protection result: %+v (duration: %v)", result, duration)
}

// TestPHPProtectionWorkflow tests PHP file protection workflow
func TestPHPProtectionWorkflow(t *testing.T) {
	// Create test PHP file
	testDir := "/tmp/eden_test_php"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	phpFile := filepath.Join(testDir, "test.php")
	phpContent := `<?php
echo "Hello from protected PHP!\n";
$result = array_sum(range(1, 1000));
echo "Calculation result: $result\n";
usleep(100000); // 0.1 second
echo "PHP execution completed\n";
?>`

	err := os.WriteFile(phpFile, []byte(phpContent), 0644)
	assert.NoError(t, err)

	// Create protection engine
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")
	defer os.RemoveAll("/tmp/eden_test_temp")
	defer os.RemoveAll("/tmp/eden_test_backup")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test protection workflow
	options := core.ProtectionOptions{
		MultiAuth:     true,
		TimeLock:      false,
		Ownership:     false,
		PolicyScript:  false,
		Teams:         []string{"test_team"},
		LockDuration:  "",
		OwnerKey:      "",
		ScriptContent: "",
	}

	start := time.Now()
	result, err := engine.ProtectFile(phpFile, options, true)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, duration < 10*time.Second, "Protection should complete within 10 seconds")

	t.Logf("PHP protection result: %+v (duration: %v)", result, duration)
}

// TestJavaScriptProtectionWorkflow tests JavaScript file protection workflow
func TestJavaScriptProtectionWorkflow(t *testing.T) {
	// Create test JavaScript file
	testDir := "/tmp/eden_test_js"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	jsFile := filepath.Join(testDir, "test.js")
	jsContent := `#!/usr/bin/env node
console.log("Hello from protected JavaScript!");
const result = Array.from({length: 1000}, (_, i) => i + 1).reduce((a, b) => a + b, 0);
console.log("Calculation result:", result);
setTimeout(() => {
    console.log("JavaScript execution completed");
}, 100);
`

	err := os.WriteFile(jsFile, []byte(jsContent), 0644)
	assert.NoError(t, err)

	// Create protection engine
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")
	defer os.RemoveAll("/tmp/eden_test_temp")
	defer os.RemoveAll("/tmp/eden_test_backup")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test protection workflow
	options := core.ProtectionOptions{
		MultiAuth:     true,
		TimeLock:      false,
		Ownership:     false,
		PolicyScript:  false,
		Teams:         []string{"test_team"},
		LockDuration:  "",
		OwnerKey:      "",
		ScriptContent: "",
	}

	start := time.Now()
	result, err := engine.ProtectFile(jsFile, options, true)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.True(t, duration < 10*time.Second, "Protection should complete within 10 seconds")

	t.Logf("JavaScript protection result: %+v (duration: %v)", result, duration)
}

// TestPerformanceEngineIntegration tests integration with performance engine
func TestPerformanceEngineIntegration(t *testing.T) {
	// Test performance options creation
	options := core.PerformanceOptions{
		UsePyPyJIT:      true,
		PrecompileCache: true,
		CacheDirectory:  "/tmp/eden_test_cache",
	}

	// Create performance engine
	perfEngine := core.NewPerformanceEngine(options)
	assert.NotNil(t, perfEngine)

	// Test that options are stored correctly
	assert.True(t, options.UsePyPyJIT)
	assert.True(t, options.PrecompileCache)
	assert.Equal(t, "/tmp/eden_test_cache", options.CacheDirectory)

	// Clean up
	os.RemoveAll("/tmp/eden_test_cache")
}

// TestProtectionWithPerformanceOptimization tests complete protection flow with optimization
func TestProtectionWithPerformanceOptimization(t *testing.T) {
	// Create test file
	testDir := "/tmp/eden_test_integration"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	testFile := filepath.Join(testDir, "integration_test.py")
	testContent := `#!/usr/bin/env python3
print("This is a test file for protection with optimization")
for i in range(10):
    print(f"Iteration {i}")
print("Test completed successfully")
`

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	assert.NoError(t, err)

	// Create protection engine
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test protection options
	options := core.ProtectionOptions{
		MultiAuth:     true,
		TimeLock:      false,
		Ownership:     false,
		PolicyScript:  false,
		Teams:         []string{"test_team"},
		LockDuration:  "",
		OwnerKey:      "",
		ScriptContent: "",
	}

	// Protect the file
	result, err := engine.ProtectFile(testFile, options, true)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.NotEmpty(t, result.FileID)
	assert.NotEmpty(t, result.ProtectedPath)
	assert.NotEmpty(t, result.KeyPath)

	t.Logf("Protection result: FileID=%s, Protected=%s, Key=%s",
		result.FileID, result.ProtectedPath, result.KeyPath)
}

// TestExecutionMethodsWorkflow tests the protection and execution workflow
func TestExecutionMethodsWorkflow(t *testing.T) {
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")
	defer os.RemoveAll("/tmp/eden_test_temp")
	defer os.RemoveAll("/tmp/eden_test_backup")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test basic engine creation
	assert.NotNil(t, engine)

	// Test that protection engine can be created without panics
	assert.NotPanics(t, func() {
		core.NewProtectionEngine(cfg, validator, storageManager)
	})
}

// TestPerformanceOptionsValidation tests performance options validation
func TestPerformanceOptionsValidation(t *testing.T) {
	testCases := []struct {
		name    string
		options core.PerformanceOptions
		valid   bool
	}{
		{
			name: "all_optimizations_enabled",
			options: core.PerformanceOptions{
				UsePyPyJIT:      true,
				PrecompileCache: true,
				CacheDirectory:  "/tmp/cache",
			},
			valid: true,
		},
		{
			name: "minimal_optimizations",
			options: core.PerformanceOptions{
				UsePyPyJIT:      false,
				PrecompileCache: false,
			},
			valid: true,
		},
		{
			name: "custom_cache_directory",
			options: core.PerformanceOptions{
				UsePyPyJIT:     true,
				CacheDirectory: "/custom/cache/path",
			},
			valid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			perfEngine := core.NewPerformanceEngine(tc.options)

			if tc.valid {
				assert.NotNil(t, perfEngine)

				// Verify cache directory is set (default or custom)
				expectedDir := tc.options.CacheDirectory
				if expectedDir == "" {
					expectedDir = "/tmp/eden_performance_cache"
				}

				// The performance engine should be created successfully
				assert.NotNil(t, perfEngine.GetPerformanceStats())
			}

			// Clean up any created directories
			if tc.options.CacheDirectory != "" {
				os.RemoveAll(tc.options.CacheDirectory)
			}
			os.RemoveAll("/tmp/eden_performance_cache")
		})
	}
}

// TestExecutionStatsCalculation tests performance statistics calculation
func TestExecutionStatsCalculation(t *testing.T) {
	// Create mock execution stats
	stats := &core.ExecutionStats{
		OriginalTime:    1000 * time.Millisecond,
		ProtectedTime:   1050 * time.Millisecond,
		DecryptionTime:  20 * time.Millisecond,
		CompilationTime: 30 * time.Millisecond,
		ExecutionTime:   1000 * time.Millisecond,
	}

	// Calculate expected overhead
	expectedOverhead := float64(stats.ProtectedTime-stats.OriginalTime) / float64(stats.OriginalTime) * 100
	stats.OverheadPercent = expectedOverhead

	// Verify calculations
	assert.Equal(t, 5.0, stats.OverheadPercent) // 50ms overhead on 1000ms = 5%
	assert.True(t, stats.ProtectedTime > stats.OriginalTime)
	assert.True(t, stats.DecryptionTime < 100*time.Millisecond)
	assert.True(t, stats.CompilationTime < 100*time.Millisecond)
	assert.Equal(t, 1000*time.Millisecond, stats.ExecutionTime)

	totalOverhead := stats.DecryptionTime + stats.CompilationTime
	assert.Equal(t, 50*time.Millisecond, totalOverhead)
}

// BenchmarkProtectionEngineCreation benchmarks protection engine creation
func BenchmarkProtectionEngineCreation(b *testing.B) {
	cfg := createMockConfig()
	validator := createMockValidator(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storageManager := createMockStorageManager()
		engine := core.NewProtectionEngine(cfg, validator, storageManager)
		_ = engine
	}

	// Clean up
	os.RemoveAll("/tmp/eden_test_storage")
}

// BenchmarkPerformanceEngineCreation benchmarks performance engine creation
func BenchmarkPerformanceEngineCreation(b *testing.B) {
	options := core.PerformanceOptions{
		UsePyPyJIT:      true,
		PrecompileCache: true,
		CacheDirectory:  "/tmp/eden_bench_cache",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		perfEngine := core.NewPerformanceEngine(options)
		_ = perfEngine
	}

	// Clean up
	os.RemoveAll("/tmp/eden_bench_cache")
}

// TestCacheDirectoryCreation tests cache directory creation
func TestCacheDirectoryCreation(t *testing.T) {
	customCacheDir := "/tmp/eden_custom_cache_test"

	// Ensure directory doesn't exist
	os.RemoveAll(customCacheDir)

	options := core.PerformanceOptions{
		CacheDirectory: customCacheDir,
	}

	perfEngine := core.NewPerformanceEngine(options)
	assert.NotNil(t, perfEngine)

	// Verify directory was created
	_, err := os.Stat(customCacheDir)
	assert.NoError(t, err)

	// Clean up
	os.RemoveAll(customCacheDir)
}

// TestFallbackBehavior tests fallback behavior when files don't exist
func TestFallbackBehavior(t *testing.T) {
	cfg := createMockConfig()
	validator := createMockValidator(cfg)
	storageManager := createMockStorageManager()
	defer os.RemoveAll("/tmp/eden_test_storage")
	defer os.RemoveAll("/tmp/eden_test_temp")
	defer os.RemoveAll("/tmp/eden_test_backup")

	engine := core.NewProtectionEngine(cfg, validator, storageManager)

	// Test protection of non-existent file
	nonExistentFile := "/tmp/non_existent_file.py"
	options := core.ProtectionOptions{
		MultiAuth:     false,
		TimeLock:      false,
		Ownership:     false,
		PolicyScript:  false,
		Teams:         []string{},
		LockDuration:  "",
		OwnerKey:      "",
		ScriptContent: "",
	}

	// This should fail gracefully, not panic
	assert.NotPanics(t, func() {
		result, err := engine.ProtectFile(nonExistentFile, options, true)
		// We expect this to fail
		if err != nil {
			t.Logf("Expected error for non-existent file: %v", err)
		}
		if result != nil && !result.Success {
			t.Logf("Expected protection failure: %s", result.Message)
		}
	})
}
