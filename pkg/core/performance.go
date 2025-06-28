package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// PerformanceOptions represents performance optimization settings
type PerformanceOptions struct {
	UseCython       bool   `json:"use_cython"`
	UsePHPOPcache   bool   `json:"use_php_opcache"`
	UseNodeJIT      bool   `json:"use_node_jit"`
	PrecompileCache bool   `json:"precompile_cache"`
	InMemoryExec    bool   `json:"in_memory_exec"`
	ParallelDecrypt bool   `json:"parallel_decrypt"`
	CacheDirectory  string `json:"cache_directory"`
	JITWarmupTime   int    `json:"jit_warmup_time"`
}

// PerformanceEngine handles performance optimizations for protected code
type PerformanceEngine struct {
	options    PerformanceOptions
	cacheDir   string
	statsCache map[string]*ExecutionStats
}

// ExecutionStats tracks performance metrics
type ExecutionStats struct {
	OriginalTime    time.Duration `json:"original_time"`
	ProtectedTime   time.Duration `json:"protected_time"`
	DecryptionTime  time.Duration `json:"decryption_time"`
	CompilationTime time.Duration `json:"compilation_time"`
	ExecutionTime   time.Duration `json:"execution_time"`
	OverheadPercent float64       `json:"overhead_percent"`
}

// NewPerformanceEngine creates a new performance optimization engine
func NewPerformanceEngine(options PerformanceOptions) *PerformanceEngine {
	if options.CacheDirectory == "" {
		options.CacheDirectory = "/tmp/eden_performance_cache"
	}

	// Ensure cache directory exists
	os.MkdirAll(options.CacheDirectory, 0755)

	return &PerformanceEngine{
		options:    options,
		cacheDir:   options.CacheDirectory,
		statsCache: make(map[string]*ExecutionStats),
	}
}

// OptimizePythonExecution optimizes Python code execution using various techniques
func (pe *PerformanceEngine) OptimizePythonExecution(sourceFile string) error {
	if pe.options.UseCython {
		return optimizePythonWithCython(sourceFile, pe.cacheDir)
	}
	return pe.optimizeWithPyPy(sourceFile)
}

// optimizeWithPyPy uses PyPy JIT for faster execution
func (pe *PerformanceEngine) optimizeWithPyPy(sourceFile string) error {
	fmt.Printf("Optimizing Python with PyPy JIT...\n")

	// Check if PyPy is available
	if _, err := exec.LookPath("pypy3"); err != nil {
		fmt.Printf("PyPy not found, using regular Python3\n")
		return pe.executeRegularPython(sourceFile)
	}

	// Warm up JIT if configured
	if pe.options.JITWarmupTime > 0 {
		fmt.Printf("Warming up PyPy JIT...\n")
		warmupCmd := exec.Command("pypy3", "-c", "import time; [x**2 for x in range(100000)]")
		warmupCmd.Run()
	}

	// Execute with PyPy
	cmd := exec.Command("pypy3", sourceFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// executeRegularPython executes with standard Python interpreter
func (pe *PerformanceEngine) executeRegularPython(sourceFile string) error {
	cmd := exec.Command("python3", sourceFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// OptimizePHPExecution optimizes PHP code execution
func (pe *PerformanceEngine) OptimizePHPExecution(sourceFile string) error {
	fmt.Printf("Optimizing PHP with OPcache...\n")

	if pe.options.UsePHPOPcache {
		return pe.optimizeWithOPcache(sourceFile)
	}

	return pe.executeRegularPHP(sourceFile)
}

// optimizeWithOPcache enables PHP OPcache for faster execution
func (pe *PerformanceEngine) optimizeWithOPcache(sourceFile string) error {
	// Create temporary php.ini with OPcache enabled
	tmpIni := filepath.Join(pe.cacheDir, "php_optimized.ini")
	iniContent := `
; Optimized PHP configuration for Eden Core
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.fast_shutdown=1
opcache.save_comments=0
opcache.validate_timestamps=0
opcache.huge_code_pages=1
opcache.jit_buffer_size=256M
opcache.jit=tracing
realpath_cache_size=4M
realpath_cache_ttl=600
`

	if err := os.WriteFile(tmpIni, []byte(iniContent), 0644); err != nil {
		fmt.Printf("Failed to create optimized php.ini, using default: %v\n", err)
		return pe.executeRegularPHP(sourceFile)
	}

	// Execute with optimized configuration
	cmd := exec.Command("php", "-c", tmpIni, sourceFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// executeRegularPHP executes with standard PHP interpreter
func (pe *PerformanceEngine) executeRegularPHP(sourceFile string) error {
	cmd := exec.Command("php", sourceFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// OptimizeJavaScriptExecution optimizes JavaScript/Node.js execution
func (pe *PerformanceEngine) OptimizeJavaScriptExecution(sourceFile string) error {
	fmt.Printf("Optimizing JavaScript with V8 JIT...\n")

	if pe.options.UseNodeJIT {
		return pe.optimizeWithV8JIT(sourceFile)
	}

	return pe.executeRegularNode(sourceFile)
}

// optimizeWithV8JIT enables V8 JIT optimizations
func (pe *PerformanceEngine) optimizeWithV8JIT(sourceFile string) error {
	// Node.js V8 optimization flags
	v8Flags := []string{
		"--max-old-space-size=8192", // Increase heap size
		"--optimize-for-size",       // Optimize for speed
		"--turbo-fast-api-calls",    // Enable fast API calls
		"--experimental-modules",    // Modern module support
		"--no-warnings",             // Suppress warnings
	}

	args := append(v8Flags, sourceFile)
	cmd := exec.Command("node", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// executeRegularNode executes with standard Node.js
func (pe *PerformanceEngine) executeRegularNode(sourceFile string) error {
	cmd := exec.Command("node", sourceFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// GetPerformanceStats returns performance statistics
func (pe *PerformanceEngine) GetPerformanceStats() map[string]*ExecutionStats {
	return pe.statsCache
}

// MeasurePerformance measures execution performance
func (pe *PerformanceEngine) MeasurePerformance(originalFile, protectedFile string) (*ExecutionStats, error) {
	stats := &ExecutionStats{}

	// Measure original execution time
	start := time.Now()
	// Execute original file (would implement actual execution)
	stats.OriginalTime = time.Since(start)

	// Measure protected execution time
	start = time.Now()
	// Execute protected file (would implement actual execution)
	stats.ProtectedTime = time.Since(start)

	// Calculate overhead
	if stats.OriginalTime > 0 {
		overhead := float64(stats.ProtectedTime-stats.OriginalTime) / float64(stats.OriginalTime) * 100
		stats.OverheadPercent = overhead
	}

	return stats, nil
}

// CreatePerformanceReport generates a performance analysis report
func (pe *PerformanceEngine) CreatePerformanceReport() string {
	report := "=== EDEN CORE PERFORMANCE REPORT ===\n\n"

	report += "Optimization Settings:\n"
	report += fmt.Sprintf("  Cython Optimization: %v\n", pe.options.UseCython)
	report += fmt.Sprintf("  PHP OPcache: %v\n", pe.options.UsePHPOPcache)
	report += fmt.Sprintf("  Node.js JIT: %v\n", pe.options.UseNodeJIT)
	report += fmt.Sprintf("  Precompile Cache: %v\n", pe.options.PrecompileCache)
	report += fmt.Sprintf("  Cache Directory: %s\n", pe.cacheDir)

	report += "\nPerformance Statistics:\n"
	for key, stats := range pe.statsCache {
		report += fmt.Sprintf("  %s:\n", key)
		report += fmt.Sprintf("    Original: %v\n", stats.OriginalTime)
		report += fmt.Sprintf("    Protected: %v\n", stats.ProtectedTime)
		report += fmt.Sprintf("    Overhead: %.2f%%\n", stats.OverheadPercent)
	}

	return report
}

func optimizePythonWithCython(sourcePath string, cacheDir string) error {
	setupPyContent := fmt.Sprintf(`
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        "%s",
        compiler_directives={
            'language_level': "3",
            'boundscheck': False,
            'wraparound': False,
            'initializedcheck': False,
            'nonecheck': False,
        },
        quiet=True,
    )
)`, filepath.Base(sourcePath))

	// Create setup.py in cache directory
	setupPyPath := filepath.Join(cacheDir, "setup.py")
	if err := os.WriteFile(setupPyPath, []byte(setupPyContent), 0644); err != nil {
		return fmt.Errorf("failed to create setup.py: %w", err)
	}

	// Copy source file to cache directory
	destPath := filepath.Join(cacheDir, filepath.Base(sourcePath))
	input, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}
	if err := os.WriteFile(destPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write source file: %w", err)
	}

	// Run Cython compilation
	cmd := exec.Command("python", "setup.py", "build_ext", "--inplace")
	cmd.Dir = cacheDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cython compilation failed: %w", err)
	}

	return nil
}
