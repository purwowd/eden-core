package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	MaxWorkers      int    `json:"max_workers"`
	MaxMemoryMB     int    `json:"max_memory_mb"`
	CleanupInterval int    `json:"cleanup_interval"`
}

// PerformanceEngine handles performance optimizations for protected code
type PerformanceEngine struct {
	options    PerformanceOptions
	cacheDir   string
	statsCache map[string]*ExecutionStats
	memManager *MemoryManager
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

// MemoryManager handles memory optimization
type MemoryManager struct {
	maxMemoryMB     int
	cleanupInterval int
	lastCleanup     time.Time
	mu              sync.RWMutex
	allocatedFiles  map[string]time.Time
}

// DefaultPerformanceOptions returns optimized default settings
func DefaultPerformanceOptions() PerformanceOptions {
	return PerformanceOptions{
		UseCython:       true,
		PrecompileCache: true,
		InMemoryExec:    true,
		ParallelDecrypt: true,
		MaxWorkers:      runtime.NumCPU(),
		MaxMemoryMB:     4096, // 4GB default
		CleanupInterval: 30,   // 30 minutes
		JITWarmupTime:   1000, // 1 second warmup
		CacheDirectory:  "/tmp/eden_performance_cache",
	}
}

// NewPerformanceEngine creates a new performance optimization engine
func NewPerformanceEngine(options PerformanceOptions) *PerformanceEngine {
	// Use default options if not specified
	if options.MaxWorkers <= 0 {
		defaultOpts := DefaultPerformanceOptions()
		options.MaxWorkers = defaultOpts.MaxWorkers
	}
	if options.MaxMemoryMB <= 0 {
		defaultOpts := DefaultPerformanceOptions()
		options.MaxMemoryMB = defaultOpts.MaxMemoryMB
	}
	if options.CleanupInterval <= 0 {
		defaultOpts := DefaultPerformanceOptions()
		options.CleanupInterval = defaultOpts.CleanupInterval
	}
	if options.CacheDirectory == "" {
		defaultOpts := DefaultPerformanceOptions()
		options.CacheDirectory = defaultOpts.CacheDirectory
	}

	// Ensure cache directory exists
	os.MkdirAll(options.CacheDirectory, 0755)

	return &PerformanceEngine{
		options:    options,
		cacheDir:   options.CacheDirectory,
		statsCache: make(map[string]*ExecutionStats),
		memManager: NewMemoryManager(options.MaxMemoryMB, options.CleanupInterval),
	}
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager(maxMemoryMB, cleanupInterval int) *MemoryManager {
	return &MemoryManager{
		maxMemoryMB:     maxMemoryMB,
		cleanupInterval: cleanupInterval,
		lastCleanup:     time.Now(),
		allocatedFiles:  make(map[string]time.Time),
	}
}

// OptimizePythonExecution optimizes Python code execution using various techniques
func (pe *PerformanceEngine) OptimizePythonExecution(sourceFile string) error {
	// Initialize memory manager if needed
	if pe.memManager == nil {
		pe.memManager = NewMemoryManager(
			pe.options.MaxMemoryMB,
			pe.options.CleanupInterval,
		)
	}

	// Check and cleanup memory if needed
	if err := pe.memManager.CheckMemory(); err != nil {
		return fmt.Errorf("memory check failed: %w", err)
	}

	// Track file allocation
	pe.memManager.TrackFile(sourceFile)

	// Check cache first
	cacheKey := fmt.Sprintf("python_%s", filepath.Base(sourceFile))
	if pe.options.PrecompileCache {
		if cached := pe.loadFromCache(cacheKey); cached != nil {
			return pe.executeFromCache(cached)
		}
	}

	var err error
	if pe.options.UseCython {
		err = pe.optimizeWithCython(sourceFile)
		if err == nil {
			// Cache successful compilation
			if pe.options.PrecompileCache {
				pe.saveToCache(cacheKey, sourceFile)
			}
			return nil
		}
		// Log Cython failure but continue to PyPy
		fmt.Printf("Cython optimization failed: %v, falling back to PyPy\n", err)
	}

	return pe.optimizeWithPyPy(sourceFile)
}

// loadFromCache attempts to load cached optimization
func (pe *PerformanceEngine) loadFromCache(cacheKey string) *CachedOptimization {
	cachePath := filepath.Join(pe.cacheDir, cacheKey+".cache")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil
	}

	var cached CachedOptimization
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil
	}

	// Verify cache is still valid
	if time.Since(cached.CreatedAt) > 24*time.Hour {
		return nil
	}

	return &cached
}

// saveToCache saves successful optimization to cache
func (pe *PerformanceEngine) saveToCache(cacheKey, sourceFile string) {
	cached := CachedOptimization{
		SourceFile: sourceFile,
		CreatedAt:  time.Now(),
		Options:    pe.options,
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return
	}

	cachePath := filepath.Join(pe.cacheDir, cacheKey+".cache")
	os.WriteFile(cachePath, data, 0644)
}

// CachedOptimization represents cached optimization data
type CachedOptimization struct {
	SourceFile string             `json:"source_file"`
	CreatedAt  time.Time          `json:"created_at"`
	Options    PerformanceOptions `json:"options"`
}

// executeFromCache executes optimized code from cache
func (pe *PerformanceEngine) executeFromCache(cached *CachedOptimization) error {
	fmt.Printf("Using cached optimization for %s\n", cached.SourceFile)

	// Execute with appropriate runtime
	if cached.Options.UseCython {
		return pe.executeCythonizedCode(cached.SourceFile)
	}
	return pe.optimizeWithPyPy(cached.SourceFile)
}

// optimizeWithCython optimizes Python code using Cython
func (pe *PerformanceEngine) optimizeWithCython(sourceFile string) error {
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
)`, filepath.Base(sourceFile))

	// Create setup.py in cache directory
	setupPyPath := filepath.Join(pe.cacheDir, "setup.py")
	if err := os.WriteFile(setupPyPath, []byte(setupPyContent), 0644); err != nil {
		return fmt.Errorf("failed to create setup.py: %w", err)
	}

	// Copy source file to cache directory
	destPath := filepath.Join(pe.cacheDir, filepath.Base(sourceFile))
	input, err := os.ReadFile(sourceFile)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}
	if err := os.WriteFile(destPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write source file: %w", err)
	}

	// Run Cython compilation
	cmd := exec.Command("python", "setup.py", "build_ext", "--inplace")
	cmd.Dir = pe.cacheDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cython compilation failed: %w", err)
	}

	return nil
}

// executeCythonizedCode executes Cython-compiled code
func (pe *PerformanceEngine) executeCythonizedCode(sourceFile string) error {
	compiledPath := filepath.Join(pe.cacheDir, filepath.Base(sourceFile)+".so")

	// Verify compiled file exists
	if _, err := os.Stat(compiledPath); err != nil {
		return fmt.Errorf("compiled file not found: %w", err)
	}

	// Import and execute compiled module
	cmd := exec.Command("python3", "-c", fmt.Sprintf(`
import sys
sys.path.append("%s")
import %s
`, pe.cacheDir, strings.TrimSuffix(filepath.Base(sourceFile), ".py")))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
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

// OptimizePythonBatch optimizes multiple Python files in parallel
func (pe *PerformanceEngine) OptimizePythonBatch(sourceFiles []string) error {
	if pe.options.MaxWorkers <= 0 {
		pe.options.MaxWorkers = runtime.NumCPU()
	}

	// Create worker pool
	workerCount := min(pe.options.MaxWorkers, len(sourceFiles))
	jobs := make(chan string, len(sourceFiles))
	results := make(chan error, len(sourceFiles))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sourceFile := range jobs {
				results <- pe.OptimizePythonExecution(sourceFile)
			}
		}()
	}

	// Send jobs
	for _, file := range sourceFiles {
		jobs <- file
	}
	close(jobs)

	// Wait for all workers
	wg.Wait()
	close(results)

	// Check results
	var errors []error
	for err := range results {
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("batch optimization failed with %d errors: %v", len(errors), errors)
	}

	return nil
}

// CheckMemory checks and manages memory usage
func (mm *MemoryManager) CheckMemory() error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Check if cleanup is needed
	if time.Since(mm.lastCleanup).Minutes() < float64(mm.cleanupInterval) {
		return nil
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Convert to MB
	usedMemoryMB := int(m.Alloc / 1024 / 1024)

	if usedMemoryMB > mm.maxMemoryMB {
		// Trigger cleanup
		runtime.GC()
		mm.cleanupOldFiles()
	}

	mm.lastCleanup = time.Now()
	return nil
}

// TrackFile tracks file allocation
func (mm *MemoryManager) TrackFile(file string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.allocatedFiles[file] = time.Now()
}

// cleanupOldFiles removes old cached files
func (mm *MemoryManager) cleanupOldFiles() {
	threshold := time.Now().Add(-time.Hour) // Keep files younger than 1 hour

	for file, timestamp := range mm.allocatedFiles {
		if timestamp.Before(threshold) {
			os.Remove(file)
			delete(mm.allocatedFiles, file)
		}
	}
}
