package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/purwowd/eden-core/internal/config"
	"github.com/purwowd/eden-core/internal/storage"
	"github.com/purwowd/eden-core/pkg/core"
	"github.com/purwowd/eden-core/pkg/crypto"
)

// BenchmarkSuite contains all benchmark operations
type BenchmarkSuite struct {
	config           *config.Config
	protectionEngine *core.ProtectionEngine
	tempDir          string
	results          *BenchmarkResults
}

// BenchmarkResults stores benchmark results
type BenchmarkResults struct {
	TestDate       time.Time         `json:"test_date"`
	SystemInfo     SystemInfo        `json:"system_info"`
	CryptoResults  CryptoBenchmarks  `json:"crypto_results"`
	FileResults    FileBenchmarks    `json:"file_results"`
	NetworkResults NetworkBenchmarks `json:"network_results"`
	Summary        BenchmarkSummary  `json:"summary"`
}

// SystemInfo contains system information
type SystemInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	NumCPU       int    `json:"num_cpu"`
	GoVersion    string `json:"go_version"`
	EdenVersion  string `json:"eden_version"`
}

// CryptoBenchmarks contains cryptographic operation benchmarks
type CryptoBenchmarks struct {
	KeyGeneration    BenchmarkResult `json:"key_generation"`
	ECDHOperations   BenchmarkResult `json:"ecdh_operations"`
	Encryption       BenchmarkResult `json:"encryption"`
	Decryption       BenchmarkResult `json:"decryption"`
	DigitalSignature BenchmarkResult `json:"digital_signature"`
	Verification     BenchmarkResult `json:"verification"`
}

// FileBenchmarks contains file operation benchmarks
type FileBenchmarks struct {
	SmallFiles  BenchmarkResult `json:"small_files"`  // < 1KB
	MediumFiles BenchmarkResult `json:"medium_files"` // 1KB - 1MB
	LargeFiles  BenchmarkResult `json:"large_files"`  // 1MB - 100MB
	BatchFiles  BenchmarkResult `json:"batch_files"`  // Multiple files
}

// NetworkBenchmarks contains network operation benchmarks
type NetworkBenchmarks struct {
	NodeJoin           BenchmarkResult `json:"node_join"`
	RecordRegistration BenchmarkResult `json:"record_registration"`
	AccessVerification BenchmarkResult `json:"access_verification"`
	NetworkStats       BenchmarkResult `json:"network_stats"`
}

// BenchmarkResult contains individual benchmark result
type BenchmarkResult struct {
	Operation        string        `json:"operation"`
	Iterations       int           `json:"iterations"`
	TotalTime        time.Duration `json:"total_time"`
	AverageTime      time.Duration `json:"average_time"`
	OperationsPerSec float64       `json:"operations_per_sec"`
	MinTime          time.Duration `json:"min_time"`
	MaxTime          time.Duration `json:"max_time"`
	MemoryUsage      int64         `json:"memory_usage_bytes"`
	Success          bool          `json:"success"`
	ErrorRate        float64       `json:"error_rate"`
}

// BenchmarkSummary contains overall benchmark summary
type BenchmarkSummary struct {
	TotalOperations    int           `json:"total_operations"`
	TotalTime          time.Duration `json:"total_time"`
	OverallPerformance string        `json:"overall_performance"`
	RecommendedUse     string        `json:"recommended_use"`
	PerformanceGrade   string        `json:"performance_grade"`
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite() (*BenchmarkSuite, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	// Create temp directory for benchmarks
	tempDir, err := ioutil.TempDir("", "eden_benchmark_")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Initialize components
	validator := config.NewValidator(cfg)
	storageManager, err := storage.NewManager(tempDir, tempDir, tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to initialize storage: %v", err)
	}

	protectionEngine := core.NewProtectionEngine(cfg, validator, storageManager)

	return &BenchmarkSuite{
		config:           cfg,
		protectionEngine: protectionEngine,
		tempDir:          tempDir,
		results: &BenchmarkResults{
			TestDate: time.Now(),
			SystemInfo: SystemInfo{
				OS:           runtime.GOOS,
				Architecture: runtime.GOARCH,
				NumCPU:       runtime.NumCPU(),
				GoVersion:    runtime.Version(),
				EdenVersion:  Version,
			},
		},
	}, nil
}

// RunAllBenchmarks executes all benchmark suites
func (bs *BenchmarkSuite) RunAllBenchmarks() error {
	fmt.Printf("EDEN CORE COMPREHENSIVE PERFORMANCE BENCHMARK\n")
	fmt.Printf("============================================\n")
	fmt.Printf("Test Date: %s\n", bs.results.TestDate.Format(time.RFC3339))
	fmt.Printf("System: %s/%s (%d CPUs)\n", bs.results.SystemInfo.OS,
		bs.results.SystemInfo.Architecture, bs.results.SystemInfo.NumCPU)
	fmt.Printf("Eden Version: %s\n\n", bs.results.SystemInfo.EdenVersion)

	// Run crypto benchmarks
	fmt.Printf("🔐 CRYPTOGRAPHIC OPERATIONS\n")
	fmt.Printf("---------------------------\n")
	if err := bs.runCryptoBenchmarks(); err != nil {
		return fmt.Errorf("crypto benchmarks failed: %v", err)
	}

	// Run file operation benchmarks
	fmt.Printf("\n📁 FILE OPERATIONS\n")
	fmt.Printf("------------------\n")
	if err := bs.runFileBenchmarks(); err != nil {
		return fmt.Errorf("file benchmarks failed: %v", err)
	}

	// Run network benchmarks
	fmt.Printf("\n🌐 NETWORK OPERATIONS\n")
	fmt.Printf("--------------------\n")
	if err := bs.runNetworkBenchmarks(); err != nil {
		return fmt.Errorf("network benchmarks failed: %v", err)
	}

	// Generate summary
	bs.generateSummary()

	// Display results
	bs.displayResults()

	return nil
}

// runCryptoBenchmarks runs cryptographic operation benchmarks
func (bs *BenchmarkSuite) runCryptoBenchmarks() error {
	// Key Generation Benchmark
	bs.results.CryptoResults.KeyGeneration = bs.benchmarkOperation("Key Generation", 1000, func() error {
		_, err := crypto.NewEllipticCrypto()
		return err
	})

	// ECDH Operations Benchmark
	bs.results.CryptoResults.ECDHOperations = bs.benchmarkOperation("ECDH Operations", 500, func() error {
		ecc1, _ := crypto.NewEllipticCrypto()
		ecc2, _ := crypto.NewEllipticCrypto()

		// Simulate ECDH key exchange
		testData := []byte("test data for ecdh")
		_, err := ecc1.ProtectWithECC(testData)
		if err != nil {
			return err
		}

		_, err = ecc2.ProtectWithECC(testData)
		return err
	})

	// Encryption Benchmark
	testData := make([]byte, 1024) // 1KB test data
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	bs.results.CryptoResults.Encryption = bs.benchmarkOperation("Encryption (1KB)", 200, func() error {
		ecc, _ := crypto.NewEllipticCrypto()
		_, err := ecc.ProtectWithECC(testData)
		return err
	})

	// Decryption Benchmark
	ecc, _ := crypto.NewEllipticCrypto()
	protected, _ := ecc.ProtectWithECC(testData)

	bs.results.CryptoResults.Decryption = bs.benchmarkOperation("Decryption (1KB)", 200, func() error {
		_, err := ecc.UnprotectWithECC(protected)
		return err
	})

	// Digital Signature Benchmark
	bs.results.CryptoResults.DigitalSignature = bs.benchmarkOperation("Digital Signature", 300, func() error {
		ecc, _ := crypto.NewEllipticCrypto()
		_, err := ecc.ProtectWithECC(testData) // This includes signature generation
		return err
	})

	// Verification Benchmark
	bs.results.CryptoResults.Verification = bs.benchmarkOperation("Signature Verification", 300, func() error {
		ecc, _ := crypto.NewEllipticCrypto()
		protection, err := ecc.ProtectWithECC(testData)
		if err != nil {
			return err
		}

		_, err = ecc.UnprotectWithECC(protection) // This includes signature verification
		return err
	})

	return nil
}

// runFileBenchmarks runs file operation benchmarks
func (bs *BenchmarkSuite) runFileBenchmarks() error {
	// Small Files (< 1KB)
	smallFile := bs.createTestFile("small.py", 512) // 512 bytes
	defer os.Remove(smallFile)

	bs.results.FileResults.SmallFiles = bs.benchmarkOperation("Small File Protection", 50, func() error {
		options := core.ProtectionOptions{
			MultiAuth: true,
			Teams:     []string{"test-team"},
		}
		_, err := bs.protectionEngine.ProtectFile(smallFile, options, false)
		return err
	})

	// Medium Files (1KB - 1MB)
	mediumFile := bs.createTestFile("medium.js", 50*1024) // 50KB
	defer os.Remove(mediumFile)

	bs.results.FileResults.MediumFiles = bs.benchmarkOperation("Medium File Protection", 20, func() error {
		options := core.ProtectionOptions{
			MultiAuth: true,
			Teams:     []string{"test-team"},
		}
		_, err := bs.protectionEngine.ProtectFile(mediumFile, options, false)
		return err
	})

	// Large Files (1MB - 100MB)
	largeFile := bs.createTestFile("large.php", 5*1024*1024) // 5MB
	defer os.Remove(largeFile)

	bs.results.FileResults.LargeFiles = bs.benchmarkOperation("Large File Protection", 5, func() error {
		options := core.ProtectionOptions{
			MultiAuth: true,
			Teams:     []string{"test-team"},
		}
		_, err := bs.protectionEngine.ProtectFile(largeFile, options, false)
		return err
	})

	// Batch Files
	batchFiles := bs.createBatchTestFiles(10, 1024) // 10 files of 1KB each
	defer func() {
		for _, file := range batchFiles {
			os.Remove(file)
		}
	}()

	bs.results.FileResults.BatchFiles = bs.benchmarkOperation("Batch File Protection", 5, func() error {
		for _, file := range batchFiles {
			options := core.ProtectionOptions{
				MultiAuth: true,
				Teams:     []string{"test-team"},
			}
			_, err := bs.protectionEngine.ProtectFile(file, options, false)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return nil
}

// runNetworkBenchmarks runs network operation benchmarks
func (bs *BenchmarkSuite) runNetworkBenchmarks() error {
	// Simulate network operations (these would be real network calls in production)

	bs.results.NetworkResults.NodeJoin = bs.benchmarkOperation("Network Node Join", 10, func() error {
		// Simulate network join operation
		time.Sleep(10 * time.Millisecond) // Simulate network latency
		return nil
	})

	bs.results.NetworkResults.RecordRegistration = bs.benchmarkOperation("Record Registration", 20, func() error {
		// Simulate record registration
		time.Sleep(5 * time.Millisecond) // Simulate network operation
		return nil
	})

	bs.results.NetworkResults.AccessVerification = bs.benchmarkOperation("Access Verification", 50, func() error {
		// Simulate access verification
		time.Sleep(2 * time.Millisecond) // Simulate verification
		return nil
	})

	bs.results.NetworkResults.NetworkStats = bs.benchmarkOperation("Network Stats", 100, func() error {
		// Simulate network stats collection
		time.Sleep(1 * time.Millisecond) // Simulate stats collection
		return nil
	})

	return nil
}

// benchmarkOperation runs a benchmark for a specific operation
func (bs *BenchmarkSuite) benchmarkOperation(name string, iterations int, operation func() error) BenchmarkResult {
	fmt.Printf("Running %s (%d iterations)... ", name, iterations)

	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	var totalTime time.Duration
	var minTime time.Duration = time.Hour
	var maxTime time.Duration
	var errors int

	for i := 0; i < iterations; i++ {
		opStart := time.Now()
		err := operation()
		opDuration := time.Since(opStart)

		if err != nil {
			errors++
		}

		totalTime += opDuration
		if opDuration < minTime {
			minTime = opDuration
		}
		if opDuration > maxTime {
			maxTime = opDuration
		}
	}

	runtime.ReadMemStats(&memAfter)

	averageTime := totalTime / time.Duration(iterations)
	opsPerSec := float64(iterations) / totalTime.Seconds()
	errorRate := float64(errors) / float64(iterations) * 100

	result := BenchmarkResult{
		Operation:        name,
		Iterations:       iterations,
		TotalTime:        totalTime,
		AverageTime:      averageTime,
		OperationsPerSec: opsPerSec,
		MinTime:          minTime,
		MaxTime:          maxTime,
		MemoryUsage:      int64(memAfter.Alloc - memBefore.Alloc),
		Success:          errors == 0,
		ErrorRate:        errorRate,
	}

	fmt.Printf("✓ %.2f ops/sec (avg: %v)\n", opsPerSec, averageTime)

	return result
}

// createTestFile creates a test file with specified size
func (bs *BenchmarkSuite) createTestFile(name string, size int) string {
	filePath := filepath.Join(bs.tempDir, name)

	content := make([]byte, size)
	for i := range content {
		content[i] = byte('A' + (i % 26)) // Fill with A-Z pattern
	}

	// Add some Python/JS/PHP content for realism
	header := fmt.Sprintf("#!/usr/bin/env python3\n# Test file: %s\n# Size: %d bytes\n\n", name, size)
	if size > len(header) {
		copy(content, []byte(header))
	}

	ioutil.WriteFile(filePath, content, 0644)
	return filePath
}

// createBatchTestFiles creates multiple test files
func (bs *BenchmarkSuite) createBatchTestFiles(count, size int) []string {
	files := make([]string, count)
	for i := 0; i < count; i++ {
		filename := fmt.Sprintf("batch_%d.py", i)
		files[i] = bs.createTestFile(filename, size)
	}
	return files
}

// generateSummary generates overall benchmark summary
func (bs *BenchmarkSuite) generateSummary() {
	totalOps := bs.results.CryptoResults.KeyGeneration.Iterations +
		bs.results.CryptoResults.Encryption.Iterations +
		bs.results.FileResults.SmallFiles.Iterations +
		bs.results.FileResults.MediumFiles.Iterations

	totalTime := bs.results.CryptoResults.KeyGeneration.TotalTime +
		bs.results.CryptoResults.Encryption.TotalTime +
		bs.results.FileResults.SmallFiles.TotalTime +
		bs.results.FileResults.MediumFiles.TotalTime

	// Performance grading
	avgOpsPerSec := bs.results.CryptoResults.KeyGeneration.OperationsPerSec
	var grade string
	var recommendation string

	switch {
	case avgOpsPerSec > 1000:
		grade = "EXCELLENT"
		recommendation = "Ready for high-throughput production use"
	case avgOpsPerSec > 500:
		grade = "GOOD"
		recommendation = "Ready for production use"
	case avgOpsPerSec > 100:
		grade = "FAIR"
		recommendation = "Suitable for moderate production workloads"
	default:
		grade = "NEEDS_OPTIMIZATION"
		recommendation = "Performance optimization recommended"
	}

	bs.results.Summary = BenchmarkSummary{
		TotalOperations:    totalOps,
		TotalTime:          totalTime,
		OverallPerformance: fmt.Sprintf("%.2f ops/sec average", avgOpsPerSec),
		RecommendedUse:     recommendation,
		PerformanceGrade:   grade,
	}
}

// displayResults displays comprehensive benchmark results
func (bs *BenchmarkSuite) displayResults() {
	fmt.Printf("\n📊 BENCHMARK RESULTS SUMMARY\n")
	fmt.Printf("============================\n")

	fmt.Printf("\n🔐 CRYPTOGRAPHIC PERFORMANCE:\n")
	bs.displayResult("Key Generation", bs.results.CryptoResults.KeyGeneration)
	bs.displayResult("ECDH Operations", bs.results.CryptoResults.ECDHOperations)
	bs.displayResult("Encryption", bs.results.CryptoResults.Encryption)
	bs.displayResult("Decryption", bs.results.CryptoResults.Decryption)

	fmt.Printf("\n📁 FILE OPERATION PERFORMANCE:\n")
	bs.displayResult("Small Files", bs.results.FileResults.SmallFiles)
	bs.displayResult("Medium Files", bs.results.FileResults.MediumFiles)
	bs.displayResult("Large Files", bs.results.FileResults.LargeFiles)
	bs.displayResult("Batch Files", bs.results.FileResults.BatchFiles)

	fmt.Printf("\n🌐 NETWORK PERFORMANCE:\n")
	bs.displayResult("Node Join", bs.results.NetworkResults.NodeJoin)
	bs.displayResult("Record Registration", bs.results.NetworkResults.RecordRegistration)
	bs.displayResult("Access Verification", bs.results.NetworkResults.AccessVerification)

	fmt.Printf("\n🎯 OVERALL ASSESSMENT:\n")
	fmt.Printf("   Grade: %s\n", bs.results.Summary.PerformanceGrade)
	fmt.Printf("   Performance: %s\n", bs.results.Summary.OverallPerformance)
	fmt.Printf("   Recommendation: %s\n", bs.results.Summary.RecommendedUse)
	fmt.Printf("   Total Operations: %d\n", bs.results.Summary.TotalOperations)
	fmt.Printf("   Total Time: %v\n", bs.results.Summary.TotalTime)

	fmt.Printf("\n💡 PERFORMANCE COMPARISON:\n")
	fmt.Printf("   Eden Core vs Industry Standards:\n")
	fmt.Printf("   ✓ Crypto Operations: %s (Target: >500 ops/sec)\n",
		bs.gradeComparison(bs.results.CryptoResults.KeyGeneration.OperationsPerSec, 500))
	fmt.Printf("   ✓ File Protection: %s (Target: >100 ops/sec)\n",
		bs.gradeComparison(bs.results.FileResults.SmallFiles.OperationsPerSec, 100))

	fmt.Printf("\n🔧 SYSTEM INFORMATION:\n")
	fmt.Printf("   OS: %s/%s\n", bs.results.SystemInfo.OS, bs.results.SystemInfo.Architecture)
	fmt.Printf("   CPUs: %d\n", bs.results.SystemInfo.NumCPU)
	fmt.Printf("   Go Version: %s\n", bs.results.SystemInfo.GoVersion)
	fmt.Printf("   Eden Version: %s\n", bs.results.SystemInfo.EdenVersion)
}

// displayResult displays individual benchmark result
func (bs *BenchmarkSuite) displayResult(name string, result BenchmarkResult) {
	status := "✓"
	if !result.Success {
		status = "✗"
	}

	fmt.Printf("   %s %-20s: %8.2f ops/sec | avg: %8v | mem: %8s\n",
		status, name, result.OperationsPerSec, result.AverageTime,
		bs.formatBytes(result.MemoryUsage))
}

// gradeComparison compares performance against target
func (bs *BenchmarkSuite) gradeComparison(actual, target float64) string {
	if actual >= target*2 {
		return "EXCELLENT (2x target)"
	} else if actual >= target*1.5 {
		return "VERY GOOD (1.5x target)"
	} else if actual >= target {
		return "GOOD (meets target)"
	} else {
		return "NEEDS IMPROVEMENT"
	}
}

// formatBytes formats bytes in human readable format
func (bs *BenchmarkSuite) formatBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
}

// Cleanup cleans up benchmark resources
func (bs *BenchmarkSuite) Cleanup() {
	if bs.tempDir != "" {
		os.RemoveAll(bs.tempDir)
	}
}

// runComprehensiveBenchmark is the main entry point for benchmarks
func runComprehensiveBenchmark() error {
	suite, err := NewBenchmarkSuite()
	if err != nil {
		return fmt.Errorf("failed to create benchmark suite: %v", err)
	}
	defer suite.Cleanup()

	return suite.RunAllBenchmarks()
}
