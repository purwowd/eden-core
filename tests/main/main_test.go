package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var edenBinary string

func TestMain(m *testing.M) {
	// Build the binary before running tests
	edenBinary = buildEdenBinary()
	if edenBinary == "" {
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	os.Remove(edenBinary)
	os.Exit(code)
}

func buildEdenBinary() string {
	cmd := exec.Command("go", "build", "-o", "eden-test", "../../cmd/eden")
	err := cmd.Run()
	if err != nil {
		return ""
	}
	return "./eden-test"
}

func TestCLIHelp(t *testing.T) {
	cmd := exec.Command(edenBinary, "-help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Help command failed: %v", err)
	}

	// Should contain usage information
	outputStr := string(output)
	if !strings.Contains(outputStr, "Usage of") {
		t.Error("Help output should contain 'Usage of'")
	}
}

func TestCLISecurityAnalysis(t *testing.T) {
	cmd := exec.Command(edenBinary, "-security")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Security analysis failed: %v", err)
	}

	// Should contain security information
	outputStr := string(output)
	if !strings.Contains(outputStr, "Universal Source Code Protection System") {
		t.Error("Security output should contain security information")
	}
}

// FileIndex represents the actual storage index structure
type FileIndex map[string]FileMetadata

type FileMetadata struct {
	ID            string                 `json:"id"`
	OriginalPath  string                 `json:"original_path"`
	ProtectedPath string                 `json:"protected_path"`
	KeyPath       string                 `json:"key_path"`
	Hash          string                 `json:"hash"`
	Size          int64                  `json:"size"`
	CreatedAt     time.Time              `json:"created_at"`
	ModifiedAt    time.Time              `json:"modified_at"`
	Protection    map[string]interface{} `json:"protection"`
	Metadata      map[string]interface{} `json:"metadata"`
}

func TestCLIProtectionWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	protectedDir := filepath.Join(tempDir, "protected")

	// Create test source file
	sourceFile := filepath.Join(tempDir, "test.py")
	sourceContent := `#!/usr/bin/env python3
print("Hello from Eden protected Python!")
import sys
print(f"Arguments: {sys.argv}")
`
	err := os.WriteFile(sourceFile, []byte(sourceContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test source file: %v", err)
	}

	// Step 1: Protect the file
	protectCmd := exec.Command(edenBinary,
		"-protect",
		"-input", sourceFile,
		"-output", protectedDir,
		"-key", filepath.Join(tempDir, "test.key"))

	protectOutput, err := protectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Protection failed: %v\nOutput: %s", err, protectOutput)
	}

	// Parse output to get file ID
	outputStr := string(protectOutput)
	lines := strings.Split(outputStr, "\n")
	var fileID string
	for _, line := range lines {
		if strings.Contains(line, "File ID:") {
			parts := strings.Split(line, "File ID:")
			if len(parts) > 1 {
				fileID = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	if fileID == "" {
		t.Fatalf("Could not extract file ID from output: %s", outputStr)
	}

	// Verify protected file exists in new structure
	protectedFile := filepath.Join(protectedDir, "files", fileID+".eden")
	if _, err := os.Stat(protectedFile); os.IsNotExist(err) {
		t.Fatalf("Protected file was not created at %s", protectedFile)
	}

	// Verify key file exists in new structure
	keyFile := filepath.Join(protectedDir, "keys", fileID+".key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatalf("Key file was not created at %s", keyFile)
	}

	// Verify index.json exists
	indexFile := filepath.Join(protectedDir, "index.json")
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		t.Fatal("Index file was not created")
	}

	// Verify index.json contains file metadata
	indexData, err := os.ReadFile(indexFile)
	if err != nil {
		t.Fatalf("Failed to read index file: %v", err)
	}

	var index FileIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		t.Fatalf("Index file is not valid JSON: %v", err)
	}

	if _, exists := index[fileID]; !exists {
		t.Errorf("Index file does not contain metadata for file ID: %s", fileID)
	}

	// Step 2: Run the protected file
	runCmd := exec.Command(edenBinary,
		"-run",
		"-input", protectedFile,
		"-key", keyFile)

	runOutput, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Protected file execution failed: %v\nOutput: %s", err, runOutput)
	}

	// Verify execution output
	runOutputStr := string(runOutput)
	expectedOutputs := []string{
		"Hello from Eden protected Python!",
		"Protected file execution completed successfully",
	}

	for _, expected := range expectedOutputs {
		if !strings.Contains(runOutputStr, expected) {
			t.Errorf("Expected output to contain %q\nGot: %s", expected, runOutputStr)
		}
	}
}

func TestCLIRecursiveProtection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	protectedDir := filepath.Join(tempDir, "protected")

	// Create source directory structure
	os.MkdirAll(sourceDir, 0755)

	// Create multiple test files
	testFiles := map[string]string{
		"app.py":    `print("Python app")`,
		"script.js": `console.log("JavaScript app");`,
		"app.php":   `<?php echo "PHP app"; ?>`,
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(sourceDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Protect recursively
	protectCmd := exec.Command(edenBinary,
		"-protect",
		"-recursive",
		"-input", sourceDir,
		"-output", protectedDir,
		"-key", filepath.Join(tempDir, "recursive.key"))

	protectOutput, err := protectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Recursive protection failed: %v\nOutput: %s", err, protectOutput)
	}

	// Verify index.json was created
	indexFile := filepath.Join(protectedDir, "index.json")
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		t.Fatal("Index file was not created")
	}

	// Read index to verify all files were protected
	indexData, err := os.ReadFile(indexFile)
	if err != nil {
		t.Fatalf("Failed to read index file: %v", err)
	}

	var index FileIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		t.Fatalf("Index file is not valid JSON: %v", err)
	}

	// Verify all source files are in the index
	if len(index) != len(testFiles) {
		t.Errorf("Expected %d files in index, got %d", len(testFiles), len(index))
	}

	// Verify all protected files exist
	for fileID := range index {
		protectedFile := filepath.Join(protectedDir, "files", fileID+".eden")
		if _, err := os.Stat(protectedFile); os.IsNotExist(err) {
			t.Errorf("Protected file %s was not created", protectedFile)
		}

		keyFile := filepath.Join(protectedDir, "keys", fileID+".key")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			t.Errorf("Key file %s was not created", keyFile)
		}
	}

	// Verify protection count in output
	outputStr := string(protectOutput)
	if !strings.Contains(outputStr, "Protected files: 3") {
		t.Error("Should report protecting 3 files")
	}
}

func TestCLIInvalidInput(t *testing.T) {
	testCases := []struct {
		name       string
		args       []string
		shouldFail bool
	}{
		{
			name:       "No input file",
			args:       []string{"-protect"},
			shouldFail: true,
		},
		{
			name:       "Non-existent input file",
			args:       []string{"-protect", "-input", "/nonexistent/file.py"},
			shouldFail: true,
		},
		{
			name:       "No action specified",
			args:       []string{"-input", "test.py"},
			shouldFail: true,
		},
		{
			name:       "Run without key",
			args:       []string{"-run", "-input", "test.py.eden"},
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(edenBinary, tc.args...)
			_, err := cmd.CombinedOutput()

			if tc.shouldFail && err == nil {
				t.Error("Command should have failed but didn't")
			}
			if !tc.shouldFail && err != nil {
				t.Errorf("Command should have succeeded but failed: %v", err)
			}
		})
	}
}

func TestCLILanguageSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	protectedDir := filepath.Join(tempDir, "protected")

	// Test different language files
	testFiles := map[string]string{
		"test.py":   `print("Python test")`,
		"test.js":   `console.log("JavaScript test");`,
		"test.php":  `<?php echo "PHP test"; ?>`,
		"test.go":   `package main; func main() { println("Go test") }`,
		"test.rb":   `puts "Ruby test"`,
		"test.java": `public class Test { public static void main(String[] args) { System.out.println("Java test"); } }`,
		"test.pl":   `print "Perl test\\n";`,
	}

	for filename, content := range testFiles {
		// Create source file
		sourceFile := filepath.Join(tempDir, filename)
		err := os.WriteFile(sourceFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}

		// Protect file
		keyFile := filepath.Join(tempDir, filename+".key")
		protectCmd := exec.Command(edenBinary,
			"-protect",
			"-input", sourceFile,
			"-output", protectedDir,
			"-key", keyFile)

		protectOutput, err := protectCmd.CombinedOutput()
		if err != nil {
			t.Errorf("Protection failed for %s: %v\nOutput: %s", filename, err, protectOutput)
			continue
		}

		// Parse file ID from output
		outputStr := string(protectOutput)
		lines := strings.Split(outputStr, "\n")
		var fileID string
		for _, line := range lines {
			if strings.Contains(line, "File ID:") {
				parts := strings.Split(line, "File ID:")
				if len(parts) > 1 {
					fileID = strings.TrimSpace(parts[1])
					break
				}
			}
		}

		if fileID == "" {
			t.Errorf("Could not extract file ID for %s", filename)
			continue
		}

		// Verify protected file was created
		protectedFile := filepath.Join(protectedDir, "files", fileID+".eden")
		if _, err := os.Stat(protectedFile); os.IsNotExist(err) {
			t.Errorf("Protected file was not created for %s at %s", filename, protectedFile)
		}
	}
}

func TestCLIDeprotection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	protectedDir := filepath.Join(tempDir, "protected")
	deprotectedDir := filepath.Join(tempDir, "deprotected")

	// Create and protect a test file first
	sourceFile := filepath.Join(tempDir, "original.py")
	sourceContent := `print("Original content")`
	err := os.WriteFile(sourceFile, []byte(sourceContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Protect the file
	protectCmd := exec.Command(edenBinary,
		"-protect",
		"-input", sourceFile,
		"-output", protectedDir,
		"-key", filepath.Join(tempDir, "test.key"))

	protectOutput, err := protectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Protection failed: %v\nOutput: %s", err, protectOutput)
	}

	// Parse file ID from protection output
	outputStr := string(protectOutput)
	lines := strings.Split(outputStr, "\n")
	var fileID string
	for _, line := range lines {
		if strings.Contains(line, "File ID:") {
			parts := strings.Split(line, "File ID:")
			if len(parts) > 1 {
				fileID = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	if fileID == "" {
		t.Fatalf("Could not extract file ID from protection output")
	}

	// Now deprotect using the new format
	protectedFile := filepath.Join(protectedDir, "files", fileID+".eden")
	keyFile := filepath.Join(protectedDir, "keys", fileID+".key")

	// Create deprotected directory
	err = os.MkdirAll(deprotectedDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create deprotected directory: %v", err)
	}

	deprotectCmd := exec.Command(edenBinary,
		"-deprotect",
		"-input", protectedFile,
		"-key", keyFile,
		"-output", deprotectedDir)

	deprotectOutput, err := deprotectCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Deprotection failed: %v\nOutput: %s", err, deprotectOutput)
	}

	// Verify deprotected file exists (it should be named after the file ID)
	deprotectedFile := filepath.Join(deprotectedDir, fileID+"_deprotected")
	deprotectedContent, err := os.ReadFile(deprotectedFile)
	if err != nil {
		t.Fatalf("Failed to read deprotected file: %v", err)
	}

	// Verify content matches original
	if string(deprotectedContent) != sourceContent {
		t.Errorf("Deprotected content doesn't match original.\nExpected: %s\nGot: %s",
			sourceContent, string(deprotectedContent))
	}
}

func BenchmarkCLIProtection(b *testing.B) {
	tempDir := b.TempDir()
	sourceFile := filepath.Join(tempDir, "bench.py")
	protectedDir := filepath.Join(tempDir, "protected")

	// Create test file
	content := `print("Benchmark test")`
	os.WriteFile(sourceFile, []byte(content), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyFile := filepath.Join(tempDir, "bench.key")
		cmd := exec.Command(edenBinary,
			"-protect",
			"-input", sourceFile,
			"-output", protectedDir,
			"-key", keyFile)
		cmd.Run()
	}
}
