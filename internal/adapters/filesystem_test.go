package adapters

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSystemOperations(t *testing.T) {
	// Create temp directory for tests
	tempDir := t.TempDir()
	fs := NewFileSystem()

	t.Run("WriteAndRead", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "test.txt")
		testContent := []byte("test content")

		// Test Write
		err := fs.WriteFile(testFile, testContent, 0644)
		if err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		// Test Read
		content, err := fs.ReadFile(testFile)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}

		if string(content) != string(testContent) {
			t.Errorf("Content mismatch. Got %s, want %s", string(content), string(testContent))
		}
	})

	t.Run("FileExists", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "exists.txt")

		// Test non-existent file
		if fs.Exists(testFile) {
			t.Error("File should not exist")
		}

		// Create file
		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Test existing file
		if !fs.Exists(testFile) {
			t.Error("File should exist")
		}
	})

	t.Run("CreateDirectory", func(t *testing.T) {
		testDir := filepath.Join(tempDir, "newdir")

		err := fs.CreateDirectory(testDir)
		if err != nil {
			t.Fatalf("CreateDirectory failed: %v", err)
		}

		if !fs.Exists(testDir) {
			t.Error("Directory should exist")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "to_remove.txt")

		// Create file
		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Test Remove
		err = fs.Remove(testFile)
		if err != nil {
			t.Fatalf("Remove failed: %v", err)
		}

		if fs.Exists(testFile) {
			t.Error("File should not exist after removal")
		}
	})
}
