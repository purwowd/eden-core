package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageManager(t *testing.T) {
	// Create temp directories for tests
	tempDir := t.TempDir()
	storageDir := filepath.Join(tempDir, "storage")
	tempStorageDir := filepath.Join(tempDir, "temp")
	backupDir := filepath.Join(tempDir, "backup")

	// Create storage manager
	manager, err := NewManager(storageDir, tempStorageDir, backupDir)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}

	// Clean up any existing files
	if err := os.RemoveAll(storageDir); err != nil {
		t.Fatalf("Failed to clean up storage directory: %v", err)
	}
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		t.Fatalf("Failed to recreate storage directory: %v", err)
	}

	t.Run("StoreAndRetrieve", func(t *testing.T) {
		fileID := "test123"
		content := []byte("test content")

		// Test Store
		err := manager.Store(fileID, content)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		// Test Retrieve
		retrieved, err := manager.Retrieve(fileID)
		if err != nil {
			t.Fatalf("Retrieve failed: %v", err)
		}

		if !bytes.Equal(content, retrieved) {
			t.Error("Retrieved content does not match stored content")
		}

		// Clean up
		err = manager.Delete(fileID)
		if err != nil {
			t.Fatalf("Failed to clean up test file: %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		// Store test files
		files := map[string][]byte{
			"file1": []byte("content1"),
			"file2": []byte("content2"),
		}

		for id, content := range files {
			err := manager.Store(id, content)
			if err != nil {
				t.Fatalf("Failed to store file %s: %v", id, err)
			}
		}

		// Test List
		fileList, err := manager.List()
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(fileList) != len(files) {
			t.Errorf("Expected %d files, got %d", len(files), len(fileList))
		}

		for _, id := range fileList {
			if _, exists := files[id]; !exists {
				t.Errorf("Unexpected file in list: %s", id)
			}
		}

		// Clean up
		for id := range files {
			err = manager.Delete(id)
			if err != nil {
				t.Fatalf("Failed to clean up test file %s: %v", id, err)
			}
		}
	})

	t.Run("Delete", func(t *testing.T) {
		fileID := "test_delete"
		content := []byte("delete me")

		// Store file
		err := manager.Store(fileID, content)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		// Delete file
		err = manager.Delete(fileID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Try to retrieve deleted file
		_, err = manager.Retrieve(fileID)
		if err == nil {
			t.Error("Expected error when retrieving deleted file")
		}
	})

	t.Run("Backup", func(t *testing.T) {
		fileID := "test_backup"
		content := []byte("backup me")

		// Store file
		err := manager.Store(fileID, content)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		// Create backup
		err = manager.Backup(fileID)
		if err != nil {
			t.Fatalf("Backup failed: %v", err)
		}

		// Verify backup file exists
		backupPath := filepath.Join(backupDir, fileID)
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			t.Error("Backup file should exist")
		}

		// Clean up
		err = manager.Delete(fileID)
		if err != nil {
			t.Fatalf("Failed to clean up test file: %v", err)
		}
		err = os.Remove(backupPath)
		if err != nil {
			t.Fatalf("Failed to clean up backup file: %v", err)
		}
	})

	t.Run("Restore", func(t *testing.T) {
		fileID := "test_restore"
		content := []byte("restore me")

		// Store and backup file
		err := manager.Store(fileID, content)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}
		err = manager.Backup(fileID)
		if err != nil {
			t.Fatalf("Backup failed: %v", err)
		}

		// Delete original file
		err = manager.Delete(fileID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Restore from backup
		err = manager.Restore(fileID)
		if err != nil {
			t.Fatalf("Restore failed: %v", err)
		}

		// Verify restored content
		restored, err := manager.Retrieve(fileID)
		if err != nil {
			t.Fatalf("Failed to retrieve restored file: %v", err)
		}
		if !bytes.Equal(content, restored) {
			t.Error("Restored content does not match original")
		}

		// Clean up
		err = manager.Delete(fileID)
		if err != nil {
			t.Fatalf("Failed to clean up test file: %v", err)
		}
		backupPath := filepath.Join(backupDir, fileID)
		err = os.Remove(backupPath)
		if err != nil {
			t.Fatalf("Failed to clean up backup file: %v", err)
		}
	})
}
