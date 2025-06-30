package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProtectedFile represents a protected file with metadata
type ProtectedFile struct {
	ID            string            `json:"id"`
	OriginalPath  string            `json:"original_path"`
	ProtectedPath string            `json:"protected_path"`
	KeyPath       string            `json:"key_path"`
	Hash          string            `json:"hash"`
	Size          int64             `json:"size"`
	CreatedAt     time.Time         `json:"created_at"`
	ModifiedAt    time.Time         `json:"modified_at"`
	Protection    ProtectionConfig  `json:"protection"`
	Metadata      map[string]string `json:"metadata"`
}

// ProtectionConfig holds protection settings
type ProtectionConfig struct {
	MultiAuth    bool     `json:"multi_auth"`
	TimeLock     bool     `json:"time_lock"`
	Ownership    bool     `json:"ownership"`
	PolicyScript bool     `json:"policy_script"`
	Teams        []string `json:"teams"`
	LockDuration string   `json:"lock_duration"`
}

// Manager handles file storage operations
type Manager struct {
	storageDir string
	tempDir    string
	backupDir  string
	index      map[string]*ProtectedFile
	indexFile  string
	mutex      sync.RWMutex
}

// NewManager creates a new storage manager
func NewManager(storageDir, tempDir, backupDir string) (*Manager, error) {
	// Create directories if they don't exist
	for _, dir := range []string{storageDir, tempDir, backupDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	manager := &Manager{
		storageDir: storageDir,
		tempDir:    tempDir,
		backupDir:  backupDir,
		index:      make(map[string]*ProtectedFile),
		indexFile:  filepath.Join(storageDir, "index.json"),
	}

	// Load existing index
	if err := manager.loadIndex(); err != nil {
		return nil, fmt.Errorf("failed to load index: %v", err)
	}

	return manager, nil
}

// Store stores data with the given ID
func (m *Manager) Store(id string, data []byte) error {
	filePath := filepath.Join(m.storageDir, id)
	return os.WriteFile(filePath, data, 0644)
}

// Retrieve retrieves data with the given ID
func (m *Manager) Retrieve(id string) ([]byte, error) {
	filePath := filepath.Join(m.storageDir, id)
	return os.ReadFile(filePath)
}

// List returns a list of all stored file IDs
func (m *Manager) List() ([]string, error) {
	files, err := os.ReadDir(m.storageDir)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, file := range files {
		if !file.IsDir() {
			ids = append(ids, file.Name())
		}
	}

	return ids, nil
}

// Delete removes a file with the given ID
func (m *Manager) Delete(id string) error {
	filePath := filepath.Join(m.storageDir, id)
	return os.Remove(filePath)
}

// Backup creates a backup of a file
func (m *Manager) Backup(id string) error {
	srcPath := filepath.Join(m.storageDir, id)
	dstPath := filepath.Join(m.backupDir, id)

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	return os.WriteFile(dstPath, data, 0644)
}

// Restore restores a file from backup
func (m *Manager) Restore(id string) error {
	srcPath := filepath.Join(m.backupDir, id)
	dstPath := filepath.Join(m.storageDir, id)

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	return os.WriteFile(dstPath, data, 0644)
}

// StoreFile stores a protected file with metadata
func (m *Manager) StoreFile(originalPath string, protectedData []byte, keyData []byte, config ProtectionConfig) (*ProtectedFile, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Generate unique ID
	id := generateID()

	// Calculate hash
	hash := sha256.Sum256(protectedData)
	hashStr := hex.EncodeToString(hash[:])

	// Create protected file record
	pf := &ProtectedFile{
		ID:           id,
		OriginalPath: originalPath,
		Hash:         hashStr,
		Size:         int64(len(protectedData)),
		CreatedAt:    time.Now(),
		ModifiedAt:   time.Now(),
		Protection:   config,
		Metadata:     make(map[string]string),
	}

	// Generate file paths
	pf.ProtectedPath = filepath.Join(m.storageDir, id+".eden")
	pf.KeyPath = filepath.Join(m.storageDir, id+".key")

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(pf.ProtectedPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create files directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(pf.KeyPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %v", err)
	}

	// Write protected file
	if err := os.WriteFile(pf.ProtectedPath, protectedData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write protected file: %v", err)
	}

	// Write key file
	if err := os.WriteFile(pf.KeyPath, keyData, 0600); err != nil {
		// Cleanup protected file on key write failure
		os.Remove(pf.ProtectedPath)
		return nil, fmt.Errorf("failed to write key file: %v", err)
	}

	// Add to index
	m.index[id] = pf

	// Save index
	if err := m.saveIndex(); err != nil {
		return nil, fmt.Errorf("failed to save index: %v", err)
	}

	return pf, nil
}

// GetFile retrieves a protected file by ID
func (m *Manager) GetFile(id string) (*ProtectedFile, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Try exact ID first
	pf, exists := m.index[id]
	if exists {
		return pf, nil
	}

	// Try with and without .eden extension
	var tryIDs []string
	if strings.HasSuffix(id, ".eden") {
		tryIDs = append(tryIDs, strings.TrimSuffix(id, ".eden"))
	} else {
		tryIDs = append(tryIDs, id+".eden")
	}

	for _, tryID := range tryIDs {
		if pf, exists := m.index[tryID]; exists {
			return pf, nil
		}
	}

	return nil, fmt.Errorf("file not found: %s", id)
}

// LoadProtectedData loads the protected file data
func (m *Manager) LoadProtectedData(id string) ([]byte, error) {
	pf, err := m.GetFile(id)
	if err != nil {
		// Try adding .eden extension if not found
		if !strings.HasSuffix(id, ".eden") {
			pf, err = m.GetFile(id + ".eden")
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	data, err := os.ReadFile(pf.ProtectedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read protected file: %v", err)
	}

	return data, nil
}

// LoadKeyData loads the key file data
func (m *Manager) LoadKeyData(id string) ([]byte, error) {
	pf, err := m.GetFile(id)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(pf.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	return data, nil
}

// ListFiles returns all protected files
func (m *Manager) ListFiles() []*ProtectedFile {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	files := make([]*ProtectedFile, 0, len(m.index))
	for _, pf := range m.index {
		files = append(files, pf)
	}

	return files
}

// DeleteFile removes a protected file and its key
func (m *Manager) DeleteFile(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pf, exists := m.index[id]
	if !exists {
		return fmt.Errorf("file not found: %s", id)
	}

	// Create backup before deletion
	if err := m.createBackup(pf); err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}

	// Remove files
	if err := os.Remove(pf.ProtectedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove protected file: %v", err)
	}

	if err := os.Remove(pf.KeyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove key file: %v", err)
	}

	// Remove from index
	delete(m.index, id)

	// Save index
	if err := m.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %v", err)
	}

	return nil
}

// UpdateMetadata updates file metadata
func (m *Manager) UpdateMetadata(id string, metadata map[string]string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pf, exists := m.index[id]
	if !exists {
		return fmt.Errorf("file not found: %s", id)
	}

	// Update metadata
	for k, v := range metadata {
		pf.Metadata[k] = v
	}
	pf.ModifiedAt = time.Now()

	// Save index
	if err := m.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %v", err)
	}

	return nil
}

// SearchFiles searches for files by criteria
func (m *Manager) SearchFiles(query string) []*ProtectedFile {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var results []*ProtectedFile
	query = strings.ToLower(query)

	for _, pf := range m.index {
		// Search in original path, metadata, and protection settings
		if strings.Contains(strings.ToLower(pf.OriginalPath), query) ||
			m.searchInMetadata(pf.Metadata, query) ||
			m.searchInProtection(pf.Protection, query) {
			results = append(results, pf)
		}
	}

	return results
}

// GetStats returns storage statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_files": len(m.index),
		"total_size":  int64(0),
		"protection_stats": map[string]int{
			"multi_auth":    0,
			"time_lock":     0,
			"ownership":     0,
			"policy_script": 0,
		},
	}

	for _, pf := range m.index {
		stats["total_size"] = stats["total_size"].(int64) + pf.Size

		protStats := stats["protection_stats"].(map[string]int)
		if pf.Protection.MultiAuth {
			protStats["multi_auth"]++
		}
		if pf.Protection.TimeLock {
			protStats["time_lock"]++
		}
		if pf.Protection.Ownership {
			protStats["ownership"]++
		}
		if pf.Protection.PolicyScript {
			protStats["policy_script"]++
		}
	}

	return stats
}

// CleanupTemp removes old temporary files
func (m *Manager) CleanupTemp(maxAge time.Duration) error {
	return filepath.Walk(m.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && time.Since(info.ModTime()) > maxAge {
			return os.Remove(path)
		}

		return nil
	})
}

// CreateBackup creates a backup of all protected files
func (m *Manager) CreateBackup() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(m.backupDir, timestamp)

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %v", err)
	}

	// Copy index file
	indexData, err := json.MarshalIndent(m.index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %v", err)
	}

	if err := os.WriteFile(filepath.Join(backupDir, "index.json"), indexData, 0644); err != nil {
		return fmt.Errorf("failed to write backup index: %v", err)
	}

	// Copy all files
	for _, pf := range m.index {
		if err := m.copyFile(pf.ProtectedPath, filepath.Join(backupDir, "files", filepath.Base(pf.ProtectedPath))); err != nil {
			return fmt.Errorf("failed to backup protected file: %v", err)
		}

		if err := m.copyFile(pf.KeyPath, filepath.Join(backupDir, "keys", filepath.Base(pf.KeyPath))); err != nil {
			return fmt.Errorf("failed to backup key file: %v", err)
		}
	}

	return nil
}

// Internal helper methods

func (m *Manager) loadIndex() error {
	if _, err := os.Stat(m.indexFile); os.IsNotExist(err) {
		// Index file doesn't exist, start with empty index
		return nil
	}

	data, err := os.ReadFile(m.indexFile)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &m.index)
}

func (m *Manager) saveIndex() error {
	data, err := json.MarshalIndent(m.index, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.indexFile, data, 0644)
}

func (m *Manager) createBackup(pf *ProtectedFile) error {
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(m.backupDir, "deleted", timestamp)

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return err
	}

	// Backup protected file
	if err := m.copyFile(pf.ProtectedPath, filepath.Join(backupDir, filepath.Base(pf.ProtectedPath))); err != nil {
		return err
	}

	// Backup key file
	if err := m.copyFile(pf.KeyPath, filepath.Join(backupDir, filepath.Base(pf.KeyPath))); err != nil {
		return err
	}

	// Save metadata
	metadataFile := filepath.Join(backupDir, "metadata.json")
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataFile, data, 0644)
}

func (m *Manager) copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (m *Manager) searchInMetadata(metadata map[string]string, query string) bool {
	for k, v := range metadata {
		if strings.Contains(strings.ToLower(k), query) ||
			strings.Contains(strings.ToLower(v), query) {
			return true
		}
	}
	return false
}

func (m *Manager) searchInProtection(protection ProtectionConfig, query string) bool {
	if protection.MultiAuth && strings.Contains("multiauth", query) {
		return true
	}
	if protection.TimeLock && strings.Contains("timelock", query) {
		return true
	}
	if protection.Ownership && strings.Contains("ownership", query) {
		return true
	}
	if protection.PolicyScript && strings.Contains("policyscript", query) {
		return true
	}

	for _, team := range protection.Teams {
		if strings.Contains(strings.ToLower(team), query) {
			return true
		}
	}

	return false
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
