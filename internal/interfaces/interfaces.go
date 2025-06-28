// Package interfaces defines contracts for dependency injection and testing
package interfaces

import (
	"io"
	"os"
	"time"
)

// FileSystem defines file system operations
type FileSystem interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Exists(path string) bool
	CreateDirectory(path string) error
	Remove(path string) error
}

// FileInfo interface for file information
type FileInfo interface {
	Name() string
	Size() int64
	Mode() int
	ModTime() time.Time
	IsDir() bool
}

// File interface for file operations
type File interface {
	io.ReadWriteCloser
	Stat() (FileInfo, error)
	Seek(offset int64, whence int) (int64, error)
}

// CryptoProvider interface for cryptographic operations (mockable)
type CryptoProvider interface {
	Encrypt(data []byte, key []byte) ([]byte, error)
	Decrypt(data []byte, key []byte) ([]byte, error)
	GenerateKey() ([]byte, error)
	Hash(data []byte) []byte
	Sign(data []byte, privateKey []byte) ([]byte, error)
	Verify(data []byte, signature []byte, publicKey []byte) bool
}

// Logger interface for logging operations (mockable)
type Logger interface {
	Debug(message string, data ...map[string]interface{})
	Info(message string, data ...map[string]interface{})
	Warn(message string, data ...map[string]interface{})
	Error(message string, err error, data ...map[string]interface{})
	LogOperation(operation, message string, duration time.Duration, data ...map[string]interface{})
	LogSecurity(event, userID, fileID string, data ...map[string]interface{})
	LogAccess(operation, userID, fileID string, success bool, data ...map[string]interface{})
	LogPerformance(operation string, duration time.Duration, metrics map[string]interface{})
	Close() error
}

// ConfigProvider interface for configuration management (mockable)
type ConfigProvider interface {
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
	GetDuration(key string) time.Duration
	GetStringSlice(key string) []string
	Set(key string, value interface{})
	Load(configPath string) error
	Validate() error
}

// StorageProvider interface for storage operations (mockable)
type StorageProvider interface {
	Store(id string, data []byte, metadata map[string]interface{}) error
	Retrieve(id string) ([]byte, map[string]interface{}, error)
	Delete(id string) error
	List() ([]string, error)
	Search(query map[string]interface{}) ([]string, error)
	GetStats() map[string]interface{}
	Cleanup() error
	Backup(destination string) error
}

// Validator interface for input validation (mockable)
type Validator interface {
	ValidateFilePath(path string) ValidationResult
	ValidateFileContent(path string) ValidationResult
	ValidateProtectionConfig(multiAuth, timeLock, ownership, policyScript bool, teams []string, lockDuration string) ValidationResult
	ValidateKeyFile(keyPath string) ValidationResult
	ValidateEnvironment() ValidationResult
	ValidateSignature(data []byte, signature []byte, publicKey []byte) ValidationResult
	ValidateHash(hash string, expectedLength int) ValidationResult
	CalculateFileHash(path string) (string, error)
}

// ValidationResult represents validation results
type ValidationResult interface {
	IsValid() bool
	GetErrors() []ValidationError
	AddError(field, message, code string)
}

// ValidationError represents a validation error
type ValidationError interface {
	GetField() string
	GetMessage() string
	GetCode() string
	Error() string
}

// NetworkProvider interface for network operations (mockable)
type NetworkProvider interface {
	RegisterProtectedCode(metadata interface{}) (interface{}, error)
	VerifyCodeAccess(protectionID string, requesterPubKey string) (bool, error)
	DistributeToNetwork(record interface{}) error
	JoinNetwork(bootstrapNodes []string) error
	GetNetworkStats() map[string]interface{}
}

// PerformanceMonitor interface for performance tracking (mockable)
type PerformanceMonitor interface {
	StartOperation(name string) PerformanceTracker
	RecordMetric(name string, value float64, tags map[string]string)
	GetStats() map[string]interface{}
	Reset()
}

// PerformanceTracker interface for tracking individual operations
type PerformanceTracker interface {
	End() time.Duration
	AddMetadata(key string, value interface{})
	GetDuration() time.Duration
}
