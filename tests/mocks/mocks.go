// Package mocks provides mock implementations for testing
package mocks

import (
	"time"

	"github.com/purwowd/eden-core/internal/interfaces"
	"github.com/stretchr/testify/mock"
)

// MockFileSystem provides a mock implementation of FileSystem
type MockFileSystem struct {
	mock.Mock
}

func (m *MockFileSystem) ReadFile(filename string) ([]byte, error) {
	args := m.Called(filename)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockFileSystem) WriteFile(filename string, data []byte, perm int) error {
	args := m.Called(filename, data, perm)
	return args.Error(0)
}

func (m *MockFileSystem) Stat(filename string) (interfaces.FileInfo, error) {
	args := m.Called(filename)
	return args.Get(0).(interfaces.FileInfo), args.Error(1)
}

func (m *MockFileSystem) Remove(filename string) error {
	args := m.Called(filename)
	return args.Error(0)
}

func (m *MockFileSystem) MkdirAll(path string, perm int) error {
	args := m.Called(path, perm)
	return args.Error(0)
}

func (m *MockFileSystem) OpenFile(name string, flag int, perm int) (interfaces.File, error) {
	args := m.Called(name, flag, perm)
	return args.Get(0).(interfaces.File), args.Error(1)
}

func (m *MockFileSystem) Exists(filename string) bool {
	args := m.Called(filename)
	return args.Bool(0)
}

func (m *MockFileSystem) TempDir() string {
	args := m.Called()
	return args.String(0)
}

// MockFileInfo provides a mock implementation of FileInfo
type MockFileInfo struct {
	mock.Mock
}

func (m *MockFileInfo) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockFileInfo) Size() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}

func (m *MockFileInfo) Mode() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockFileInfo) ModTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *MockFileInfo) IsDir() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockFile provides a mock implementation of File
type MockFile struct {
	mock.Mock
}

func (m *MockFile) Read(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockFile) Write(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockFile) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockFile) Stat() (interfaces.FileInfo, error) {
	args := m.Called()
	return args.Get(0).(interfaces.FileInfo), args.Error(1)
}

func (m *MockFile) Seek(offset int64, whence int) (int64, error) {
	args := m.Called(offset, whence)
	return args.Get(0).(int64), args.Error(1)
}

// MockCryptoProvider provides a mock implementation of CryptoProvider
type MockCryptoProvider struct {
	mock.Mock
}

func (m *MockCryptoProvider) Encrypt(data []byte, key []byte) ([]byte, error) {
	args := m.Called(data, key)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) Decrypt(data []byte, key []byte) ([]byte, error) {
	args := m.Called(data, key)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) GenerateKey() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) Hash(data []byte) []byte {
	args := m.Called(data)
	return args.Get(0).([]byte)
}

func (m *MockCryptoProvider) Sign(data []byte, privateKey []byte) ([]byte, error) {
	args := m.Called(data, privateKey)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoProvider) Verify(data []byte, signature []byte, publicKey []byte) bool {
	args := m.Called(data, signature, publicKey)
	return args.Bool(0)
}

// MockLogger provides a mock implementation of Logger
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(message string, data ...map[string]interface{}) {
	args := []interface{}{message}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) Info(message string, data ...map[string]interface{}) {
	args := []interface{}{message}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) Warn(message string, data ...map[string]interface{}) {
	args := []interface{}{message}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) Error(message string, err error, data ...map[string]interface{}) {
	args := []interface{}{message, err}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) LogOperation(operation, message string, duration time.Duration, data ...map[string]interface{}) {
	args := []interface{}{operation, message, duration}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) LogSecurity(event, userID, fileID string, data ...map[string]interface{}) {
	args := []interface{}{event, userID, fileID}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) LogAccess(operation, userID, fileID string, success bool, data ...map[string]interface{}) {
	args := []interface{}{operation, userID, fileID, success}
	for _, d := range data {
		args = append(args, d)
	}
	m.Called(args...)
}

func (m *MockLogger) LogPerformance(operation string, duration time.Duration, metrics map[string]interface{}) {
	m.Called(operation, duration, metrics)
}

func (m *MockLogger) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockStorageProvider provides a mock implementation of StorageProvider
type MockStorageProvider struct {
	mock.Mock
}

func (m *MockStorageProvider) Store(id string, data []byte, metadata map[string]interface{}) error {
	args := m.Called(id, data, metadata)
	return args.Error(0)
}

func (m *MockStorageProvider) Retrieve(id string) ([]byte, map[string]interface{}, error) {
	args := m.Called(id)
	return args.Get(0).([]byte), args.Get(1).(map[string]interface{}), args.Error(2)
}

func (m *MockStorageProvider) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockStorageProvider) List() ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorageProvider) Search(query map[string]interface{}) ([]string, error) {
	args := m.Called(query)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorageProvider) GetStats() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

func (m *MockStorageProvider) Cleanup() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockStorageProvider) Backup(destination string) error {
	args := m.Called(destination)
	return args.Error(0)
}

// MockValidationResult provides a mock implementation of ValidationResult
type MockValidationResult struct {
	mock.Mock
}

func (m *MockValidationResult) IsValid() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockValidationResult) GetErrors() []interfaces.ValidationError {
	args := m.Called()
	return args.Get(0).([]interfaces.ValidationError)
}

func (m *MockValidationResult) AddError(field, message, code string) {
	m.Called(field, message, code)
}

// MockValidationError provides a mock implementation of ValidationError
type MockValidationError struct {
	mock.Mock
}

func (m *MockValidationError) GetField() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockValidationError) GetMessage() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockValidationError) GetCode() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockValidationError) Error() string {
	args := m.Called()
	return args.String(0)
}

// MockPerformanceMonitor provides a mock implementation of PerformanceMonitor
type MockPerformanceMonitor struct {
	mock.Mock
}

func (m *MockPerformanceMonitor) StartOperation(name string) interfaces.PerformanceTracker {
	args := m.Called(name)
	return args.Get(0).(interfaces.PerformanceTracker)
}

func (m *MockPerformanceMonitor) RecordMetric(name string, value float64, tags map[string]string) {
	m.Called(name, value, tags)
}

func (m *MockPerformanceMonitor) GetStats() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

func (m *MockPerformanceMonitor) Reset() {
	m.Called()
}

// MockPerformanceTracker provides a mock implementation of PerformanceTracker
type MockPerformanceTracker struct {
	mock.Mock
}

func (m *MockPerformanceTracker) End() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *MockPerformanceTracker) AddMetadata(key string, value interface{}) {
	m.Called(key, value)
}

func (m *MockPerformanceTracker) GetDuration() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}
