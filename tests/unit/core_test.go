// Package unit provides unit tests with mocks
package unit

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/purwowd/eden-core/internal/adapters"
	"github.com/purwowd/eden-core/tests/mocks"
)

func TestFileSystemOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, mockFS *mocks.MockFileSystem)
	}{
		{
			name: "ReadFile_Success",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				expectedData := []byte("test content")
				mockFS.On("ReadFile", "test.txt").Return(expectedData, nil)

				data, err := mockFS.ReadFile("test.txt")

				assert.NoError(t, err)
				assert.Equal(t, expectedData, data)
				mockFS.AssertExpectations(t)
			},
		},
		{
			name: "ReadFile_FileNotFound",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				mockFS.On("ReadFile", "nonexistent.txt").Return([]byte(nil), errors.New("file not found"))

				data, err := mockFS.ReadFile("nonexistent.txt")

				assert.Error(t, err)
				assert.Nil(t, data)
				assert.Contains(t, err.Error(), "file not found")
				mockFS.AssertExpectations(t)
			},
		},
		{
			name: "WriteFile_Success",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				testData := []byte("test data to write")
				mockFS.On("WriteFile", "output.txt", testData, 0644).Return(nil)

				err := mockFS.WriteFile("output.txt", testData, 0644)

				assert.NoError(t, err)
				mockFS.AssertExpectations(t)
			},
		},
		{
			name: "WriteFile_PermissionDenied",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				testData := []byte("test data")
				mockFS.On("WriteFile", "/root/protected.txt", testData, 0644).Return(errors.New("permission denied"))

				err := mockFS.WriteFile("/root/protected.txt", testData, 0644)

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "permission denied")
				mockFS.AssertExpectations(t)
			},
		},
		{
			name: "Exists_FileExists",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				mockFS.On("Exists", "existing.txt").Return(true)

				exists := mockFS.Exists("existing.txt")

				assert.True(t, exists)
				mockFS.AssertExpectations(t)
			},
		},
		{
			name: "Exists_FileDoesNotExist",
			testFunc: func(t *testing.T, mockFS *mocks.MockFileSystem) {
				mockFS.On("Exists", "missing.txt").Return(false)

				exists := mockFS.Exists("missing.txt")

				assert.False(t, exists)
				mockFS.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS := &mocks.MockFileSystem{}
			tt.testFunc(t, mockFS)
		})
	}
}

func TestCryptoOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, mockCrypto *mocks.MockCryptoProvider)
	}{
		{
			name: "Encrypt_Success",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				plaintext := []byte("secret data")
				key := []byte("32-byte-encryption-key-for-test")
				expectedCiphertext := []byte("encrypted_data_here")

				mockCrypto.On("Encrypt", plaintext, key).Return(expectedCiphertext, nil)

				ciphertext, err := mockCrypto.Encrypt(plaintext, key)

				assert.NoError(t, err)
				assert.Equal(t, expectedCiphertext, ciphertext)
				assert.NotEqual(t, plaintext, ciphertext)
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Encrypt_InvalidKey",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				plaintext := []byte("secret data")
				invalidKey := []byte("short")

				mockCrypto.On("Encrypt", plaintext, invalidKey).Return([]byte(nil), errors.New("invalid key length"))

				ciphertext, err := mockCrypto.Encrypt(plaintext, invalidKey)

				assert.Error(t, err)
				assert.Nil(t, ciphertext)
				assert.Contains(t, err.Error(), "invalid key")
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Decrypt_Success",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				ciphertext := []byte("encrypted_data_here")
				key := []byte("32-byte-encryption-key-for-test")
				expectedPlaintext := []byte("secret data")

				mockCrypto.On("Decrypt", ciphertext, key).Return(expectedPlaintext, nil)

				plaintext, err := mockCrypto.Decrypt(ciphertext, key)

				assert.NoError(t, err)
				assert.Equal(t, expectedPlaintext, plaintext)
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "GenerateKey_Success",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				expectedKey := make([]byte, 32)
				for i := range expectedKey {
					expectedKey[i] = byte(i % 256)
				}

				mockCrypto.On("GenerateKey").Return(expectedKey, nil)

				key, err := mockCrypto.GenerateKey()

				assert.NoError(t, err)
				assert.Equal(t, 32, len(key))
				assert.Equal(t, expectedKey, key)
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Hash_Success",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				data := []byte("data to hash")
				expectedHash := []byte("hashed_result_32_bytes_long_here")

				mockCrypto.On("Hash", data).Return(expectedHash)

				hash := mockCrypto.Hash(data)

				assert.Equal(t, expectedHash, hash)
				assert.Equal(t, 32, len(hash))
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Sign_Success",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				data := []byte("data to sign")
				privateKey := []byte("private_key_32_bytes_for_signing")
				expectedSignature := []byte("signature_result_here")

				mockCrypto.On("Sign", data, privateKey).Return(expectedSignature, nil)

				signature, err := mockCrypto.Sign(data, privateKey)

				assert.NoError(t, err)
				assert.Equal(t, expectedSignature, signature)
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Verify_ValidSignature",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				data := []byte("signed data")
				signature := []byte("valid_signature")
				publicKey := []byte("public_key_for_verification")

				mockCrypto.On("Verify", data, signature, publicKey).Return(true)

				isValid := mockCrypto.Verify(data, signature, publicKey)

				assert.True(t, isValid)
				mockCrypto.AssertExpectations(t)
			},
		},
		{
			name: "Verify_InvalidSignature",
			testFunc: func(t *testing.T, mockCrypto *mocks.MockCryptoProvider) {
				data := []byte("signed data")
				invalidSignature := []byte("invalid_signature")
				publicKey := []byte("public_key_for_verification")

				mockCrypto.On("Verify", data, invalidSignature, publicKey).Return(false)

				isValid := mockCrypto.Verify(data, invalidSignature, publicKey)

				assert.False(t, isValid)
				mockCrypto.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCrypto := &mocks.MockCryptoProvider{}
			tt.testFunc(t, mockCrypto)
		})
	}
}

func TestLoggerOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, mockLogger *mocks.MockLogger)
	}{
		{
			name: "Debug_WithData",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				message := "Debug message"
				data := map[string]interface{}{"key": "value"}

				mockLogger.On("Debug", message, data).Return()

				mockLogger.Debug(message, data)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "Info_WithoutData",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				message := "Info message"

				mockLogger.On("Info", message).Return()

				mockLogger.Info(message)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "Error_WithError",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				message := "Error occurred"
				err := errors.New("test error")

				mockLogger.On("Error", message, err).Return()

				mockLogger.Error(message, err)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "LogOperation_WithDuration",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				operation := "file_protection"
				message := "Protection completed"
				duration := 100 * time.Millisecond

				mockLogger.On("LogOperation", operation, message, duration).Return()

				mockLogger.LogOperation(operation, message, duration)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "LogSecurity_Event",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				event := "unauthorized_access_attempt"
				userID := "user123"
				fileID := "file456"

				mockLogger.On("LogSecurity", event, userID, fileID).Return()

				mockLogger.LogSecurity(event, userID, fileID)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "LogAccess_Success",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				operation := "file_read"
				userID := "user123"
				fileID := "file456"
				success := true

				mockLogger.On("LogAccess", operation, userID, fileID, success).Return()

				mockLogger.LogAccess(operation, userID, fileID, success)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "LogPerformance_WithMetrics",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				operation := "encryption"
				duration := 50 * time.Millisecond
				metrics := map[string]interface{}{
					"bytes_processed": 1024,
				}

				mockLogger.On("LogPerformance", operation, duration, metrics).Return()

				mockLogger.LogPerformance(operation, duration, metrics)

				mockLogger.AssertExpectations(t)
			},
		},
		{
			name: "Close_Success",
			testFunc: func(t *testing.T, mockLogger *mocks.MockLogger) {
				mockLogger.On("Close").Return(nil)

				err := mockLogger.Close()

				assert.NoError(t, err)
				mockLogger.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := &mocks.MockLogger{}
			tt.testFunc(t, mockLogger)
		})
	}
}

func TestStorageOperations(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T, mockStorage *mocks.MockStorageProvider)
	}{
		{
			name: "Store_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				id := "file123"
				data := []byte("file content")
				metadata := map[string]interface{}{
					"filename": "test.txt",
					"size":     len(data),
				}

				mockStorage.On("Store", id, data, metadata).Return(nil)

				err := mockStorage.Store(id, data, metadata)

				assert.NoError(t, err)
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "Retrieve_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				id := "file123"
				expectedData := []byte("file content")
				expectedMetadata := map[string]interface{}{
					"filename": "test.txt",
					"size":     len(expectedData),
				}

				mockStorage.On("Retrieve", id).Return(expectedData, expectedMetadata, nil)

				data, metadata, err := mockStorage.Retrieve(id)

				assert.NoError(t, err)
				assert.Equal(t, expectedData, data)
				assert.Equal(t, expectedMetadata, metadata)
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "Retrieve_NotFound",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				id := "nonexistent"

				mockStorage.On("Retrieve", id).Return([]byte(nil), map[string]interface{}(nil), errors.New("not found"))

				data, metadata, err := mockStorage.Retrieve(id)

				assert.Error(t, err)
				assert.Nil(t, data)
				assert.Nil(t, metadata)
				assert.Contains(t, err.Error(), "not found")
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "List_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				expectedFiles := []string{"file1", "file2", "file3"}

				mockStorage.On("List").Return(expectedFiles, nil)

				files, err := mockStorage.List()

				assert.NoError(t, err)
				assert.Equal(t, expectedFiles, files)
				assert.Len(t, files, 3)
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "Search_WithQuery",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				query := map[string]interface{}{
					"filename": "*.txt",
					"size":     ">1024",
				}
				expectedResults := []string{"file1.txt", "file2.txt"}

				mockStorage.On("Search", query).Return(expectedResults, nil)

				results, err := mockStorage.Search(query)

				assert.NoError(t, err)
				assert.Equal(t, expectedResults, results)
				assert.Len(t, results, 2)
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "GetStats_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				expectedStats := map[string]interface{}{
					"total_files":   100,
					"total_size":    1048576,
					"last_accessed": time.Now(),
				}

				mockStorage.On("GetStats").Return(expectedStats)

				stats := mockStorage.GetStats()

				assert.Equal(t, expectedStats, stats)
				assert.Equal(t, 100, stats["total_files"])
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "Backup_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				destination := "/backup/location"

				mockStorage.On("Backup", destination).Return(nil)

				err := mockStorage.Backup(destination)

				assert.NoError(t, err)
				mockStorage.AssertExpectations(t)
			},
		},
		{
			name: "Cleanup_Success",
			testFunc: func(t *testing.T, mockStorage *mocks.MockStorageProvider) {
				mockStorage.On("Cleanup").Return(nil)

				err := mockStorage.Cleanup()

				assert.NoError(t, err)
				mockStorage.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &mocks.MockStorageProvider{}
			tt.testFunc(t, mockStorage)
		})
	}
}

func TestMemoryFileSystem(t *testing.T) {
	fs := adapters.NewMemoryFileSystem()

	t.Run("WriteAndRead", func(t *testing.T) {
		filename := "test.txt"
		content := []byte("hello world")

		// Write file
		err := fs.WriteFile(filename, content, 0644)
		assert.NoError(t, err)

		// Check if exists
		assert.True(t, fs.Exists(filename))

		// Read file
		data, err := fs.ReadFile(filename)
		assert.NoError(t, err)
		assert.Equal(t, content, data)
	})

	t.Run("ReadNonexistentFile", func(t *testing.T) {
		_, err := fs.ReadFile("nonexistent.txt")
		assert.Error(t, err)
	})

	t.Run("FileInfo", func(t *testing.T) {
		filename := "info_test.txt"
		content := []byte("test content for info")

		err := fs.WriteFile(filename, content, 0644)
		assert.NoError(t, err)

		info, err := fs.Stat(filename)
		assert.NoError(t, err)
		assert.Equal(t, "info_test.txt", info.Name())
		assert.Equal(t, int64(len(content)), info.Size())
		assert.False(t, info.IsDir())
	})

	t.Run("Remove", func(t *testing.T) {
		filename := "to_remove.txt"
		content := []byte("remove me")

		err := fs.WriteFile(filename, content, 0644)
		assert.NoError(t, err)
		assert.True(t, fs.Exists(filename))

		err = fs.Remove(filename)
		assert.NoError(t, err)
		assert.False(t, fs.Exists(filename))
	})
}
