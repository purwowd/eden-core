package unit

import (
	"errors"
	"testing"
	"time"

	"github.com/purwowd/eden-core/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEdenError_Creation(t *testing.T) {
	tests := []struct {
		name      string
		errorType core.ErrorType
		severity  core.ErrorSeverity
		code      string
		component string
		message   string
	}{
		{
			name:      "Validation Error",
			errorType: core.ErrorTypeValidation,
			severity:  core.SeverityMedium,
			code:      core.ErrCodeInvalidInput,
			component: "Validator",
			message:   "Invalid input provided",
		},
		{
			name:      "Crypto Error",
			errorType: core.ErrorTypeCrypto,
			severity:  core.SeverityHigh,
			code:      core.ErrCodeEncryptionFailed,
			component: "Crypto",
			message:   "Encryption operation failed",
		},
		{
			name:      "Critical System Error",
			errorType: core.ErrorTypeSystem,
			severity:  core.SeverityCritical,
			code:      core.ErrCodeOutOfMemory,
			component: "System",
			message:   "Out of memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := core.NewEdenError(tt.errorType, tt.severity, tt.code, tt.component, tt.message)

			assert.Equal(t, tt.errorType, err.Type)
			assert.Equal(t, tt.severity, err.Severity)
			assert.Equal(t, tt.code, err.Code)
			assert.Equal(t, tt.component, err.Component)
			assert.Equal(t, tt.message, err.Message)
			assert.NotZero(t, err.Timestamp)
			assert.NotEmpty(t, err.File)

			// Test error interface
			assert.Contains(t, err.Error(), tt.errorType)
			assert.Contains(t, err.Error(), tt.code)
			assert.Contains(t, err.Error(), tt.component)
			assert.Contains(t, err.Error(), tt.message)
		})
	}
}

func TestEdenError_WrapError(t *testing.T) {
	originalErr := errors.New("original error message")

	wrappedErr := core.WrapError(originalErr, core.ErrorTypeCrypto,
		core.SeverityHigh, core.ErrCodeEncryptionFailed, "Crypto", "Encryption failed")

	assert.Equal(t, core.ErrorTypeCrypto, wrappedErr.Type)
	assert.Equal(t, core.SeverityHigh, wrappedErr.Severity)
	assert.Equal(t, core.ErrCodeEncryptionFailed, wrappedErr.Code)
	assert.Equal(t, "Crypto", wrappedErr.Component)
	assert.Equal(t, "Encryption failed", wrappedErr.Message)
	assert.Equal(t, "original error message", wrappedErr.Details)
	assert.Equal(t, originalErr, wrappedErr.Cause)

	// Test unwrapping
	assert.Equal(t, originalErr, wrappedErr.Unwrap())

	// Test stack trace for high severity
	assert.NotEmpty(t, wrappedErr.StackTrace)
}

func TestEdenError_NilWrap(t *testing.T) {
	wrappedErr := core.WrapError(nil, core.ErrorTypeCrypto,
		core.SeverityHigh, core.ErrCodeEncryptionFailed, "Crypto", "Encryption failed")

	assert.Nil(t, wrappedErr)
}

func TestEdenError_IsCritical(t *testing.T) {
	tests := []struct {
		name       string
		severity   core.ErrorSeverity
		isCritical bool
	}{
		{"Low Severity", core.SeverityLow, false},
		{"Medium Severity", core.SeverityMedium, false},
		{"High Severity", core.SeverityHigh, false},
		{"Critical Severity", core.SeverityCritical, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := core.NewEdenError(core.ErrorTypeSystem, tt.severity,
				"TEST_CODE", "Test", "Test message")

			assert.Equal(t, tt.isCritical, err.IsCritical())
		})
	}
}

func TestEdenError_UserFriendlyError(t *testing.T) {
	// Test with custom user message
	err := core.NewEdenError(core.ErrorTypeValidation, core.SeverityMedium,
		core.ErrCodeInvalidInput, "Validator", "Technical validation message")
	err.UserMessage = "Please provide a valid input file"

	assert.Equal(t, "Please provide a valid input file", err.UserFriendlyError())

	// Test without custom user message (fallback to message)
	err2 := core.NewEdenError(core.ErrorTypeValidation, core.SeverityMedium,
		core.ErrCodeInvalidInput, "Validator", "Technical validation message")

	assert.Equal(t, "Technical validation message", err2.UserFriendlyError())
}

func TestErrorConstructors(t *testing.T) {
	t.Run("NewValidationError", func(t *testing.T) {
		err := core.NewValidationError(core.ErrCodeInvalidInput, "Invalid input")

		assert.Equal(t, core.ErrorTypeValidation, err.Type)
		assert.Equal(t, core.SeverityMedium, err.Severity)
		assert.Equal(t, "Validator", err.Component)
	})

	t.Run("NewCryptoError", func(t *testing.T) {
		err := core.NewCryptoError(core.ErrCodeEncryptionFailed, "Encryption failed")

		assert.Equal(t, core.ErrorTypeCrypto, err.Type)
		assert.Equal(t, core.SeverityHigh, err.Severity)
		assert.Equal(t, "Crypto", err.Component)
	})

	t.Run("NewStorageError", func(t *testing.T) {
		err := core.NewStorageError(core.ErrCodeFileNotFound, "File not found")

		assert.Equal(t, core.ErrorTypeStorage, err.Type)
		assert.Equal(t, core.SeverityMedium, err.Severity)
		assert.Equal(t, "Storage", err.Component)
	})

	t.Run("NewNetworkError", func(t *testing.T) {
		err := core.NewNetworkError(core.ErrCodeConnectionFailed, "Connection failed")

		assert.Equal(t, core.ErrorTypeNetwork, err.Type)
		assert.Equal(t, core.SeverityMedium, err.Severity)
		assert.Equal(t, "Network", err.Component)
	})

	t.Run("NewPermissionError", func(t *testing.T) {
		err := core.NewPermissionError(core.ErrCodeAccessDenied, "Access denied")

		assert.Equal(t, core.ErrorTypePermission, err.Type)
		assert.Equal(t, core.SeverityHigh, err.Severity)
		assert.Equal(t, "Permission", err.Component)
	})

	t.Run("NewSystemError", func(t *testing.T) {
		err := core.NewSystemError(core.ErrCodeSystemResource, "System resource error")

		assert.Equal(t, core.ErrorTypeSystem, err.Type)
		assert.Equal(t, core.SeverityCritical, err.Severity)
		assert.Equal(t, "System", err.Component)
	})

	t.Run("NewInternalError", func(t *testing.T) {
		err := core.NewInternalError("INTERNAL_FAILURE", "Internal failure")

		assert.Equal(t, core.ErrorTypeInternal, err.Type)
		assert.Equal(t, core.SeverityCritical, err.Severity)
		assert.Equal(t, "Internal", err.Component)
	})
}

func TestWrapErrorConstructors(t *testing.T) {
	originalErr := errors.New("original error")

	t.Run("WrapCryptoError", func(t *testing.T) {
		err := core.WrapCryptoError(originalErr, core.ErrCodeDecryptionFailed, "Decryption failed")

		assert.Equal(t, core.ErrorTypeCrypto, err.Type)
		assert.Equal(t, core.SeverityHigh, err.Severity)
		assert.Equal(t, "Crypto", err.Component)
		assert.Equal(t, originalErr, err.Cause)
	})

	t.Run("WrapStorageError", func(t *testing.T) {
		err := core.WrapStorageError(originalErr, core.ErrCodeFileAccess, "File access error")

		assert.Equal(t, core.ErrorTypeStorage, err.Type)
		assert.Equal(t, core.SeverityMedium, err.Severity)
		assert.Equal(t, "Storage", err.Component)
		assert.Equal(t, originalErr, err.Cause)
	})

	t.Run("WrapNetworkError", func(t *testing.T) {
		err := core.WrapNetworkError(originalErr, core.ErrCodeTimeout, "Network timeout")

		assert.Equal(t, core.ErrorTypeNetwork, err.Type)
		assert.Equal(t, core.SeverityMedium, err.Severity)
		assert.Equal(t, "Network", err.Component)
		assert.Equal(t, originalErr, err.Cause)
	})

	t.Run("WrapSystemError", func(t *testing.T) {
		err := core.WrapSystemError(originalErr, core.ErrCodeDependencyFailure, "Dependency failure")

		assert.Equal(t, core.ErrorTypeSystem, err.Type)
		assert.Equal(t, core.SeverityCritical, err.Severity)
		assert.Equal(t, "System", err.Component)
		assert.Equal(t, originalErr, err.Cause)
	})
}

func TestErrorRecovery_Creation(t *testing.T) {
	recovery := core.NewErrorRecovery(3, 100*time.Millisecond)

	assert.Equal(t, 3, recovery.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, recovery.RetryDelay)
	assert.Contains(t, recovery.RecoverableTypes, core.ErrorTypeNetwork)
	assert.Contains(t, recovery.RecoverableTypes, core.ErrorTypeStorage)
	assert.Contains(t, recovery.RecoverableTypes, core.ErrorTypeSystem)
}

func TestErrorRecovery_IsRecoverable(t *testing.T) {
	recovery := core.NewErrorRecovery(3, 100*time.Millisecond)

	tests := []struct {
		name          string
		err           error
		isRecoverable bool
	}{
		{
			name:          "Recoverable Network Error",
			err:           core.NewNetworkError(core.ErrCodeConnectionFailed, "Connection failed"),
			isRecoverable: true,
		},
		{
			name:          "Recoverable Storage Error",
			err:           core.NewStorageError(core.ErrCodeFileAccess, "File access error"),
			isRecoverable: true,
		},
		{
			name:          "Non-recoverable Critical Error",
			err:           core.NewSystemError(core.ErrCodeOutOfMemory, "Out of memory"),
			isRecoverable: false,
		},
		{
			name:          "Non-recoverable Crypto Error",
			err:           core.NewCryptoError(core.ErrCodeInvalidKey, "Invalid key"),
			isRecoverable: false,
		},
		{
			name:          "Non-Eden Error",
			err:           errors.New("regular error"),
			isRecoverable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := recovery.IsRecoverable(tt.err)
			assert.Equal(t, tt.isRecoverable, result)
		})
	}
}

func TestErrorRecovery_RetryWithRecovery_Success(t *testing.T) {
	recovery := core.NewErrorRecovery(3, 1*time.Millisecond)

	callCount := 0
	operation := func() error {
		callCount++
		if callCount < 3 {
			return core.NewNetworkError(core.ErrCodeConnectionFailed, "Connection failed")
		}
		return nil
	}

	err := recovery.RetryWithRecovery(operation)

	assert.NoError(t, err)
	assert.Equal(t, 3, callCount)
}

func TestErrorRecovery_RetryWithRecovery_FailureAfterRetries(t *testing.T) {
	recovery := core.NewErrorRecovery(2, 1*time.Millisecond)

	callCount := 0
	operation := func() error {
		callCount++
		return core.NewNetworkError(core.ErrCodeConnectionFailed, "Connection failed")
	}

	err := recovery.RetryWithRecovery(operation)

	assert.Error(t, err)
	assert.Equal(t, 3, callCount) // Initial call + 2 retries

	// Check that the error is wrapped with retry exhausted
	edenErr, ok := err.(*core.EdenError)
	require.True(t, ok)
	assert.Equal(t, "RETRY_EXHAUSTED", edenErr.Code)
}

func TestErrorRecovery_RetryWithRecovery_NonRecoverableError(t *testing.T) {
	recovery := core.NewErrorRecovery(3, 1*time.Millisecond)

	callCount := 0
	operation := func() error {
		callCount++
		return core.NewCryptoError(core.ErrCodeInvalidKey, "Invalid key")
	}

	err := recovery.RetryWithRecovery(operation)

	assert.Error(t, err)
	assert.Equal(t, 1, callCount) // Only one call, no retries for non-recoverable

	edenErr, ok := err.(*core.EdenError)
	require.True(t, ok)
	assert.Equal(t, core.ErrCodeInvalidKey, edenErr.Code)
}

func TestErrorRecovery_RetryWithRecovery_ImmediateSuccess(t *testing.T) {
	recovery := core.NewErrorRecovery(3, 1*time.Millisecond)

	callCount := 0
	operation := func() error {
		callCount++
		return nil
	}

	err := recovery.RetryWithRecovery(operation)

	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestErrorCodes_Constants(t *testing.T) {
	// Test that error codes are properly defined
	assert.Equal(t, "INVALID_INPUT", core.ErrCodeInvalidInput)
	assert.Equal(t, "INVALID_FORMAT", core.ErrCodeInvalidFormat)
	assert.Equal(t, "MISSING_REQUIRED", core.ErrCodeMissingRequired)
	assert.Equal(t, "INVALID_PATH", core.ErrCodeInvalidPath)
	assert.Equal(t, "INVALID_CONFIG", core.ErrCodeInvalidConfig)

	assert.Equal(t, "KEY_GENERATION_FAILED", core.ErrCodeKeyGeneration)
	assert.Equal(t, "ENCRYPTION_FAILED", core.ErrCodeEncryptionFailed)
	assert.Equal(t, "DECRYPTION_FAILED", core.ErrCodeDecryptionFailed)
	assert.Equal(t, "SIGNATURE_FAILED", core.ErrCodeSignatureFailed)
	assert.Equal(t, "INVALID_KEY", core.ErrCodeInvalidKey)
	assert.Equal(t, "INVALID_SIGNATURE", core.ErrCodeInvalidSignature)

	assert.Equal(t, "FILE_NOT_FOUND", core.ErrCodeFileNotFound)
	assert.Equal(t, "FILE_ACCESS_DENIED", core.ErrCodeFileAccess)
	assert.Equal(t, "STORAGE_FULL", core.ErrCodeStorageFull)
	assert.Equal(t, "CORRUPTED_DATA", core.ErrCodeCorruptedData)

	assert.Equal(t, "CONNECTION_FAILED", core.ErrCodeConnectionFailed)
	assert.Equal(t, "TIMEOUT", core.ErrCodeTimeout)
	assert.Equal(t, "UNAUTHORIZED", core.ErrCodeUnauthorized)
	assert.Equal(t, "NETWORK_UNAVAILABLE", core.ErrCodeNetworkUnavailable)

	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", core.ErrCodeInsufficientPermissions)
	assert.Equal(t, "ACCESS_DENIED", core.ErrCodeAccessDenied)
	assert.Equal(t, "AUTHENTICATION_FAILED", core.ErrCodeAuthenticationFailed)

	assert.Equal(t, "OUT_OF_MEMORY", core.ErrCodeOutOfMemory)
	assert.Equal(t, "SYSTEM_RESOURCE_ERROR", core.ErrCodeSystemResource)
	assert.Equal(t, "DEPENDENCY_FAILURE", core.ErrCodeDependencyFailure)
}

func TestErrorType_String(t *testing.T) {
	// Test that error types can be converted to strings properly
	assert.Equal(t, "VALIDATION", string(core.ErrorTypeValidation))
	assert.Equal(t, "CRYPTO", string(core.ErrorTypeCrypto))
	assert.Equal(t, "STORAGE", string(core.ErrorTypeStorage))
	assert.Equal(t, "NETWORK", string(core.ErrorTypeNetwork))
	assert.Equal(t, "PERMISSION", string(core.ErrorTypePermission))
	assert.Equal(t, "SYSTEM", string(core.ErrorTypeSystem))
	assert.Equal(t, "INTERNAL", string(core.ErrorTypeInternal))
}

func TestErrorSeverity_String(t *testing.T) {
	// Test that error severities can be converted to strings properly
	assert.Equal(t, "LOW", string(core.SeverityLow))
	assert.Equal(t, "MEDIUM", string(core.SeverityMedium))
	assert.Equal(t, "HIGH", string(core.SeverityHigh))
	assert.Equal(t, "CRITICAL", string(core.SeverityCritical))
}
