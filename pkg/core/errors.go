package core

import (
	"fmt"
	"runtime"
	"time"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation ErrorType = "VALIDATION"
	ErrorTypeCrypto     ErrorType = "CRYPTO"
	ErrorTypeStorage    ErrorType = "STORAGE"
	ErrorTypeNetwork    ErrorType = "NETWORK"
	ErrorTypePermission ErrorType = "PERMISSION"
	ErrorTypeSystem     ErrorType = "SYSTEM"
	ErrorTypeInternal   ErrorType = "INTERNAL"
)

// ErrorSeverity represents the severity level of errors
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "LOW"
	SeverityMedium   ErrorSeverity = "MEDIUM"
	SeverityHigh     ErrorSeverity = "HIGH"
	SeverityCritical ErrorSeverity = "CRITICAL"
)

// EdenError represents a structured error with context
type EdenError struct {
	Type        ErrorType     `json:"type"`
	Severity    ErrorSeverity `json:"severity"`
	Code        string        `json:"code"`
	Message     string        `json:"message"`
	Details     string        `json:"details,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
	StackTrace  string        `json:"stack_trace,omitempty"`
	Operation   string        `json:"operation,omitempty"`
	File        string        `json:"file,omitempty"`
	Component   string        `json:"component"`
	UserMessage string        `json:"user_message,omitempty"`
	Cause       error         `json:"-"` // Original error
}

// Error implements the error interface
func (e *EdenError) Error() string {
	return fmt.Sprintf("[%s:%s] %s: %s", e.Type, e.Code, e.Component, e.Message)
}

// UserFriendlyError returns a user-friendly error message
func (e *EdenError) UserFriendlyError() string {
	if e.UserMessage != "" {
		return e.UserMessage
	}
	return e.Message
}

// Unwrap implements error unwrapping for Go 1.13+
func (e *EdenError) Unwrap() error {
	return e.Cause
}

// IsCritical returns true if error is critical severity
func (e *EdenError) IsCritical() bool {
	return e.Severity == SeverityCritical
}

// NewEdenError creates a new structured error
func NewEdenError(errorType ErrorType, severity ErrorSeverity, code, component, message string) *EdenError {
	_, file, line, _ := runtime.Caller(1)

	return &EdenError{
		Type:      errorType,
		Severity:  severity,
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		File:      fmt.Sprintf("%s:%d", file, line),
		Component: component,
	}
}

// WrapError wraps an existing error with Eden context
func WrapError(err error, errorType ErrorType, severity ErrorSeverity, code, component, message string) *EdenError {
	if err == nil {
		return nil
	}

	_, file, line, _ := runtime.Caller(1)

	edenErr := &EdenError{
		Type:      errorType,
		Severity:  severity,
		Code:      code,
		Message:   message,
		Details:   err.Error(),
		Timestamp: time.Now(),
		File:      fmt.Sprintf("%s:%d", file, line),
		Component: component,
		Cause:     err,
	}

	// Capture stack trace for high/critical errors
	if severity == SeverityHigh || severity == SeverityCritical {
		edenErr.StackTrace = captureStackTrace()
	}

	return edenErr
}

// Common error constructors for different components

// Validation Errors
func NewValidationError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeValidation, SeverityMedium, code, "Validator", message)
}

// Crypto Errors
func NewCryptoError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeCrypto, SeverityHigh, code, "Crypto", message)
}

func WrapCryptoError(err error, code, message string) *EdenError {
	return WrapError(err, ErrorTypeCrypto, SeverityHigh, code, "Crypto", message)
}

// Storage Errors
func NewStorageError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeStorage, SeverityMedium, code, "Storage", message)
}

func WrapStorageError(err error, code, message string) *EdenError {
	return WrapError(err, ErrorTypeStorage, SeverityMedium, code, "Storage", message)
}

// Network Errors
func NewNetworkError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeNetwork, SeverityMedium, code, "Network", message)
}

func WrapNetworkError(err error, code, message string) *EdenError {
	return WrapError(err, ErrorTypeNetwork, SeverityMedium, code, "Network", message)
}

// Permission Errors
func NewPermissionError(code, message string) *EdenError {
	return NewEdenError(ErrorTypePermission, SeverityHigh, code, "Permission", message)
}

// System Errors
func NewSystemError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeSystem, SeverityCritical, code, "System", message)
}

func WrapSystemError(err error, code, message string) *EdenError {
	return WrapError(err, ErrorTypeSystem, SeverityCritical, code, "System", message)
}

// Internal Errors
func NewInternalError(code, message string) *EdenError {
	return NewEdenError(ErrorTypeInternal, SeverityCritical, code, "Internal", message)
}

// ErrorRecovery provides error recovery and retry logic
type ErrorRecovery struct {
	MaxRetries       int
	RetryDelay       time.Duration
	RecoverableTypes []ErrorType
}

// NewErrorRecovery creates a new error recovery instance
func NewErrorRecovery(maxRetries int, retryDelay time.Duration) *ErrorRecovery {
	return &ErrorRecovery{
		MaxRetries: maxRetries,
		RetryDelay: retryDelay,
		RecoverableTypes: []ErrorType{
			ErrorTypeNetwork,
			ErrorTypeStorage,
			ErrorTypeSystem,
		},
	}
}

// IsRecoverable checks if an error can be recovered from
func (er *ErrorRecovery) IsRecoverable(err error) bool {
	if edenErr, ok := err.(*EdenError); ok {
		for _, recoverableType := range er.RecoverableTypes {
			if edenErr.Type == recoverableType && edenErr.Severity != SeverityCritical {
				return true
			}
		}
	}
	return false
}

// RetryWithRecovery executes a function with retry logic
func (er *ErrorRecovery) RetryWithRecovery(operation func() error) error {
	var lastErr error

	for attempt := 0; attempt <= er.MaxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		if !er.IsRecoverable(err) {
			return err
		}

		if attempt < er.MaxRetries {
			time.Sleep(er.RetryDelay)
		}
	}

	return WrapError(lastErr, ErrorTypeSystem, SeverityHigh, "RETRY_EXHAUSTED",
		"ErrorRecovery", "Maximum retry attempts exceeded")
}

// captureStackTrace captures the current stack trace
func captureStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// Common error codes
const (
	// Validation codes
	ErrCodeInvalidInput    = "INVALID_INPUT"
	ErrCodeInvalidFormat   = "INVALID_FORMAT"
	ErrCodeMissingRequired = "MISSING_REQUIRED"
	ErrCodeInvalidPath     = "INVALID_PATH"
	ErrCodeInvalidConfig   = "INVALID_CONFIG"

	// Crypto codes
	ErrCodeKeyGeneration    = "KEY_GENERATION_FAILED"
	ErrCodeEncryptionFailed = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed = "DECRYPTION_FAILED"
	ErrCodeSignatureFailed  = "SIGNATURE_FAILED"
	ErrCodeInvalidKey       = "INVALID_KEY"
	ErrCodeInvalidSignature = "INVALID_SIGNATURE"

	// Storage codes
	ErrCodeFileNotFound  = "FILE_NOT_FOUND"
	ErrCodeFileAccess    = "FILE_ACCESS_DENIED"
	ErrCodeStorageFull   = "STORAGE_FULL"
	ErrCodeCorruptedData = "CORRUPTED_DATA"

	// Network codes
	ErrCodeConnectionFailed   = "CONNECTION_FAILED"
	ErrCodeTimeout            = "TIMEOUT"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeNetworkUnavailable = "NETWORK_UNAVAILABLE"

	// Permission codes
	ErrCodeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
	ErrCodeAccessDenied            = "ACCESS_DENIED"
	ErrCodeAuthenticationFailed    = "AUTHENTICATION_FAILED"

	// System codes
	ErrCodeOutOfMemory       = "OUT_OF_MEMORY"
	ErrCodeSystemResource    = "SYSTEM_RESOURCE_ERROR"
	ErrCodeDependencyFailure = "DEPENDENCY_FAILURE"
)
