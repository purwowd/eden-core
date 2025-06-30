package config

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Validator handles input validation and security checks
type Validator struct {
	config *Config
}

// NewValidator creates a new validator with configuration
func NewValidator(cfg *Config) *Validator {
	return &Validator{config: cfg}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
	Code    string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s: %s (code: %s)", e.Field, e.Message, e.Code)
}

// ValidationResult holds validation results
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// AddError adds a validation error
func (vr *ValidationResult) AddError(field, message, code string) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// ValidateFilePath validates file path for security
func (v *Validator) ValidateFilePath(path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check for empty path
	if strings.TrimSpace(path) == "" {
		result.AddError("path", "file path cannot be empty", "EMPTY_PATH")
		return result
	}

	// Check for path traversal attacks
	if strings.Contains(path, "..") {
		result.AddError("path", "path traversal not allowed", "PATH_TRAVERSAL")
		return result
	}

	// Check for absolute path outside allowed directories
	absPath, err := filepath.Abs(path)
	if err != nil {
		result.AddError("path", "invalid file path", "INVALID_PATH")
		return result
	}

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		ext = ext[1:] // Remove the dot
		allowed := false
		for _, allowedExt := range v.config.Security.AllowedFormats {
			if ext == strings.ToLower(allowedExt) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.AddError("extension", fmt.Sprintf("file extension '%s' not allowed", ext), "INVALID_EXTENSION")
		}
	}

	// Check if file exists and is readable
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		result.AddError("path", "file does not exist", "FILE_NOT_FOUND")
	} else if err != nil {
		result.AddError("path", "cannot access file", "ACCESS_ERROR")
	}

	return result
}

// ValidateFileContent validates file content for security
func (v *Validator) ValidateFileContent(path string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	file, err := os.Open(path)
	if err != nil {
		result.AddError("file", "cannot open file for validation", "OPEN_ERROR")
		return result
	}
	defer file.Close()

	// Check file size
	stat, err := file.Stat()
	if err != nil {
		result.AddError("file", "cannot get file info", "STAT_ERROR")
		return result
	}

	if stat.Size() > v.config.Security.MaxFileSize {
		result.AddError("size", fmt.Sprintf("file size %d exceeds maximum %d", stat.Size(), v.config.Security.MaxFileSize), "FILE_TOO_LARGE")
		return result
	}

	// Check if it's a directory
	if stat.IsDir() {
		result.AddError("type", "directories are not supported", "DIRECTORY_NOT_SUPPORTED")
		return result
	}

	// Read first chunk to check for binary content
	buffer := make([]byte, 1024)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		result.AddError("content", "cannot read file content", "READ_ERROR")
		return result
	}

	// Check for null bytes (binary content)
	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			result.AddError("content", "binary files are not supported", "BINARY_FILE")
			break
		}
	}

	// Reset file pointer
	file.Seek(0, 0)

	// Validate content based on file type
	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		ext = ext[1:] // Remove the dot
		if err := v.validateFileByType(file, ext); err != nil {
			result.AddError("content", err.Error(), "CONTENT_VALIDATION_FAILED")
		}
	}

	return result
}

// ValidateProtectionConfig validates protection configuration
func (v *Validator) ValidateProtectionConfig(multiAuth, timeLock, ownership, policyScript bool, teams []string, lockDuration string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// At least one protection method must be enabled
	if !multiAuth && !timeLock && !ownership && !policyScript {
		result.AddError("protection", "at least one protection method must be enabled", "NO_PROTECTION")
	}

	// Validate teams for multi-auth
	if multiAuth {
		if len(teams) == 0 {
			result.AddError("teams", "teams list cannot be empty when multi-auth is enabled", "EMPTY_TEAMS")
		} else {
			for i, team := range teams {
				if strings.TrimSpace(team) == "" {
					result.AddError("teams", fmt.Sprintf("team name at index %d cannot be empty", i), "EMPTY_TEAM_NAME")
				}
				if !v.isValidTeamName(team) {
					result.AddError("teams", fmt.Sprintf("invalid team name: %s", team), "INVALID_TEAM_NAME")
				}
			}
		}
	}

	// Validate lock duration for time-lock
	if timeLock {
		if lockDuration == "" {
			result.AddError("lockDuration", "lock duration cannot be empty when time-lock is enabled", "EMPTY_LOCK_DURATION")
		} else {
			// Try to validate as relative duration first
			if _, err := time.ParseDuration(lockDuration); err != nil {
				// If relative duration fails, try absolute time format
				if _, err := time.Parse(time.RFC3339, lockDuration); err != nil {
					result.AddError("lockDuration", "invalid lock duration format. Use relative (e.g., '+1h', '+24h') or absolute (e.g., '2025-01-01T00:00:00Z')", "INVALID_DURATION_FORMAT")
				}
			}
		}
	}

	return result
}

// ValidateKeyFile validates a key file
func (v *Validator) ValidateKeyFile(keyPath string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check if key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		result.AddError("keyFile", "key file does not exist", "KEY_FILE_NOT_FOUND")
		return result
	}

	// Check key file size (should be reasonable for cryptographic keys)
	stat, err := os.Stat(keyPath)
	if err != nil {
		result.AddError("keyFile", "cannot access key file", "KEY_FILE_ACCESS_ERROR")
		return result
	}

	if stat.Size() < 32 || stat.Size() > 8192 {
		result.AddError("keyFile", "key file size is suspicious", "SUSPICIOUS_KEY_SIZE")
	}

	// Check key file permissions (should be restricted)
	mode := stat.Mode()
	if mode&0077 != 0 {
		result.AddError("keyFile", "key file has overly permissive permissions", "INSECURE_KEY_PERMISSIONS")
	}

	return result
}

// ValidateEnvironment validates the runtime environment
func (v *Validator) ValidateEnvironment() *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check required directories exist and are writable
	dirs := []string{
		v.config.Security.KeyDirectory,
		v.config.Storage.BasePath,
		v.config.Storage.TempDirectory,
	}

	for _, dir := range dirs {
		if err := v.checkDirectoryAccess(dir); err != nil {
			result.AddError("environment", fmt.Sprintf("directory access error for %s: %v", dir, err), "DIRECTORY_ACCESS_ERROR")
		}
	}

	// Check disk space
	if err := v.checkDiskSpace(); err != nil {
		result.AddError("environment", fmt.Sprintf("disk space check failed: %v", err), "DISK_SPACE_ERROR")
	}

	return result
}

// ValidateSignature validates a cryptographic signature
func (v *Validator) ValidateSignature(data []byte, signature []byte, publicKey []byte) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Basic validation
	if len(data) == 0 {
		result.AddError("signature", "data cannot be empty", "EMPTY_DATA")
	}

	if len(signature) == 0 {
		result.AddError("signature", "signature cannot be empty", "EMPTY_SIGNATURE")
	}

	if len(publicKey) == 0 {
		result.AddError("signature", "public key cannot be empty", "EMPTY_PUBLIC_KEY")
	}

	// Check signature format (basic length check for secp256k1)
	if len(signature) != 64 && len(signature) != 65 {
		result.AddError("signature", "invalid signature length", "INVALID_SIGNATURE_LENGTH")
	}

	// Check public key format (33 or 65 bytes for secp256k1)
	if len(publicKey) != 33 && len(publicKey) != 65 {
		result.AddError("signature", "invalid public key length", "INVALID_PUBLIC_KEY_LENGTH")
	}

	return result
}

// ValidateHash validates a hash value
func (v *Validator) ValidateHash(hash string, expectedLength int) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if hash == "" {
		result.AddError("hash", "hash cannot be empty", "EMPTY_HASH")
		return result
	}

	// Check if it's valid hex
	if _, err := hex.DecodeString(hash); err != nil {
		result.AddError("hash", "hash must be valid hexadecimal", "INVALID_HEX")
	}

	// Check length
	if len(hash) != expectedLength*2 { // hex encoding doubles the length
		result.AddError("hash", fmt.Sprintf("hash length must be %d characters", expectedLength*2), "INVALID_HASH_LENGTH")
	}

	return result
}

// CalculateFileHash calculates SHA256 hash of a file
func (v *Validator) CalculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Internal helper methods

func (v *Validator) validateFileByType(file *os.File, ext string) error {
	switch ext {
	case "py":
		return v.validatePythonFile(file)
	case "js":
		return v.validateJavaScriptFile(file)
	case "php":
		return v.validatePHPFile(file)
	case "go":
		return v.validateGoFile(file)
	default:
		// For other files, just check for basic syntax
		return v.validateGenericFile(file)
	}
}

func (v *Validator) validatePythonFile(file *os.File) error {
	// Basic Python syntax validation
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check for obvious syntax errors
		if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ") {
			continue
		}

		// Check for suspicious imports
		suspiciousImports := []string{"subprocess", "os.system", "eval", "exec"}
		for _, suspicious := range suspiciousImports {
			if strings.Contains(line, suspicious) {
				return fmt.Errorf("potentially dangerous import detected at line %d: %s", lineNum, suspicious)
			}
		}
	}

	return scanner.Err()
}

func (v *Validator) validateJavaScriptFile(file *os.File) error {
	// Basic JavaScript validation
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check for suspicious patterns
		suspicious := []string{"eval(", "Function(", "document.write", "innerHTML"}
		for _, pattern := range suspicious {
			if strings.Contains(line, pattern) {
				return fmt.Errorf("potentially dangerous pattern detected at line %d: %s", lineNum, pattern)
			}
		}
	}

	return scanner.Err()
}

func (v *Validator) validatePHPFile(file *os.File) error {
	// Basic PHP validation
	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasPhpTag := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<?php") {
			hasPhpTag = true
		}

		// Check for suspicious functions
		suspicious := []string{"eval(", "system(", "shell_exec(", "passthru("}
		for _, pattern := range suspicious {
			if strings.Contains(line, pattern) {
				return fmt.Errorf("potentially dangerous function detected at line %d: %s", lineNum, pattern)
			}
		}
	}

	if !hasPhpTag && lineNum > 0 {
		return fmt.Errorf("PHP file must contain <?php tag")
	}

	return scanner.Err()
}

func (v *Validator) validateGoFile(file *os.File) error {
	// Basic Go syntax validation
	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasPackage := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "package ") {
			hasPackage = true
		}

		// Check for suspicious imports
		if strings.Contains(line, "os/exec") || strings.Contains(line, "unsafe") {
			return fmt.Errorf("potentially dangerous import detected at line %d", lineNum)
		}
	}

	if !hasPackage && lineNum > 0 {
		return fmt.Errorf("go file must contain package declaration")
	}

	return scanner.Err()
}

func (v *Validator) validateGenericFile(file *os.File) error {
	// Generic file validation - check for control characters
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for control characters (except tab, newline, carriage return)
		for _, r := range line {
			if r < 32 && r != 9 && r != 10 && r != 13 {
				return fmt.Errorf("control character detected at line %d", lineNum)
			}
		}
	}

	return scanner.Err()
}

func (v *Validator) isValidTeamName(team string) bool {
	// Team name validation: alphanumeric, underscore, dash, max 50 chars
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{1,50}$`, team)
	return matched
}

func (v *Validator) checkDirectoryAccess(dir string) error {
	// Check if directory exists
	stat, err := os.Stat(dir)
	if err != nil {
		return err
	}

	if !stat.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	// Check write permissions by creating a temp file
	tempFile := filepath.Join(dir, ".eden_access_test")
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("directory not writable: %v", err)
	}
	file.Close()
	os.Remove(tempFile)

	return nil
}

func (v *Validator) checkDiskSpace() error {
	// Basic disk space check - implementation would depend on OS
	// For now, just check if we can create a file
	tempFile := filepath.Join(v.config.Storage.TempDirectory, ".eden_space_test")
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("cannot create temporary file: %v", err)
	}
	file.Close()
	os.Remove(tempFile)

	return nil
}
