package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeySize is the size of encryption keys in bytes
	KeySize = 32
	// SaltSize is the size of salt used in key derivation
	SaltSize = 16
	// Iterations is the number of iterations for key derivation
	Iterations = 10000
)

// GenerateMultiAuthKey generates a key for multi-authentication protection
func GenerateMultiAuthKey(teams []string) ([]byte, error) {
	// Create a deterministic key based on team names and current time
	var combinedTeams string
	for _, team := range teams {
		combinedTeams += team
	}

	// Add salt for additional security
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Create key material
	keyMaterial := fmt.Sprintf("multiauth:%s:%s", combinedTeams, hex.EncodeToString(salt))
	hash := sha256.Sum256([]byte(keyMaterial))

	return hash[:], nil
}

// GenerateTimeLockKey generates a key for time-lock protection
func GenerateTimeLockKey(duration string) ([]byte, error) {
	// Try parse as duration (relative)
	if lockDuration, err := time.ParseDuration(duration); err == nil {
		expirationTime := time.Now().Add(lockDuration)
		// Add randomness for security
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}
		keyMaterial := fmt.Sprintf("timelock:%d:%s:%s",
			expirationTime.Unix(), duration, hex.EncodeToString(nonce))
		hash := sha256.Sum256([]byte(keyMaterial))
		return hash[:], nil
	}
	// Try parse as absolute time (RFC3339)
	if t, err := time.Parse(time.RFC3339, duration); err == nil {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}
		keyMaterial := fmt.Sprintf("timelock-abs:%d:%s:%s",
			t.Unix(), duration, hex.EncodeToString(nonce))
		hash := sha256.Sum256([]byte(keyMaterial))
		return hash[:], nil
	}
	return nil, fmt.Errorf("invalid duration or absolute time format: %s", duration)
}

// GenerateOwnershipKey generates a key for ownership protection
func GenerateOwnershipKey(ownerKey string) ([]byte, error) {
	if ownerKey == "" {
		// Generate a new ownership key if none provided
		ownerKeyBytes := make([]byte, 32)
		if _, err := rand.Read(ownerKeyBytes); err != nil {
			return nil, fmt.Errorf("failed to generate owner key: %v", err)
		}
		ownerKey = hex.EncodeToString(ownerKeyBytes)
	}

	// Create ownership-based key
	keyMaterial := fmt.Sprintf("ownership:%s", ownerKey)
	hash := sha256.Sum256([]byte(keyMaterial))

	return hash[:], nil
}

// GeneratePolicyScriptKey generates a key for policy script protection
func GeneratePolicyScriptKey(scriptContent string) ([]byte, error) {
	if scriptContent == "" {
		// Use default policy if none provided
		scriptContent = "default_policy_allow_execution"
	}

	// Create script-based key
	scriptHash := sha256.Sum256([]byte(scriptContent))

	// Add randomness for additional security
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Combine script hash with random data
	keyMaterial := fmt.Sprintf("policyscript:%s:%s",
		hex.EncodeToString(scriptHash[:]), hex.EncodeToString(randomBytes))
	hash := sha256.Sum256([]byte(keyMaterial))

	return hash[:], nil
}

// ValidateTimeLockKey validates if a time-lock key is still valid
func ValidateTimeLockKey(keyData []byte, duration string) error {
	// This would implement actual time-lock validation
	// For now, return nil (always valid)
	return nil
}

// ValidateMultiAuthKey validates multi-auth key with team membership
func ValidateMultiAuthKey(keyData []byte, teams []string, currentUser string) error {
	// This would implement actual multi-auth validation
	// For now, return nil (always valid)
	return nil
}

// ValidateOwnershipKey validates ownership key
func ValidateOwnershipKey(keyData []byte, ownerKey string) error {
	// This would implement actual ownership validation
	// For now, return nil (always valid)
	return nil
}

// ValidatePolicyScriptKey validates policy script key
func ValidatePolicyScriptKey(keyData []byte, scriptContent string) error {
	// This would implement actual policy script validation
	// For now, return nil (always valid)
	return nil
}

// GenerateKey generates a new random key
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateKeyPair generates a pair of public and private keys
func GenerateKeyPair() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	// Generate public key (in this simple implementation, we'll derive it from private key)
	publicKey := sha256.Sum256(privateKey)
	return publicKey[:], privateKey, nil
}

// DeriveKey derives a key from a password and salt using PBKDF2
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("empty password")
	}

	// If salt is too short, extend it
	if len(salt) < SaltSize {
		newSalt := make([]byte, SaltSize)
		copy(newSalt, salt)
		for i := len(salt); i < SaltSize; i++ {
			newSalt[i] = byte(i)
		}
		salt = newSalt
	}

	return pbkdf2.Key(password, salt, Iterations, KeySize, sha256.New), nil
}
