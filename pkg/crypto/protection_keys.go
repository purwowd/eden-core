package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/purwowd/eden-core/pkg/monitoring"
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

// KeyRotationConfig represents configuration for automatic key rotation
type KeyRotationConfig struct {
	RotationInterval time.Duration // How often keys should be rotated
	RetentionPeriod  time.Duration // How long to keep old keys
	EmergencyKeys    []string      // Backup keys for emergency access
	NotifyBefore     time.Duration // Notification period before rotation
}

// RotateProtectionKey implements secure key rotation
func RotateProtectionKey(oldKey []byte, config KeyRotationConfig) ([]byte, error) {
	// Generate new key material
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, fmt.Errorf("failed to generate new key: %v", err)
	}

	// Derive new key using both old and new material for security
	h := sha256.New()
	h.Write(oldKey)
	h.Write(newKey)
	derivedKey := h.Sum(nil)

	// Store key metadata for audit
	metadata := map[string]interface{}{
		"rotation_time": time.Now().UTC(),
		"key_hash":      fmt.Sprintf("%x", sha256.Sum256(derivedKey)),
		"valid_until":   time.Now().Add(config.RotationInterval),
	}

	// Log rotation event (implement audit logging)
	logKeyRotation(metadata)

	return derivedKey, nil
}

// VerifyKeyRotationPolicy checks if key rotation is needed
func VerifyKeyRotationPolicy(keyData []byte, config KeyRotationConfig) (bool, error) {
	// Extract key metadata
	metadata, err := extractKeyMetadata(keyData)
	if err != nil {
		return false, fmt.Errorf("failed to extract key metadata: %v", err)
	}

	// Check if rotation is needed
	rotationTimeStr, ok := metadata["rotation_time"].(string)
	if !ok {
		return false, fmt.Errorf("invalid rotation_time format in metadata")
	}

	rotationTime, err := time.Parse(time.RFC3339, rotationTimeStr)
	if err != nil {
		return false, fmt.Errorf("invalid rotation time: %v", err)
	}

	// Calculate time until next rotation
	nextRotation := rotationTime.Add(config.RotationInterval)
	timeUntilRotation := time.Until(nextRotation)

	// Check if rotation is needed
	needsRotation := timeUntilRotation <= 0

	// If approaching rotation time, send notification
	if timeUntilRotation <= config.NotifyBefore {
		notifyKeyRotation(metadata)
	}

	return needsRotation, nil
}

// logKeyRotation logs key rotation events for audit
func logKeyRotation(metadata map[string]interface{}) {
	// TODO: Implement proper audit logging
	log.Printf("Key rotation event: %+v", metadata)
}

// extractKeyMetadata extracts metadata from key data
func extractKeyMetadata(keyData []byte) (map[string]interface{}, error) {
	// Key format: [32 bytes key][metadata length][metadata json]
	if len(keyData) < 33 { // At least key + 1 byte length
		return nil, fmt.Errorf("invalid key data format")
	}

	metadataLen := int(keyData[32]) // Length byte after key
	if len(keyData) < 33+metadataLen {
		return nil, fmt.Errorf("truncated key data")
	}

	metadata := make(map[string]interface{})
	if err := json.Unmarshal(keyData[33:33+metadataLen], &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse key metadata: %v", err)
	}

	return metadata, nil
}

// notifyKeyRotation sends notifications about upcoming key rotation
func notifyKeyRotation(metadata map[string]interface{}) {
	// Create notification event
	event := monitoring.AuditEvent{
		ID:        fmt.Sprintf("KEY-ROT-%d", time.Now().UnixNano()),
		Type:      monitoring.EventKeyRotation,
		Timestamp: time.Now().UTC(),
		Action:    "key_rotation_notification",
		Resource:  metadata["key_id"].(string),
		Status:    "pending",
		Details:   metadata,
		Risk:      "MEDIUM",
	}

	// Log notification event
	if err := monitoring.LogAuditEvent(event); err != nil {
		log.Printf("Failed to log key rotation notification: %v", err)
	}

	// Send notification to configured channels
	if notifyBefore, ok := metadata["notify_before"].(time.Duration); ok {
		rotationTime := time.Now().Add(notifyBefore)
		details := fmt.Sprintf("Key rotation scheduled for: %s\nKey ID: %s",
			rotationTime.Format(time.RFC3339),
			metadata["key_id"])

		// Send to all emergency contacts
		if contacts, ok := metadata["emergency_contacts"].([]string); ok {
			for _, contact := range contacts {
				sendNotification(contact, "Key Rotation Scheduled", details)
			}
		}
	}
}

// sendNotification sends a notification to a specific contact
func sendNotification(contact, subject, details string) {
	// For now, just log the notification
	// In production, this would integrate with email/SMS/Slack etc.
	log.Printf("NOTIFICATION to %s: %s\n%s", contact, subject, details)
}
