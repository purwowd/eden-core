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

// KeyRotationAuditLogger handles audit logging for key rotation events
type KeyRotationAuditLogger struct {
	auditLogger *monitoring.AuditLogger
	enabled     bool
}

// NewKeyRotationAuditLogger creates a new key rotation audit logger
func NewKeyRotationAuditLogger() (*KeyRotationAuditLogger, error) {
	config := map[string]interface{}{
		"log_path": "logs/key_rotation_audit.db",
	}

	auditLogger, err := monitoring.NewAuditLogger(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %v", err)
	}

	return &KeyRotationAuditLogger{
		auditLogger: auditLogger,
		enabled:     true,
	}, nil
}

// LogKeyRotationStart logs the start of a key rotation process
func (kral *KeyRotationAuditLogger) LogKeyRotationStart(keyID string, details map[string]interface{}) error {
	if !kral.enabled {
		return nil
	}

	enrichedDetails := make(map[string]interface{})
	for k, v := range details {
		enrichedDetails[k] = v
	}
	enrichedDetails["phase"] = "rotation_start"
	enrichedDetails["security_level"] = "high"
	enrichedDetails["compliance_required"] = true

	return kral.auditLogger.LogKeyRotationEvent("key_rotation_start", keyID, enrichedDetails)
}

// LogKeyRotationComplete logs successful completion of key rotation
func (kral *KeyRotationAuditLogger) LogKeyRotationComplete(keyID string, details map[string]interface{}) error {
	if !kral.enabled {
		return nil
	}

	enrichedDetails := make(map[string]interface{})
	for k, v := range details {
		enrichedDetails[k] = v
	}
	enrichedDetails["phase"] = "rotation_complete"
	enrichedDetails["status"] = "success"
	enrichedDetails["compliance_verified"] = true

	return kral.auditLogger.LogKeyRotationEvent("key_rotation_complete", keyID, enrichedDetails)
}

// LogKeyRotationFailure logs failure in key rotation process
func (kral *KeyRotationAuditLogger) LogKeyRotationFailure(keyID string, err error, details map[string]interface{}) error {
	if !kral.enabled {
		return nil
	}

	enrichedDetails := make(map[string]interface{})
	for k, v := range details {
		enrichedDetails[k] = v
	}
	enrichedDetails["phase"] = "rotation_failed"
	enrichedDetails["status"] = "failure"
	enrichedDetails["error"] = err.Error()
	enrichedDetails["requires_attention"] = true

	return kral.auditLogger.LogKeyRotationEvent("key_rotation_failure", keyID, enrichedDetails)
}

// LogKeyRotationPolicy logs policy validation events
func (kral *KeyRotationAuditLogger) LogKeyRotationPolicy(keyID string, policyResult string, details map[string]interface{}) error {
	if !kral.enabled {
		return nil
	}

	enrichedDetails := make(map[string]interface{})
	for k, v := range details {
		enrichedDetails[k] = v
	}
	enrichedDetails["phase"] = "policy_check"
	enrichedDetails["policy_result"] = policyResult
	enrichedDetails["compliance_check"] = true

	return kral.auditLogger.LogKeyRotationEvent("key_rotation_policy", keyID, enrichedDetails)
}

// Global audit logger instance
var globalKeyRotationLogger *KeyRotationAuditLogger

// initializeGlobalAuditLogger initializes the global audit logger
func initializeGlobalAuditLogger() {
	if globalKeyRotationLogger == nil {
		logger, err := NewKeyRotationAuditLogger()
		if err != nil {
			log.Printf("Failed to initialize key rotation audit logger: %v", err)
			return
		}
		globalKeyRotationLogger = logger
	}
}

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

// RotateProtectionKey implements secure key rotation with comprehensive audit logging
func RotateProtectionKey(oldKey []byte, config KeyRotationConfig) ([]byte, error) {
	// Initialize audit logger
	initializeGlobalAuditLogger()

	// Generate unique rotation ID for tracking
	rotationID := generateRotationID()

	// Create rotation metadata
	metadata := map[string]interface{}{
		"rotation_id":       rotationID,
		"rotation_time":     time.Now().UTC(),
		"key_hash":          fmt.Sprintf("%x", sha256.Sum256(oldKey)),
		"rotation_interval": config.RotationInterval.String(),
		"retention_period":  config.RetentionPeriod.String(),
		"notify_before":     config.NotifyBefore.String(),
		"emergency_keys":    len(config.EmergencyKeys),
	}

	// Log rotation start
	if globalKeyRotationLogger != nil {
		if err := globalKeyRotationLogger.LogKeyRotationStart(rotationID, metadata); err != nil {
			log.Printf("Failed to log key rotation start: %v", err)
		}
	}

	// Generate new key material
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		rotationErr := fmt.Errorf("failed to generate new key: %v", err)

		// Log failure
		if globalKeyRotationLogger != nil {
			failureMetadata := metadata
			failureMetadata["failure_stage"] = "key_generation"
			globalKeyRotationLogger.LogKeyRotationFailure(rotationID, rotationErr, failureMetadata)
		}

		return nil, rotationErr
	}

	// Derive new key using both old and new material for security
	h := sha256.New()
	h.Write(oldKey)
	h.Write(newKey)
	derivedKey := h.Sum(nil)

	// Update metadata with new key information
	metadata["new_key_hash"] = fmt.Sprintf("%x", sha256.Sum256(derivedKey))
	metadata["valid_until"] = time.Now().Add(config.RotationInterval).Format(time.RFC3339)
	metadata["derivation_method"] = "sha256_combined"

	// Log successful rotation
	if globalKeyRotationLogger != nil {
		if err := globalKeyRotationLogger.LogKeyRotationComplete(rotationID, metadata); err != nil {
			log.Printf("Failed to log key rotation completion: %v", err)
		}
	}

	// Log rotation event for general audit trail
	logKeyRotationAudit(metadata)

	return derivedKey, nil
}

// VerifyKeyRotationPolicy checks if key rotation is needed with enhanced audit logging
func VerifyKeyRotationPolicy(keyData []byte, config KeyRotationConfig) (bool, error) {
	// Initialize audit logger
	initializeGlobalAuditLogger()

	// Generate policy check ID
	policyCheckID := generatePolicyCheckID()

	// Extract key metadata
	metadata, err := extractKeyMetadata(keyData)
	if err != nil {
		policyErr := fmt.Errorf("failed to extract key metadata: %v", err)

		// Log policy check failure
		if globalKeyRotationLogger != nil {
			failureDetails := map[string]interface{}{
				"policy_check_id": policyCheckID,
				"failure_stage":   "metadata_extraction",
				"error":           err.Error(),
			}
			globalKeyRotationLogger.LogKeyRotationFailure(policyCheckID, policyErr, failureDetails)
		}

		return false, policyErr
	}

	// Check if rotation is needed
	rotationTimeStr, ok := metadata["rotation_time"].(string)
	if !ok {
		policyErr := fmt.Errorf("invalid rotation_time format in metadata")

		// Log policy validation failure
		if globalKeyRotationLogger != nil {
			failureDetails := map[string]interface{}{
				"policy_check_id": policyCheckID,
				"failure_stage":   "time_validation",
				"metadata":        metadata,
			}
			globalKeyRotationLogger.LogKeyRotationFailure(policyCheckID, policyErr, failureDetails)
		}

		return false, policyErr
	}

	rotationTime, err := time.Parse(time.RFC3339, rotationTimeStr)
	if err != nil {
		policyErr := fmt.Errorf("invalid rotation time: %v", err)

		// Log policy validation failure
		if globalKeyRotationLogger != nil {
			failureDetails := map[string]interface{}{
				"policy_check_id":   policyCheckID,
				"failure_stage":     "time_parsing",
				"rotation_time_str": rotationTimeStr,
			}
			globalKeyRotationLogger.LogKeyRotationFailure(policyCheckID, policyErr, failureDetails)
		}

		return false, policyErr
	}

	// Calculate time until next rotation
	nextRotation := rotationTime.Add(config.RotationInterval)
	timeUntilRotation := time.Until(nextRotation)
	needsRotation := timeUntilRotation <= 0

	// Create policy result details
	policyDetails := map[string]interface{}{
		"policy_check_id":     policyCheckID,
		"current_time":        time.Now().UTC().Format(time.RFC3339),
		"last_rotation":       rotationTime.Format(time.RFC3339),
		"next_rotation":       nextRotation.Format(time.RFC3339),
		"time_until_rotation": timeUntilRotation.String(),
		"needs_rotation":      needsRotation,
		"rotation_interval":   config.RotationInterval.String(),
		"notify_before":       config.NotifyBefore.String(),
	}

	// Determine policy result
	var policyResult string
	if needsRotation {
		policyResult = "ROTATION_REQUIRED"
	} else if timeUntilRotation <= config.NotifyBefore {
		policyResult = "ROTATION_APPROACHING"
	} else {
		policyResult = "ROTATION_NOT_NEEDED"
	}

	// Log policy check result
	if globalKeyRotationLogger != nil {
		if err := globalKeyRotationLogger.LogKeyRotationPolicy(policyCheckID, policyResult, policyDetails); err != nil {
			log.Printf("Failed to log key rotation policy check: %v", err)
		}
	}

	// If approaching rotation time, send notification
	if timeUntilRotation <= config.NotifyBefore {
		notifyKeyRotationAudit(metadata, policyDetails)
	}

	return needsRotation, nil
}

// logKeyRotationAudit logs key rotation events for comprehensive audit with proper storage
func logKeyRotationAudit(metadata map[string]interface{}) {
	// Enhanced audit logging with structured data
	enrichedMetadata := make(map[string]interface{})
	for k, v := range metadata {
		enrichedMetadata[k] = v
	}
	enrichedMetadata["audit_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	enrichedMetadata["audit_source"] = "key_rotation_system"
	enrichedMetadata["compliance_category"] = "cryptographic_operations"
	enrichedMetadata["regulatory_required"] = true

	// Create audit event
	event := monitoring.AuditEvent{
		ID:        fmt.Sprintf("KEY-ROT-%d", time.Now().UnixNano()),
		Type:      monitoring.EventKeyRotation,
		Timestamp: time.Now().UTC(),
		User:      "system",
		Action:    "key_rotation_completed",
		Resource:  fmt.Sprintf("key-%s", metadata["rotation_id"]),
		Status:    "success",
		Details:   enrichedMetadata,
		Risk:      "HIGH",
	}

	// Store audit event
	if err := monitoring.LogAuditEvent(event); err != nil {
		log.Printf("Failed to log key rotation audit event: %v", err)
	}
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

// notifyKeyRotationAudit sends comprehensive notifications about upcoming key rotation
func notifyKeyRotationAudit(metadata map[string]interface{}, policyDetails map[string]interface{}) {
	// Enhanced notification with audit trail
	notificationDetails := map[string]interface{}{
		"notification_id":   generateNotificationID(),
		"notification_type": "key_rotation_approaching",
		"notification_time": time.Now().UTC().Format(time.RFC3339),
		"key_metadata":      metadata,
		"policy_details":    policyDetails,
		"urgency_level":     "high",
		"action_required":   true,
	}

	// Create notification audit event
	event := monitoring.AuditEvent{
		ID:        fmt.Sprintf("KEY-NOT-%d", time.Now().UnixNano()),
		Type:      monitoring.EventKeyRotation,
		Timestamp: time.Now().UTC(),
		User:      "system",
		Action:    "key_rotation_notification",
		Resource:  fmt.Sprintf("key-%s", metadata["key_id"]),
		Status:    "pending",
		Details:   notificationDetails,
		Risk:      "MEDIUM",
	}

	// Log notification event with audit system
	if err := monitoring.LogAuditEvent(event); err != nil {
		log.Printf("Failed to log key rotation notification audit: %v", err)
	}

	// Send notification to configured channels
	if notifyBefore, ok := metadata["notify_before"].(time.Duration); ok {
		rotationTime := time.Now().Add(notifyBefore)
		details := fmt.Sprintf("Key rotation scheduled for: %s\nKey ID: %s\nPolicy Check: %v",
			rotationTime.Format(time.RFC3339),
			metadata["key_id"],
			policyDetails["policy_check_id"])

		// Send to all emergency contacts
		if contacts, ok := metadata["emergency_contacts"].([]string); ok {
			for _, contact := range contacts {
				sendNotificationAudit(contact, "Key Rotation Scheduled", details, notificationDetails)
			}
		}
	}
}

// sendNotificationAudit sends a notification with proper audit logging
func sendNotificationAudit(contact, subject, details string, auditDetails map[string]interface{}) {
	// Enhanced notification sending with audit trail
	sendDetails := map[string]interface{}{
		"contact":           contact,
		"subject":           subject,
		"details":           details,
		"sent_time":         time.Now().UTC().Format(time.RFC3339),
		"delivery_method":   "system_log", // In production: email/SMS/Slack
		"notification_meta": auditDetails,
	}

	// Log notification delivery attempt
	event := monitoring.AuditEvent{
		ID:        fmt.Sprintf("KEY-SEND-%d", time.Now().UnixNano()),
		Type:      monitoring.EventKeyRotation,
		Timestamp: time.Now().UTC(),
		User:      "system",
		Action:    "notification_sent",
		Resource:  contact,
		Status:    "delivered",
		Details:   sendDetails,
		Risk:      "LOW",
	}

	// Store delivery audit event
	if err := monitoring.LogAuditEvent(event); err != nil {
		log.Printf("Failed to log notification delivery audit: %v", err)
	}

	// For now, just log the notification
	// In production, this would integrate with email/SMS/Slack etc.
	log.Printf("AUDIT NOTIFICATION to %s: %s\n%s", contact, subject, details)
}

// Helper functions for generating unique IDs
func generateRotationID() string {
	return fmt.Sprintf("ROT-%d", time.Now().UnixNano())
}

func generatePolicyCheckID() string {
	return fmt.Sprintf("POL-%d", time.Now().UnixNano())
}

func generateNotificationID() string {
	return fmt.Sprintf("NOT-%d", time.Now().UnixNano())
}
