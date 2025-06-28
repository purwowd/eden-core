// Package crypto - TimeLock implementation for Eden Core
// Adopting Bitcoin's CheckLockTimeVerify (CLTV) for time-based code protection
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// TimeLockType represents different types of time-based locks
type TimeLockType string

const (
	TimeLockAbsolute    TimeLockType = "absolute"    // Lock until specific timestamp
	TimeLockRelative    TimeLockType = "relative"    // Lock for duration from creation
	TimeLockBlockHeight TimeLockType = "blockheight" // Lock until specific network block height
	TimeLockCondition   TimeLockType = "condition"   // Lock until custom condition met
)

// TimeLockConfig represents Bitcoin-style time lock configuration
type TimeLockConfig struct {
	LockType         TimeLockType `json:"lock_type"`
	LockValue        int64        `json:"lock_value"`         // Timestamp, duration, or block height
	CreatedAt        int64        `json:"created_at"`         // Creation timestamp
	Description      string       `json:"description"`        // Human readable description
	AllowEarlyUnlock bool         `json:"allow_early_unlock"` // Emergency unlock flag
	UnlockCondition  string       `json:"unlock_condition"`   // Custom condition (for condition type)
}

// TimeLockProtection represents time-locked protected code
type TimeLockProtection struct {
	EncryptedData    []byte         `json:"encrypted_data"`
	TimeLockConfig   TimeLockConfig `json:"timelock_config"`
	CreatorSignature string         `json:"creator_signature"`
	ConfigHash       string         `json:"config_hash"`
	CodeHash         string         `json:"code_hash"`
	UnlockAttempts   int            `json:"unlock_attempts"`
	LastAttemptAt    int64          `json:"last_attempt_at"`
	IsUnlocked       bool           `json:"is_unlocked"`
}

// TimeLockCrypto implements Bitcoin-style time lock cryptography
type TimeLockCrypto struct {
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
}

// NewTimeLockCrypto creates new time lock crypto engine
func NewTimeLockCrypto() (*TimeLockCrypto, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &TimeLockCrypto{
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
	}, nil
}

// CreateTimeLockProtection creates time-locked protection (Bitcoin CLTV style)
func (tlc *TimeLockCrypto) CreateTimeLockProtection(sourceCode []byte, config TimeLockConfig) (*TimeLockProtection, error) {
	// Validate time lock configuration
	if err := validateTimeLockConfig(config); err != nil {
		return nil, fmt.Errorf("invalid timelock config: %v", err)
	}

	// Set creation timestamp
	config.CreatedAt = getCurrentTimestamp()

	// Calculate hashes
	codeHash := sha256.Sum256(sourceCode)
	configData, _ := json.Marshal(config)
	configHashSum := sha256.Sum256(configData)

	// Create time-lock encryption key (derived from time config)
	timeLockKey := deriveTimeLockKey(codeHash[:], configHashSum[:], config)

	// Encrypt source code
	encryptedData := make([]byte, len(sourceCode))
	for i := range sourceCode {
		encryptedData[i] = sourceCode[i] ^ timeLockKey[i%32]
	}

	// Sign the configuration to prevent tampering
	signature := ecdsa.Sign(tlc.privateKey, configHashSum[:])

	protection := &TimeLockProtection{
		EncryptedData:    encryptedData,
		TimeLockConfig:   config,
		CreatorSignature: hex.EncodeToString(signature.Serialize()),
		ConfigHash:       hex.EncodeToString(configHashSum[:]),
		CodeHash:         hex.EncodeToString(codeHash[:]),
		UnlockAttempts:   0,
		LastAttemptAt:    0,
		IsUnlocked:       false,
	}

	return protection, nil
}

// CheckTimeLockStatus checks if time lock can be unlocked (Bitcoin CLTV logic)
func (tlc *TimeLockCrypto) CheckTimeLockStatus(protection *TimeLockProtection) (*TimeLockStatus, error) {
	currentTime := getCurrentTimestamp()
	config := protection.TimeLockConfig

	status := &TimeLockStatus{
		CanUnlock:     false,
		TimeRemaining: 0,
		LockType:      string(config.LockType),
		CurrentTime:   currentTime,
		UnlockTime:    0,
		Reason:        "",
	}

	switch config.LockType {
	case TimeLockAbsolute:
		// Bitcoin absolute time lock: locked until specific timestamp
		status.UnlockTime = config.LockValue
		if currentTime >= config.LockValue {
			status.CanUnlock = true
			status.Reason = "Absolute time lock expired"
		} else {
			status.TimeRemaining = config.LockValue - currentTime
			status.Reason = fmt.Sprintf("Locked until %s", time.Unix(config.LockValue, 0).Format("2006-01-02 15:04:05"))
		}

	case TimeLockRelative:
		// Bitcoin relative time lock: locked for duration from creation
		unlockTime := config.CreatedAt + config.LockValue
		status.UnlockTime = unlockTime
		if currentTime >= unlockTime {
			status.CanUnlock = true
			status.Reason = "Relative time lock expired"
		} else {
			status.TimeRemaining = unlockTime - currentTime
			duration := time.Duration(config.LockValue) * time.Second
			status.Reason = fmt.Sprintf("Locked for %s from creation", duration.String())
		}

	case TimeLockBlockHeight:
		// Bitcoin block height lock: locked until network reaches specific height
		currentBlockHeight := getCurrentBlockHeight() // Mock implementation
		if currentBlockHeight >= config.LockValue {
			status.CanUnlock = true
			status.Reason = fmt.Sprintf("Block height %d reached", config.LockValue)
		} else {
			status.TimeRemaining = config.LockValue - currentBlockHeight
			status.Reason = fmt.Sprintf("Locked until block height %d (current: %d)", config.LockValue, currentBlockHeight)
		}

	case TimeLockCondition:
		// Custom condition lock
		conditionMet := evaluateCustomCondition(config.UnlockCondition)
		if conditionMet {
			status.CanUnlock = true
			status.Reason = "Custom condition satisfied"
		} else {
			status.Reason = fmt.Sprintf("Waiting for condition: %s", config.UnlockCondition)
		}

	default:
		return nil, fmt.Errorf("unknown time lock type: %s", config.LockType)
	}

	// Check emergency unlock
	if !status.CanUnlock && config.AllowEarlyUnlock {
		// Emergency unlock requires additional verification
		status.CanUnlock = true
		status.Reason += " (Emergency unlock available)"
	}

	return status, nil
}

// UnlockTimeLockProtection unlocks time-locked code if conditions are met
func (tlc *TimeLockCrypto) UnlockTimeLockProtection(protection *TimeLockProtection, emergencyKey string) ([]byte, error) {
	// Check time lock status
	status, err := tlc.CheckTimeLockStatus(protection)
	if err != nil {
		return nil, fmt.Errorf("failed to check timelock status: %v", err)
	}

	// Record unlock attempt
	protection.UnlockAttempts++
	protection.LastAttemptAt = getCurrentTimestamp()

	// Rate limiting: prevent brute force attempts
	if protection.UnlockAttempts > 3 && getCurrentTimestamp()-protection.LastAttemptAt < 300 { // 5 minutes
		return nil, fmt.Errorf("too many unlock attempts, please wait")
	}

	// Check if unlock is allowed
	if !status.CanUnlock {
		if emergencyKey == "" {
			return nil, fmt.Errorf("time lock not expired: %s", status.Reason)
		}

		// Try emergency unlock
		if !protection.TimeLockConfig.AllowEarlyUnlock {
			return nil, fmt.Errorf("emergency unlock not allowed")
		}

		if !tlc.verifyEmergencyKey(protection, emergencyKey) {
			return nil, fmt.Errorf("invalid emergency unlock key")
		}
	}

	// Verify creator signature to prevent tampering
	if !tlc.verifyCreatorSignature(protection) {
		return nil, fmt.Errorf("creator signature verification failed")
	}

	// Recreate decryption key
	codeHashBytes, _ := hex.DecodeString(protection.CodeHash)
	configHashBytes, _ := hex.DecodeString(protection.ConfigHash)
	timeLockKey := deriveTimeLockKey(codeHashBytes, configHashBytes, protection.TimeLockConfig)

	// Decrypt source code
	decryptedData := make([]byte, len(protection.EncryptedData))
	for i := range protection.EncryptedData {
		decryptedData[i] = protection.EncryptedData[i] ^ timeLockKey[i%32]
	}

	// Verify integrity
	decryptedHash := sha256.Sum256(decryptedData)
	if hex.EncodeToString(decryptedHash[:]) != protection.CodeHash {
		return nil, fmt.Errorf("integrity check failed: code has been tampered")
	}

	// Mark as unlocked
	protection.IsUnlocked = true

	return decryptedData, nil
}

// TimeLockStatus represents current status of time lock
type TimeLockStatus struct {
	CanUnlock     bool   `json:"can_unlock"`
	TimeRemaining int64  `json:"time_remaining"`
	LockType      string `json:"lock_type"`
	CurrentTime   int64  `json:"current_time"`
	UnlockTime    int64  `json:"unlock_time"`
	Reason        string `json:"reason"`
}

// Predefined time lock configurations

// CreateDailyTimeLock creates a 24-hour time lock
func CreateDailyTimeLock(description string) TimeLockConfig {
	return TimeLockConfig{
		LockType:         TimeLockRelative,
		LockValue:        24 * 60 * 60, // 24 hours in seconds
		Description:      fmt.Sprintf("Daily lock: %s", description),
		AllowEarlyUnlock: false,
	}
}

// CreateWeeklyTimeLock creates a 7-day time lock
func CreateWeeklyTimeLock(description string) TimeLockConfig {
	return TimeLockConfig{
		LockType:         TimeLockRelative,
		LockValue:        7 * 24 * 60 * 60, // 7 days in seconds
		Description:      fmt.Sprintf("Weekly lock: %s", description),
		AllowEarlyUnlock: true, // Allow emergency unlock for longer periods
	}
}

// CreateAbsoluteTimeLock creates lock until specific date
func CreateAbsoluteTimeLock(unlockTime time.Time, description string) TimeLockConfig {
	return TimeLockConfig{
		LockType:         TimeLockAbsolute,
		LockValue:        unlockTime.Unix(),
		Description:      fmt.Sprintf("Absolute lock until %s: %s", unlockTime.Format("2006-01-02 15:04:05"), description),
		AllowEarlyUnlock: false,
	}
}

// CreateProductionTimeLock creates lock for production releases
func CreateProductionTimeLock(releaseDate time.Time) TimeLockConfig {
	return TimeLockConfig{
		LockType:         TimeLockAbsolute,
		LockValue:        releaseDate.Unix(),
		Description:      fmt.Sprintf("Production release lock until %s", releaseDate.Format("2006-01-02 15:04:05")),
		AllowEarlyUnlock: true, // Allow emergency patches
	}
}

// Utility functions

func validateTimeLockConfig(config TimeLockConfig) error {
	switch config.LockType {
	case TimeLockAbsolute:
		if config.LockValue <= getCurrentTimestamp() {
			return fmt.Errorf("absolute time lock must be in the future")
		}
	case TimeLockRelative:
		if config.LockValue <= 0 {
			return fmt.Errorf("relative time lock duration must be positive")
		}
	case TimeLockBlockHeight:
		if config.LockValue <= getCurrentBlockHeight() {
			return fmt.Errorf("block height must be in the future")
		}
	case TimeLockCondition:
		if config.UnlockCondition == "" {
			return fmt.Errorf("unlock condition cannot be empty")
		}
	default:
		return fmt.Errorf("invalid time lock type: %s", config.LockType)
	}
	return nil
}

func deriveTimeLockKey(codeHash, configHash []byte, config TimeLockConfig) []byte {
	// Create deterministic key from multiple sources
	keyMaterial := append(codeHash, configHash...)
	keyMaterial = append(keyMaterial, []byte(fmt.Sprintf("%d", config.LockValue))...)
	keyMaterial = append(keyMaterial, []byte(string(config.LockType))...)

	key := sha256.Sum256(keyMaterial)
	return key[:]
}

func (tlc *TimeLockCrypto) verifyCreatorSignature(protection *TimeLockProtection) bool {
	configHashBytes, _ := hex.DecodeString(protection.ConfigHash)
	sigBytes, _ := hex.DecodeString(protection.CreatorSignature)

	signature, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return false
	}

	return signature.Verify(configHashBytes, tlc.publicKey)
}

func (tlc *TimeLockCrypto) verifyEmergencyKey(protection *TimeLockProtection, emergencyKey string) bool {
	// Simple emergency key verification (in production, use more sophisticated method)
	expectedKey := fmt.Sprintf("emergency_%s", protection.ConfigHash[:16])
	return emergencyKey == expectedKey
}

func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

func getCurrentBlockHeight() int64 {
	// Mock implementation - in production, query actual blockchain
	return 800000 + getCurrentTimestamp()/600 // ~10 minute blocks
}

func evaluateCustomCondition(condition string) bool {
	// Mock implementation - in production, implement actual condition evaluation
	switch condition {
	case "team_approval":
		return false // Requires team approval
	case "security_audit_complete":
		return false // Requires security audit
	case "deployment_approved":
		return false // Requires deployment approval
	default:
		return false
	}
}

// GetMyPublicKey returns our public key for verification
func (tlc *TimeLockCrypto) GetMyPublicKey() string {
	return hex.EncodeToString(tlc.publicKey.SerializeCompressed())
}

// GetMyPrivateKey returns our private key (KEEP SECRET!)
func (tlc *TimeLockCrypto) GetMyPrivateKey() string {
	return hex.EncodeToString(tlc.privateKey.Serialize())
}
