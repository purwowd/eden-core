// Package crypto - Script system for Eden Core
// Adopting Bitcoin Script for programmable code access conditions
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Script operation codes (similar to Bitcoin Script opcodes)
const (
	// Arithmetic operations
	OP_ADD = "OP_ADD"
	OP_SUB = "OP_SUB"
	OP_MUL = "OP_MUL"
	OP_DIV = "OP_DIV"

	// Comparison operations
	OP_EQUAL       = "OP_EQUAL"
	OP_EQUALVERIFY = "OP_EQUALVERIFY"
	OP_LESSTHAN    = "OP_LESSTHAN"
	OP_GREATERTHAN = "OP_GREATERTHAN"

	// Logical operations
	OP_IF    = "OP_IF"
	OP_ELSE  = "OP_ELSE"
	OP_ENDIF = "OP_ENDIF"
	OP_NOT   = "OP_NOT"
	OP_AND   = "OP_AND"
	OP_OR    = "OP_OR"

	// Stack operations
	OP_DUP  = "OP_DUP"
	OP_DROP = "OP_DROP"
	OP_SWAP = "OP_SWAP"
	OP_ROT  = "OP_ROT"

	// Cryptographic operations
	OP_HASH160       = "OP_HASH160"
	OP_HASH256       = "OP_HASH256"
	OP_CHECKSIG      = "OP_CHECKSIG"
	OP_CHECKMULTISIG = "OP_CHECKMULTISIG"

	// Time operations (Bitcoin-style)
	OP_CHECKLOCKTIMEVERIFY = "OP_CHECKLOCKTIMEVERIFY"
	OP_CHECKSEQUENCEVERIFY = "OP_CHECKSEQUENCEVERIFY"

	// Code access specific operations
	OP_CHECKACCESS    = "OP_CHECKACCESS"
	OP_CHECKTEAM      = "OP_CHECKTEAM"
	OP_CHECKREP       = "OP_CHECKREP" // Check reputation
	OP_CHECKTIME      = "OP_CHECKTIME"
	OP_CHECKCONDITION = "OP_CHECKCONDITION"

	// Control operations
	OP_RETURN = "OP_RETURN"
	OP_VERIFY = "OP_VERIFY"
)

// ScriptEngine represents Bitcoin-style script execution engine
type ScriptEngine struct {
	stack        [][]byte       // Data stack
	altStack     [][]byte       // Alternative stack
	script       []string       // Script operations
	pc           int            // Program counter
	context      *ScriptContext // Execution context
	debugMode    bool           // Debug mode flag
	executionLog []string       // Execution log
}

// ScriptContext provides context for script execution
type ScriptContext struct {
	CodeID          string                 `json:"code_id"`
	RequesterPubKey string                 `json:"requester_pubkey"`
	Timestamp       int64                  `json:"timestamp"`
	BlockHeight     int64                  `json:"block_height"`
	NetworkState    map[string]interface{} `json:"network_state"`
	TeamMembers     []string               `json:"team_members"`
	AccessHistory   []AccessRecord         `json:"access_history"`
}

// AccessRecord represents a historical access record
type AccessRecord struct {
	UserPubKey string `json:"user_pubkey"`
	AccessTime int64  `json:"access_time"`
	AccessType string `json:"access_type"`
	Success    bool   `json:"success"`
}

// ScriptProtection represents script-protected code
type ScriptProtection struct {
	EncryptedData []byte       `json:"encrypted_data"`
	LockScript    string       `json:"lock_script"`    // Script that must evaluate to true
	ScriptHash    string       `json:"script_hash"`    // Hash of lock script
	CodeHash      string       `json:"code_hash"`      // Hash of original code
	CreatorPubKey string       `json:"creator_pubkey"` // Creator's public key
	CreatedAt     int64        `json:"created_at"`     // Creation timestamp
	AccessPolicy  AccessPolicy `json:"access_policy"`  // Access policy configuration
}

// AccessPolicy defines access control policy
type AccessPolicy struct {
	RequireSignature bool         `json:"require_signature"`
	RequireMultiSig  bool         `json:"require_multisig"`
	MinReputation    int          `json:"min_reputation"`
	AllowedTeams     []string     `json:"allowed_teams"`
	TimeRestrictions []TimeWindow `json:"time_restrictions"`
	MaxAccessPerHour int          `json:"max_access_per_hour"`
	RequireApproval  bool         `json:"require_approval"`
}

// TimeWindow represents allowed access time windows
type TimeWindow struct {
	StartHour int   `json:"start_hour"` // 0-23
	EndHour   int   `json:"end_hour"`   // 0-23
	Days      []int `json:"days"`       // 0=Sunday, 1=Monday, etc.
}

// ScriptCrypto implements Bitcoin Script-based cryptography
type ScriptCrypto struct {
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
}

// NewScriptCrypto creates new script-based crypto engine
func NewScriptCrypto() (*ScriptCrypto, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &ScriptCrypto{
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
	}, nil
}

// CreateScriptProtection creates script-protected code
func (sc *ScriptCrypto) CreateScriptProtection(sourceCode []byte, lockScript string, policy AccessPolicy) (*ScriptProtection, error) {
	// Validate script
	if err := validateScript(lockScript); err != nil {
		return nil, fmt.Errorf("invalid lock script: %v", err)
	}

	// Calculate hashes
	codeHash := sha256.Sum256(sourceCode)
	scriptHashSum := sha256.Sum256([]byte(lockScript))

	// Create encryption key from code and script hashes
	keyMaterial := append(codeHash[:], scriptHashSum[:]...)
	encryptionKey := sha256.Sum256(keyMaterial)

	// Encrypt source code
	encryptedData := make([]byte, len(sourceCode))
	for i := range sourceCode {
		encryptedData[i] = sourceCode[i] ^ encryptionKey[i%32]
	}

	protection := &ScriptProtection{
		EncryptedData: encryptedData,
		LockScript:    lockScript,
		ScriptHash:    hex.EncodeToString(scriptHashSum[:]),
		CodeHash:      hex.EncodeToString(codeHash[:]),
		CreatorPubKey: hex.EncodeToString(sc.publicKey.SerializeCompressed()),
		CreatedAt:     getCurrentTimestamp(),
		AccessPolicy:  policy,
	}

	return protection, nil
}

// UnlockScriptProtection unlocks script-protected code
func (sc *ScriptCrypto) UnlockScriptProtection(protection *ScriptProtection, unlockScript string, context *ScriptContext) ([]byte, error) {
	// Create combined script (unlock + lock, Bitcoin-style)
	combinedScript := unlockScript + " " + protection.LockScript

	// Create script engine
	engine := NewScriptEngine(combinedScript, context)
	engine.debugMode = true

	// Execute script
	result, err := engine.Execute()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %v", err)
	}

	if !result {
		return nil, fmt.Errorf("script evaluation returned false")
	}

	// Additional policy checks
	if err := sc.checkAccessPolicy(protection.AccessPolicy, context); err != nil {
		return nil, fmt.Errorf("access policy violation: %v", err)
	}

	// Decrypt source code
	codeHashBytes, _ := hex.DecodeString(protection.CodeHash)
	scriptHashBytes, _ := hex.DecodeString(protection.ScriptHash)
	keyMaterial := append(codeHashBytes, scriptHashBytes...)
	encryptionKey := sha256.Sum256(keyMaterial)

	decryptedData := make([]byte, len(protection.EncryptedData))
	for i := range protection.EncryptedData {
		decryptedData[i] = protection.EncryptedData[i] ^ encryptionKey[i%32]
	}

	// Verify integrity
	decryptedHash := sha256.Sum256(decryptedData)
	if hex.EncodeToString(decryptedHash[:]) != protection.CodeHash {
		return nil, fmt.Errorf("integrity check failed")
	}

	return decryptedData, nil
}

// NewScriptEngine creates new script execution engine
func NewScriptEngine(script string, context *ScriptContext) *ScriptEngine {
	operations := strings.Fields(script)

	return &ScriptEngine{
		stack:        make([][]byte, 0),
		altStack:     make([][]byte, 0),
		script:       operations,
		pc:           0,
		context:      context,
		debugMode:    false,
		executionLog: make([]string, 0),
	}
}

// Execute executes the script and returns true if successful
func (se *ScriptEngine) Execute() (bool, error) {
	for se.pc < len(se.script) {
		op := se.script[se.pc]

		if se.debugMode {
			se.executionLog = append(se.executionLog, fmt.Sprintf("PC:%d OP:%s STACK:%d", se.pc, op, len(se.stack)))
		}

		if err := se.executeOperation(op); err != nil {
			return false, err
		}

		se.pc++
	}

	// Check final stack state
	if len(se.stack) == 0 {
		return false, fmt.Errorf("empty stack at end of execution")
	}

	// Top stack element should be true (non-zero)
	top := se.stack[len(se.stack)-1]
	return !isZero(top), nil
}

// executeOperation executes a single script operation
func (se *ScriptEngine) executeOperation(op string) error {
	switch op {
	// Data operations
	case OP_DUP:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_DUP: insufficient stack items")
		}
		top := se.stack[len(se.stack)-1]
		se.stack = append(se.stack, top)

	case OP_DROP:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_DROP: insufficient stack items")
		}
		se.stack = se.stack[:len(se.stack)-1]

	// Comparison operations
	case OP_EQUAL:
		if len(se.stack) < 2 {
			return fmt.Errorf("OP_EQUAL: insufficient stack items")
		}
		a := se.stack[len(se.stack)-2]
		b := se.stack[len(se.stack)-1]
		se.stack = se.stack[:len(se.stack)-2]

		if string(a) == string(b) {
			se.stack = append(se.stack, []byte{1})
		} else {
			se.stack = append(se.stack, []byte{0})
		}

	case OP_EQUALVERIFY:
		if err := se.executeOperation(OP_EQUAL); err != nil {
			return err
		}
		return se.executeOperation(OP_VERIFY)

	case OP_VERIFY:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_VERIFY: insufficient stack items")
		}
		top := se.stack[len(se.stack)-1]
		se.stack = se.stack[:len(se.stack)-1]

		if isZero(top) {
			return fmt.Errorf("OP_VERIFY: verification failed")
		}

	// Cryptographic operations
	case OP_HASH256:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_HASH256: insufficient stack items")
		}
		data := se.stack[len(se.stack)-1]
		se.stack = se.stack[:len(se.stack)-1]

		hash := sha256.Sum256(data)
		se.stack = append(se.stack, hash[:])

	case OP_CHECKSIG:
		if len(se.stack) < 2 {
			return fmt.Errorf("OP_CHECKSIG: insufficient stack items")
		}
		pubKeyBytes := se.stack[len(se.stack)-2]
		sigBytes := se.stack[len(se.stack)-1]
		se.stack = se.stack[:len(se.stack)-2]

		// Verify signature
		result := se.verifySignature(pubKeyBytes, sigBytes)
		if result {
			se.stack = append(se.stack, []byte{1})
		} else {
			se.stack = append(se.stack, []byte{0})
		}

	// Time operations (Bitcoin-style)
	case OP_CHECKLOCKTIMEVERIFY:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_CHECKLOCKTIMEVERIFY: insufficient stack items")
		}
		lockTimeBytes := se.stack[len(se.stack)-1]
		lockTime, err := strconv.ParseInt(string(lockTimeBytes), 10, 64)
		if err != nil {
			return fmt.Errorf("OP_CHECKLOCKTIMEVERIFY: invalid lock time")
		}

		if se.context.Timestamp < lockTime {
			return fmt.Errorf("OP_CHECKLOCKTIMEVERIFY: lock time not reached")
		}

	// Code access specific operations
	case OP_CHECKACCESS:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_CHECKACCESS: insufficient stack items")
		}
		requiredAccess := string(se.stack[len(se.stack)-1])
		se.stack = se.stack[:len(se.stack)-1]

		hasAccess := se.checkUserAccess(requiredAccess)
		if hasAccess {
			se.stack = append(se.stack, []byte{1})
		} else {
			se.stack = append(se.stack, []byte{0})
		}

	case OP_CHECKTEAM:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_CHECKTEAM: insufficient stack items")
		}
		teamName := string(se.stack[len(se.stack)-1])
		se.stack = se.stack[:len(se.stack)-1]

		isTeamMember := se.checkTeamMembership(teamName)
		if isTeamMember {
			se.stack = append(se.stack, []byte{1})
		} else {
			se.stack = append(se.stack, []byte{0})
		}

	case OP_CHECKREP:
		if len(se.stack) < 1 {
			return fmt.Errorf("OP_CHECKREP: insufficient stack items")
		}
		minRepBytes := se.stack[len(se.stack)-1]
		se.stack = se.stack[:len(se.stack)-1]

		minRep, err := strconv.Atoi(string(minRepBytes))
		if err != nil {
			return fmt.Errorf("OP_CHECKREP: invalid reputation value")
		}

		userRep := se.getUserReputation()
		if userRep >= minRep {
			se.stack = append(se.stack, []byte{1})
		} else {
			se.stack = append(se.stack, []byte{0})
		}

	default:
		// Check if it's a data push (not an operation)
		if !strings.HasPrefix(op, "OP_") {
			// Push data onto stack
			se.stack = append(se.stack, []byte(op))
		} else {
			return fmt.Errorf("unknown operation: %s", op)
		}
	}

	return nil
}

// Predefined script templates

// CreateSimpleSignatureScript creates a simple signature verification script
func CreateSimpleSignatureScript(pubKeyHex string) string {
	return fmt.Sprintf("%s OP_CHECKSIG", pubKeyHex)
}

// CreateMultiSigScript creates a multi-signature script (M-of-N)
func CreateMultiSigScript(m int, pubKeys []string) string {
	script := fmt.Sprintf("%d", m)
	for _, pubKey := range pubKeys {
		script += " " + pubKey
	}
	script += fmt.Sprintf(" %d OP_CHECKMULTISIG", len(pubKeys))
	return script
}

// CreateTimeLockScript creates a time-locked script
func CreateTimeLockScript(unlockTime int64, pubKeyHex string) string {
	return fmt.Sprintf("%d OP_CHECKLOCKTIMEVERIFY OP_DROP %s OP_CHECKSIG", unlockTime, pubKeyHex)
}

// CreateTeamAccessScript creates a team-based access script
func CreateTeamAccessScript(teamName string, minReputation int) string {
	return fmt.Sprintf("%s OP_CHECKTEAM %d OP_CHECKREP OP_AND", teamName, minReputation)
}

// CreateConditionalScript creates a conditional access script
func CreateConditionalScript(condition string, trueBranch string, falseBranch string) string {
	return fmt.Sprintf("%s OP_IF %s OP_ELSE %s OP_ENDIF", condition, trueBranch, falseBranch)
}

// CreateEnterpriseAccessScript creates enterprise-grade access script
func CreateEnterpriseAccessScript(teamName string, minRep int, timeWindow string, requireMultiSig bool) string {
	script := fmt.Sprintf("%s OP_CHECKTEAM %d OP_CHECKREP OP_AND", teamName, minRep)

	if timeWindow != "" {
		script += fmt.Sprintf(" %s OP_CHECKTIME OP_AND", timeWindow)
	}

	if requireMultiSig {
		script += " 2 OP_CHECKMULTISIG OP_AND"
	}

	return script
}

// Utility functions

func (se *ScriptEngine) verifySignature(pubKeyBytes, sigBytes []byte) bool {
	// Parse public key
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false
	}

	// Parse signature
	sig, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return false
	}

	// Create message hash (simplified)
	messageHash := sha256.Sum256([]byte(se.context.CodeID + se.context.RequesterPubKey))

	return sig.Verify(messageHash[:], pubKey)
}

func (se *ScriptEngine) checkUserAccess(accessType string) bool {
	// Mock implementation - check if user has required access type
	switch accessType {
	case "read":
		return true // Everyone can read
	case "write":
		return se.checkTeamMembership("developers")
	case "execute":
		return se.getUserReputation() >= 50
	case "admin":
		return se.checkTeamMembership("admins")
	default:
		return false
	}
}

func (se *ScriptEngine) checkTeamMembership(teamName string) bool {
	// Check if team membership info exists in NetworkState
	if teamData, exists := se.context.NetworkState[teamName]; exists {
		if teamMembers, ok := teamData.([]string); ok {
			for _, member := range teamMembers {
				if member == se.context.RequesterPubKey {
					return true
				}
			}
		}
	}

	// Fallback: check if user is in general team members list
	for _, member := range se.context.TeamMembers {
		if member == se.context.RequesterPubKey {
			return true
		}
	}
	return false
}

func (se *ScriptEngine) getUserReputation() int {
	// Mock reputation calculation based on access history
	successCount := 0
	totalAccess := 0

	for _, record := range se.context.AccessHistory {
		if record.UserPubKey == se.context.RequesterPubKey {
			totalAccess++
			if record.Success {
				successCount++
			}
		}
	}

	if totalAccess == 0 {
		return 100 // New users start with neutral reputation
	}

	return (successCount * 100) / totalAccess
}

func (sc *ScriptCrypto) checkAccessPolicy(policy AccessPolicy, context *ScriptContext) error {
	// Check time restrictions
	if len(policy.TimeRestrictions) > 0 {
		currentTime := time.Unix(context.Timestamp, 0)
		allowed := false

		for _, window := range policy.TimeRestrictions {
			hour := currentTime.Hour()
			day := int(currentTime.Weekday())

			if hour >= window.StartHour && hour <= window.EndHour {
				for _, allowedDay := range window.Days {
					if day == allowedDay {
						allowed = true
						break
					}
				}
			}
		}

		if !allowed {
			return fmt.Errorf("access not allowed during current time window")
		}
	}

	// Check reputation requirement
	if policy.MinReputation > 0 {
		engine := NewScriptEngine("", context)
		userRep := engine.getUserReputation()
		if userRep < policy.MinReputation {
			return fmt.Errorf("insufficient reputation: %d < %d", userRep, policy.MinReputation)
		}
	}

	return nil
}

func validateScript(script string) error {
	operations := strings.Fields(script)

	for _, op := range operations {
		if strings.HasPrefix(op, "OP_") {
			// Validate known operations
			switch op {
			case OP_ADD, OP_SUB, OP_EQUAL, OP_CHECKSIG, OP_CHECKACCESS, OP_CHECKTEAM, OP_CHECKREP:
				// Valid operations
			default:
				return fmt.Errorf("unknown operation: %s", op)
			}
		}
	}

	return nil
}

func isZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// GetMyPublicKey returns our public key
func (sc *ScriptCrypto) GetMyPublicKey() string {
	return hex.EncodeToString(sc.publicKey.SerializeCompressed())
}

// GetExecutionLog returns script execution log for debugging
func (se *ScriptEngine) GetExecutionLog() []string {
	return se.executionLog
}
