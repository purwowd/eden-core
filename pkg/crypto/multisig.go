// Package crypto - MultiSig implementation for Eden Core
// Adopting Bitcoin's multi-signature technology for source code protection
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// MultiSigConfig represents multi-signature configuration (M-of-N)
type MultiSigConfig struct {
	RequiredSignatures int      `json:"required_signatures"` // M (minimum required)
	TotalSigners       int      `json:"total_signers"`       // N (total possible)
	PublicKeys         []string `json:"public_keys"`         // All signer public keys
	Description        string   `json:"description"`         // Human readable description
}

// MultiSigProtection represents Bitcoin-style multi-signature protected code
type MultiSigProtection struct {
	EncryptedData []byte          `json:"encrypted_data"`
	ConfigHash    string          `json:"config_hash"` // Hash of MultiSig config
	Signatures    []MultiSigEntry `json:"signatures"`  // Collected signatures
	Threshold     int             `json:"threshold"`   // Required signature count
	CodeHash      string          `json:"code_hash"`   // SHA-256 of original code
	Timestamp     int64           `json:"timestamp"`   // Protection timestamp
}

// MultiSigEntry represents a single signature in the multi-sig scheme
type MultiSigEntry struct {
	SignerPubKey string `json:"signer_pubkey"` // Public key of signer
	Signature    string `json:"signature"`     // ECDSA signature
	SignedAt     int64  `json:"signed_at"`     // Signature timestamp
	NodeID       string `json:"node_id"`       // Network node identifier
}

// MultiSigCrypto implements Bitcoin-style multi-signature cryptography
type MultiSigCrypto struct {
	config     *MultiSigConfig
	privateKey *btcec.PrivateKey // Our private key for signing
	publicKey  *btcec.PublicKey  // Our public key
}

// NewMultiSigCrypto creates new multi-signature crypto engine
// Implements Bitcoin's M-of-N multi-signature scheme
func NewMultiSigCrypto(config *MultiSigConfig) (*MultiSigCrypto, error) {
	// Validate configuration (Bitcoin-style validation)
	if err := validateMultiSigConfig(config); err != nil {
		return nil, fmt.Errorf("invalid multisig config: %v", err)
	}

	// Generate private key for this participant
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := privateKey.PubKey()

	return &MultiSigCrypto{
		config:     config,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// CreateMultiSigProtection protects code with Bitcoin-style multi-signature
func (msc *MultiSigCrypto) CreateMultiSigProtection(sourceCode []byte) (*MultiSigProtection, error) {
	// Calculate code hash for integrity (Bitcoin-style)
	codeHash := sha256.Sum256(sourceCode)

	// Generate config hash for tamper detection
	configData, _ := json.Marshal(msc.config)
	configHashSum := sha256.Sum256(configData)

	// Encrypt source code (simple XOR with derived key)
	encryptionKey := sha256.Sum256(append(codeHash[:], configHashSum[:]...))
	encryptedData := make([]byte, len(sourceCode))
	for i := range sourceCode {
		encryptedData[i] = sourceCode[i] ^ encryptionKey[i%32]
	}

	// Create initial signature from creator (us)
	creatorSignature, err := msc.signCodeHash(codeHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create creator signature: %v", err)
	}

	protection := &MultiSigProtection{
		EncryptedData: encryptedData,
		ConfigHash:    hex.EncodeToString(configHashSum[:]),
		Signatures: []MultiSigEntry{
			{
				SignerPubKey: hex.EncodeToString(msc.publicKey.SerializeCompressed()),
				Signature:    creatorSignature,
				SignedAt:     currentTimestamp(),
				NodeID:       generateNodeID(msc.publicKey),
			},
		},
		Threshold: msc.config.RequiredSignatures,
		CodeHash:  hex.EncodeToString(codeHash[:]),
		Timestamp: currentTimestamp(),
	}

	return protection, nil
}

// AddSignature adds a signature from another authorized signer
func (msc *MultiSigCrypto) AddSignature(protection *MultiSigProtection, signerPrivateKeyHex string) error {
	// Load signer's private key
	privKeyBytes, err := decodeHex(signerPrivateKeyHex)
	if err != nil {
		return err
	}
	signerPrivKey, signerPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	// Verify signer is authorized (in our config)
	signerPubKeyHex := hex.EncodeToString(signerPubKey.SerializeCompressed())
	if !msc.isAuthorizedSigner(signerPubKeyHex) {
		return fmt.Errorf("unauthorized signer: %s", signerPubKeyHex[:16])
	}

	// Check if already signed
	for _, existingSig := range protection.Signatures {
		if existingSig.SignerPubKey == signerPubKeyHex {
			return fmt.Errorf("signer already provided signature")
		}
	}

	// Create signature
	codeHashBytes, err := decodeHex(protection.CodeHash)
	if err != nil {
		return err
	}
	signature := ecdsa.Sign(signerPrivKey, codeHashBytes)

	// Add signature to protection
	protection.Signatures = append(protection.Signatures, MultiSigEntry{
		SignerPubKey: signerPubKeyHex,
		Signature:    hex.EncodeToString(signature.Serialize()),
		SignedAt:     currentTimestamp(),
		NodeID:       generateNodeID(signerPubKey),
	})

	return nil
}

// VerifyAndUnlock verifies signatures and unlocks protected code
// Implements Bitcoin's signature verification logic
func (msc *MultiSigCrypto) VerifyAndUnlock(protection *MultiSigProtection) ([]byte, error) {
	// Check if we have enough signatures (Bitcoin M-of-N validation)
	if len(protection.Signatures) < protection.Threshold {
		return nil, fmt.Errorf("insufficient signatures: %d < %d required",
			len(protection.Signatures), protection.Threshold)
	}

	// Verify each signature (Bitcoin-style verification)
	validSignatures := 0
	codeHashBytes, err := decodeHex(protection.CodeHash)
	if err != nil {
		return nil, err
	}

	for _, sigEntry := range protection.Signatures {
		// Parse public key
		pubKeyBytes, err := decodeHex(sigEntry.SignerPubKey)
		if err != nil {
			continue // Skip invalid public key
		}
		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			continue // Skip invalid public key
		}

		// Verify signer is authorized
		if !msc.isAuthorizedSigner(sigEntry.SignerPubKey) {
			continue // Skip unauthorized signer
		}

		// Parse and verify signature
		sigBytes, err := decodeHex(sigEntry.Signature)
		if err != nil {
			continue // Skip invalid signature
		}
		signature, err := ecdsa.ParseSignature(sigBytes)
		if err != nil {
			continue // Skip invalid signature
		}

		// Verify signature against code hash
		if signature.Verify(codeHashBytes, pubKey) {
			validSignatures++
		}
	}

	// Check if we have enough valid signatures
	if validSignatures < protection.Threshold {
		return nil, fmt.Errorf("insufficient valid signatures: %d < %d required",
			validSignatures, protection.Threshold)
	}

	// Decrypt source code
	configHashBytes, err := decodeHex(protection.ConfigHash)
	if err != nil {
		return nil, err
	}
	encryptionKey := sha256.Sum256(append(codeHashBytes, configHashBytes...))

	decryptedData := make([]byte, len(protection.EncryptedData))
	for i := range protection.EncryptedData {
		decryptedData[i] = protection.EncryptedData[i] ^ encryptionKey[i%32]
	}

	// Verify integrity
	decryptedHash := sha256.Sum256(decryptedData)
	if hex.EncodeToString(decryptedHash[:]) != protection.CodeHash {
		return nil, fmt.Errorf("integrity check failed: code has been tampered")
	}

	return decryptedData, nil
}

// GetMultiSigStatus returns current status of multi-sig protection
func (msc *MultiSigCrypto) GetMultiSigStatus(protection *MultiSigProtection) map[string]interface{} {
	validSigs := 0
	signerList := make([]string, 0)

	for _, sig := range protection.Signatures {
		if msc.isAuthorizedSigner(sig.SignerPubKey) {
			validSigs++
			signerList = append(signerList, sig.NodeID)
		}
	}

	return map[string]interface{}{
		"required_signatures": protection.Threshold,
		"current_signatures":  validSigs,
		"signatures_needed":   protection.Threshold - validSigs,
		"can_unlock":          validSigs >= protection.Threshold,
		"signers":             signerList,
		"config_m_of_n":       fmt.Sprintf("%d-of-%d", msc.config.RequiredSignatures, msc.config.TotalSigners),
		"security_model":      "Bitcoin-style MultiSig",
	}
}

// CreateTeamMultiSigConfig creates a predefined multi-sig config for teams
func CreateTeamMultiSigConfig(teamName string, requiredSigs int, memberPubKeys []string) *MultiSigConfig {
	return &MultiSigConfig{
		RequiredSignatures: requiredSigs,
		TotalSigners:       len(memberPubKeys),
		PublicKeys:         memberPubKeys,
		Description:        fmt.Sprintf("Team %s (%d-of-%d MultiSig)", teamName, requiredSigs, len(memberPubKeys)),
	}
}

// Utility functions

func validateMultiSigConfig(config *MultiSigConfig) error {
	if config.RequiredSignatures < 1 {
		return fmt.Errorf("required signatures must be at least 1")
	}

	if config.RequiredSignatures > config.TotalSigners {
		return fmt.Errorf("required signatures (%d) cannot exceed total signers (%d)",
			config.RequiredSignatures, config.TotalSigners)
	}

	if len(config.PublicKeys) != config.TotalSigners {
		return fmt.Errorf("public keys count (%d) must equal total signers (%d)",
			len(config.PublicKeys), config.TotalSigners)
	}

	// Validate each public key
	for i, pubKeyHex := range config.PublicKeys {
		pubKeyBytes, err := decodeHex(pubKeyHex)
		if err != nil {
			return fmt.Errorf("invalid public key %d: %v", i, err)
		}

		if _, err := btcec.ParsePubKey(pubKeyBytes); err != nil {
			return fmt.Errorf("invalid public key %d: %v", i, err)
		}
	}

	return nil
}

func (msc *MultiSigCrypto) isAuthorizedSigner(pubKeyHex string) bool {
	for _, authorizedKey := range msc.config.PublicKeys {
		if authorizedKey == pubKeyHex {
			return true
		}
	}
	return false
}

func (msc *MultiSigCrypto) signCodeHash(codeHash []byte) (string, error) {
	signature := ecdsa.Sign(msc.privateKey, codeHash)
	return hex.EncodeToString(signature.Serialize()), nil
}

func generateNodeID(pubKey *btcec.PublicKey) string {
	hash := sha256.Sum256(pubKey.SerializeCompressed())
	return hex.EncodeToString(hash[:8])
}

func currentTimestamp() int64 {
	return int64(1704067200) // Mock timestamp for demo
}

func decodeHex(s string) ([]byte, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %v", err)
	}
	return data, nil
}

// GetMyPublicKey returns our public key for sharing with other signers
func (msc *MultiSigCrypto) GetMyPublicKey() string {
	return hex.EncodeToString(msc.publicKey.SerializeCompressed())
}

// GetMyPrivateKey returns our private key (KEEP SECRET!)
func (msc *MultiSigCrypto) GetMyPrivateKey() string {
	return hex.EncodeToString(msc.privateKey.Serialize())
}
