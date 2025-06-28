// Package crypto - UTXO implementation for Eden Core
// Adopting Bitcoin's Unspent Transaction Output model for code ownership tracking
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// CodeUTXO represents an Unspent Code Access Output (like Bitcoin UTXO)
type CodeUTXO struct {
	TxID         string   `json:"tx_id"`         // Transaction ID that created this UTXO
	OutputIndex  int      `json:"output_index"`  // Output index within transaction
	CodeID       string   `json:"code_id"`       // Identifier of the protected code
	OwnerPubKey  string   `json:"owner_pubkey"`  // Current owner's public key
	AccessRights []string `json:"access_rights"` // List of permissions (read, write, execute, transfer)
	Value        int64    `json:"value"`         // Access "value" (like Bitcoin satoshis)
	CreatedAt    int64    `json:"created_at"`    // Creation timestamp
	ExpiresAt    int64    `json:"expires_at"`    // Expiration timestamp (0 = never expires)
	LockScript   string   `json:"lock_script"`   // Script that must be satisfied to spend
	IsSpent      bool     `json:"is_spent"`      // Whether this UTXO has been spent
}

// CodeTransaction represents a transaction that moves code access rights
type CodeTransaction struct {
	TxID       string         `json:"tx_id"`       // Transaction identifier
	Inputs     []CodeTxInput  `json:"inputs"`      // UTXOs being spent
	Outputs    []CodeTxOutput `json:"outputs"`     // New UTXOs being created
	Timestamp  int64          `json:"timestamp"`   // Transaction timestamp
	CreatorKey string         `json:"creator_key"` // Creator's public key
	Signatures []TxSignature  `json:"signatures"`  // Digital signatures
	Fees       int64          `json:"fees"`        // Transaction fees (access value consumed)
	TxHash     string         `json:"tx_hash"`     // SHA-256 hash of transaction
}

// CodeTxInput represents an input to a code transaction (spending a UTXO)
type CodeTxInput struct {
	PrevTxID       string `json:"prev_tx_id"`      // Previous transaction ID
	PrevOutIndex   int    `json:"prev_out_index"`  // Previous output index
	UnlockScript   string `json:"unlock_script"`   // Script that unlocks the UTXO
	OwnerSignature string `json:"owner_signature"` // Owner's signature
	Sequence       uint32 `json:"sequence"`        // Sequence number (for time locks)
}

// CodeTxOutput represents an output of a code transaction (creating new UTXO)
type CodeTxOutput struct {
	Value        int64    `json:"value"`         // Access value
	LockScript   string   `json:"lock_script"`   // Locking script
	RecipientKey string   `json:"recipient_key"` // Recipient's public key
	AccessRights []string `json:"access_rights"` // Access permissions
	ExpiresAt    int64    `json:"expires_at"`    // Expiration time
}

// TxSignature represents a digital signature on a transaction
type TxSignature struct {
	SignerPubKey string `json:"signer_pubkey"` // Signer's public key
	Signature    string `json:"signature"`     // ECDSA signature
	SigType      string `json:"sig_type"`      // Signature type (SIGHASH_ALL, etc.)
}

// UTXOSet represents the set of unspent code access outputs
type UTXOSet struct {
	utxos        map[string]*CodeUTXO        // UTXO storage (key: txid:index)
	codeOwners   map[string][]string         // Code ID -> UTXO keys
	ownerUTXOs   map[string][]string         // Owner -> UTXO keys
	transactions map[string]*CodeTransaction // Transaction storage
}

// CodeAccessManager manages Bitcoin-style code ownership using UTXO model
type CodeAccessManager struct {
	utxoSet    *UTXOSet
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
}

// NewCodeAccessManager creates new UTXO-based code access manager
func NewCodeAccessManager() (*CodeAccessManager, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &CodeAccessManager{
		utxoSet: &UTXOSet{
			utxos:        make(map[string]*CodeUTXO),
			codeOwners:   make(map[string][]string),
			ownerUTXOs:   make(map[string][]string),
			transactions: make(map[string]*CodeTransaction),
		},
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
	}, nil
}

// CreateGenesisUTXO creates initial ownership UTXO for new protected code
func (cam *CodeAccessManager) CreateGenesisUTXO(codeID string, ownerPubKey string, accessRights []string) (*CodeUTXO, error) {
	// Create genesis transaction (like Bitcoin's coinbase transaction)
	txID := generateTxID("genesis", codeID, ownerPubKey)

	utxo := &CodeUTXO{
		TxID:         txID,
		OutputIndex:  0,
		CodeID:       codeID,
		OwnerPubKey:  ownerPubKey,
		AccessRights: accessRights,
		Value:        1000000, // Initial access value (like 1 BTC = 100M satoshis)
		CreatedAt:    getCurrentTimestamp(),
		ExpiresAt:    0, // Never expires
		LockScript:   createP2PKHLockScript(ownerPubKey),
		IsSpent:      false,
	}

	// Add to UTXO set
	utxoKey := fmt.Sprintf("%s:%d", txID, 0)
	cam.utxoSet.utxos[utxoKey] = utxo
	cam.utxoSet.codeOwners[codeID] = append(cam.utxoSet.codeOwners[codeID], utxoKey)
	cam.utxoSet.ownerUTXOs[ownerPubKey] = append(cam.utxoSet.ownerUTXOs[ownerPubKey], utxoKey)

	return utxo, nil
}

// TransferCodeAccess transfers code access rights (like Bitcoin transaction)
func (cam *CodeAccessManager) TransferCodeAccess(senderPrivKey string, codeID string, recipientPubKey string, accessRights []string, value int64) (*CodeTransaction, error) {
	senderPrivKeyBytes, _ := hex.DecodeString(senderPrivKey)
	senderPriv, senderPub := btcec.PrivKeyFromBytes(senderPrivKeyBytes)
	senderPubKeyHex := hex.EncodeToString(senderPub.SerializeCompressed())

	// Find UTXOs owned by sender for this code
	senderUTXOs := cam.findUTXOsForOwnerAndCode(senderPubKeyHex, codeID)
	if len(senderUTXOs) == 0 {
		return nil, fmt.Errorf("no UTXOs found for sender and code")
	}

	// Calculate total available value
	totalValue := int64(0)
	for _, utxo := range senderUTXOs {
		totalValue += utxo.Value
	}

	if totalValue < value {
		return nil, fmt.Errorf("insufficient access value: have %d, need %d", totalValue, value)
	}

	// Create transaction
	txID := generateTxID("transfer", codeID, recipientPubKey)

	// Create inputs (spending UTXOs)
	inputs := make([]CodeTxInput, 0)
	inputValue := int64(0)

	for _, utxo := range senderUTXOs {
		if inputValue >= value {
			break
		}

		input := CodeTxInput{
			PrevTxID:     utxo.TxID,
			PrevOutIndex: utxo.OutputIndex,
			UnlockScript: createP2PKHUnlockScript(senderPubKeyHex),
			Sequence:     0xffffffff,
		}

		inputs = append(inputs, input)
		inputValue += utxo.Value
	}

	// Create outputs
	outputs := make([]CodeTxOutput, 0)

	// Output to recipient
	outputs = append(outputs, CodeTxOutput{
		Value:        value,
		LockScript:   createP2PKHLockScript(recipientPubKey),
		RecipientKey: recipientPubKey,
		AccessRights: accessRights,
		ExpiresAt:    0,
	})

	// Change output back to sender (if any)
	changeValue := inputValue - value
	if changeValue > 0 {
		outputs = append(outputs, CodeTxOutput{
			Value:        changeValue,
			LockScript:   createP2PKHLockScript(senderPubKeyHex),
			RecipientKey: senderPubKeyHex,
			AccessRights: []string{"read", "write", "execute", "transfer"}, // Full rights for change
			ExpiresAt:    0,
		})
	}

	// Create transaction
	transaction := &CodeTransaction{
		TxID:       txID,
		Inputs:     inputs,
		Outputs:    outputs,
		Timestamp:  getCurrentTimestamp(),
		CreatorKey: senderPubKeyHex,
		Fees:       0, // No fees for now
	}

	// Sign transaction
	txHash := calculateTransactionHash(transaction)
	signature := ecdsa.Sign(senderPriv, txHash)

	transaction.Signatures = []TxSignature{{
		SignerPubKey: senderPubKeyHex,
		Signature:    hex.EncodeToString(signature.Serialize()),
		SigType:      "SIGHASH_ALL",
	}}

	transaction.TxHash = hex.EncodeToString(txHash)

	// Process transaction
	if err := cam.processTransaction(transaction); err != nil {
		return nil, fmt.Errorf("failed to process transaction: %v", err)
	}

	return transaction, nil
}

// VerifyCodeAccess verifies if a user has specific access to code
func (cam *CodeAccessManager) VerifyCodeAccess(userPubKey string, codeID string, requiredRights []string) (bool, *AccessVerification) {
	userUTXOs := cam.findUTXOsForOwnerAndCode(userPubKey, codeID)

	verification := &AccessVerification{
		UserPubKey:      userPubKey,
		CodeID:          codeID,
		RequiredRights:  requiredRights,
		HasAccess:       false,
		AvailableRights: make([]string, 0),
		TotalValue:      0,
		UTXOCount:       len(userUTXOs),
	}

	if len(userUTXOs) == 0 {
		verification.Reason = "No UTXOs found for user and code"
		return false, verification
	}

	// Check access rights and calculate total value
	availableRightsMap := make(map[string]bool)
	for _, utxo := range userUTXOs {
		// Check expiration
		if utxo.ExpiresAt > 0 && getCurrentTimestamp() > utxo.ExpiresAt {
			continue // Skip expired UTXOs
		}

		verification.TotalValue += utxo.Value

		for _, right := range utxo.AccessRights {
			availableRightsMap[right] = true
		}
	}

	// Convert map to slice
	for right := range availableRightsMap {
		verification.AvailableRights = append(verification.AvailableRights, right)
	}
	sort.Strings(verification.AvailableRights)

	// Check if user has all required rights
	hasAllRights := true
	for _, requiredRight := range requiredRights {
		if !availableRightsMap[requiredRight] {
			hasAllRights = false
			break
		}
	}

	verification.HasAccess = hasAllRights
	if hasAllRights {
		verification.Reason = "All required access rights available"
	} else {
		verification.Reason = "Missing required access rights"
	}

	return hasAllRights, verification
}

// GetUTXOsForOwner returns all UTXOs owned by a specific public key
func (cam *CodeAccessManager) GetUTXOsForOwner(ownerPubKey string) []*CodeUTXO {
	utxoKeys, exists := cam.utxoSet.ownerUTXOs[ownerPubKey]
	if !exists {
		return []*CodeUTXO{}
	}

	utxos := make([]*CodeUTXO, 0)
	for _, key := range utxoKeys {
		if utxo, exists := cam.utxoSet.utxos[key]; exists && !utxo.IsSpent {
			utxos = append(utxos, utxo)
		}
	}

	return utxos
}

// GetCodeOwners returns all current owners of a specific code
func (cam *CodeAccessManager) GetCodeOwners(codeID string) map[string]*OwnershipInfo {
	owners := make(map[string]*OwnershipInfo)

	utxoKeys, exists := cam.utxoSet.codeOwners[codeID]
	if !exists {
		return owners
	}

	for _, key := range utxoKeys {
		if utxo, exists := cam.utxoSet.utxos[key]; exists && !utxo.IsSpent {
			if _, exists := owners[utxo.OwnerPubKey]; !exists {
				owners[utxo.OwnerPubKey] = &OwnershipInfo{
					OwnerPubKey:  utxo.OwnerPubKey,
					TotalValue:   0,
					AccessRights: make(map[string]bool),
					UTXOCount:    0,
				}
			}

			info := owners[utxo.OwnerPubKey]
			info.TotalValue += utxo.Value
			info.UTXOCount++

			for _, right := range utxo.AccessRights {
				info.AccessRights[right] = true
			}
		}
	}

	return owners
}

// AccessVerification represents the result of access verification
type AccessVerification struct {
	UserPubKey      string   `json:"user_pubkey"`
	CodeID          string   `json:"code_id"`
	RequiredRights  []string `json:"required_rights"`
	AvailableRights []string `json:"available_rights"`
	HasAccess       bool     `json:"has_access"`
	TotalValue      int64    `json:"total_value"`
	UTXOCount       int      `json:"utxo_count"`
	Reason          string   `json:"reason"`
}

// OwnershipInfo represents ownership information for a code
type OwnershipInfo struct {
	OwnerPubKey  string          `json:"owner_pubkey"`
	TotalValue   int64           `json:"total_value"`
	AccessRights map[string]bool `json:"access_rights"`
	UTXOCount    int             `json:"utxo_count"`
}

// Utility functions

func (cam *CodeAccessManager) findUTXOsForOwnerAndCode(ownerPubKey string, codeID string) []*CodeUTXO {
	utxos := make([]*CodeUTXO, 0)

	for _, utxo := range cam.utxoSet.utxos {
		if utxo.OwnerPubKey == ownerPubKey && utxo.CodeID == codeID && !utxo.IsSpent {
			// Check expiration
			if utxo.ExpiresAt == 0 || getCurrentTimestamp() <= utxo.ExpiresAt {
				utxos = append(utxos, utxo)
			}
		}
	}

	return utxos
}

func (cam *CodeAccessManager) processTransaction(tx *CodeTransaction) error {
	// Mark input UTXOs as spent
	for _, input := range tx.Inputs {
		utxoKey := fmt.Sprintf("%s:%d", input.PrevTxID, input.PrevOutIndex)
		if utxo, exists := cam.utxoSet.utxos[utxoKey]; exists {
			utxo.IsSpent = true
		}
	}

	// Create new UTXOs from outputs
	for i, output := range tx.Outputs {
		utxo := &CodeUTXO{
			TxID:         tx.TxID,
			OutputIndex:  i,
			CodeID:       tx.Inputs[0].PrevTxID, // Use code ID from first input
			OwnerPubKey:  output.RecipientKey,
			AccessRights: output.AccessRights,
			Value:        output.Value,
			CreatedAt:    tx.Timestamp,
			ExpiresAt:    output.ExpiresAt,
			LockScript:   output.LockScript,
			IsSpent:      false,
		}

		utxoKey := fmt.Sprintf("%s:%d", tx.TxID, i)
		cam.utxoSet.utxos[utxoKey] = utxo

		// Update indexes
		codeID := utxo.CodeID
		cam.utxoSet.codeOwners[codeID] = append(cam.utxoSet.codeOwners[codeID], utxoKey)
		cam.utxoSet.ownerUTXOs[utxo.OwnerPubKey] = append(cam.utxoSet.ownerUTXOs[utxo.OwnerPubKey], utxoKey)
	}

	// Store transaction
	cam.utxoSet.transactions[tx.TxID] = tx

	return nil
}

func generateTxID(txType, codeID, recipientKey string) string {
	data := fmt.Sprintf("%s_%s_%s_%d", txType, codeID, recipientKey, getCurrentTimestamp())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func createP2PKHLockScript(pubKeyHex string) string {
	// Bitcoin-style Pay-to-Public-Key-Hash script
	return fmt.Sprintf("OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG", pubKeyHex[:20])
}

func createP2PKHUnlockScript(pubKeyHex string) string {
	// Bitcoin-style unlock script
	return fmt.Sprintf("<sig> %s", pubKeyHex)
}

func calculateTransactionHash(tx *CodeTransaction) []byte {
	// Create deterministic hash of transaction (excluding signatures)
	txCopy := *tx
	txCopy.Signatures = nil
	txCopy.TxHash = ""

	data, _ := json.Marshal(txCopy)
	hash := sha256.Sum256(data)
	return hash[:]
}

// GetMyPublicKey returns our public key
func (cam *CodeAccessManager) GetMyPublicKey() string {
	return hex.EncodeToString(cam.publicKey.SerializeCompressed())
}

// GetMyPrivateKey returns our private key (KEEP SECRET!)
func (cam *CodeAccessManager) GetMyPrivateKey() string {
	return hex.EncodeToString(cam.privateKey.Serialize())
}
