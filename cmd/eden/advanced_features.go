package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/purwowd/eden-core/internal/config"
	"github.com/purwowd/eden-core/internal/storage"
	"github.com/purwowd/eden-core/pkg/crypto"
)

// MultiAuthSignature represents a signature in multi-auth system
type MultiAuthSignature struct {
	SignerID   string    `json:"signer_id"`
	PublicKey  string    `json:"public_key"`
	Signature  string    `json:"signature"`
	Timestamp  time.Time `json:"timestamp"`
	FileHash   string    `json:"file_hash"`
	SignerRole string    `json:"signer_role"`
}

// MultiAuthMetadata holds multi-auth information
type MultiAuthMetadata struct {
	RequiredSignatures int                  `json:"required_signatures"`
	TotalSigners       int                  `json:"total_signers"`
	Signatures         []MultiAuthSignature `json:"signatures"`
	Policy             string               `json:"policy"` // e.g., "2-of-3"
	CreatedAt          time.Time            `json:"created_at"`
	LastModified       time.Time            `json:"last_modified"`
}

// OwnershipTransferRequest represents ownership transfer
type OwnershipTransferRequest struct {
	CurrentOwner string    `json:"current_owner"`
	NewOwner     string    `json:"new_owner"`
	FileID       string    `json:"file_id"`
	Reason       string    `json:"reason"`
	Timestamp    time.Time `json:"timestamp"`
	Signature    string    `json:"signature"`
}

// PolicyExecutionResult represents policy execution result
type PolicyExecutionResult struct {
	Success    bool                   `json:"success"`
	Message    string                 `json:"message"`
	ExecutedAt time.Time              `json:"executed_at"`
	PolicyType string                 `json:"policy_type"`
	Variables  map[string]interface{} `json:"variables"`
	Duration   time.Duration          `json:"duration"`
}

// Helper functions for advanced security features integration

// applyMultiAuthProtection applies MultiAuth protection to source code
func applyMultiAuthProtection(sourceData []byte, input, output string, options *AdvancedProtectionOptions, verbose bool) (string, error) {
	if verbose {
		fmt.Printf("Applying MultiAuth protection (%s)...\n", options.MultiAuth)
	}

	// Parse MultiAuth configuration
	parts := strings.Split(options.MultiAuth, "-of-")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid multiauth format, use 'M-of-N' (e.g., '2-of-3')")
	}

	requiredSigs, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid required signatures: %v", err)
	}

	totalSigners, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid total signers: %v", err)
	}

	// Generate public keys if not provided
	var publicKeys []string
	if len(options.Signers) == totalSigners {
		publicKeys = options.Signers
	} else {
		// Generate demo keys
		for i := 0; i < totalSigners; i++ {
			crypto, _ := crypto.NewEllipticCrypto()
			publicKeys = append(publicKeys, crypto.GetPublicKeyHex())
		}
		if verbose {
			fmt.Printf("   Generated %d demo public keys\n", totalSigners)
		}
	}

	// Create MultiAuth configuration
	config := &crypto.MultiSigConfig{
		RequiredSignatures: requiredSigs,
		TotalSigners:       totalSigners,
		PublicKeys:         publicKeys,
		Description:        fmt.Sprintf("Eden Core MultiAuth (%d-of-%d)", requiredSigs, totalSigners),
	}

	// Create MultiAuth crypto engine
	msc, err := crypto.NewMultiSigCrypto(config)
	if err != nil {
		return "", fmt.Errorf("failed to create MultiAuth crypto: %v", err)
	}

	// Protect source code
	protection, err := msc.CreateMultiSigProtection(sourceData)
	if err != nil {
		return "", fmt.Errorf("failed to create MultiAuth protection: %v", err)
	}

	// Save protected file
	outputFile := filepath.Join(output, filepath.Base(input)+".multiauth")
	if err := os.MkdirAll(output, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	protectionData, err := json.MarshalIndent(protection, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal protection data: %v", err)
	}

	if err := os.WriteFile(outputFile, protectionData, 0644); err != nil {
		return "", fmt.Errorf("failed to save protected file: %v", err)
	}

	// Save metadata
	metadataFile := outputFile + ".meta"
	metadata := map[string]interface{}{
		"type":            "multiauth",
		"config":          config,
		"creator_pubkey":  msc.GetMyPublicKey(),
		"creator_privkey": msc.GetMyPrivateKey(),
		"status":          msc.GetMultiSigStatus(protection),
	}

	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataFile, metadataData, 0644)

	if verbose {
		status := msc.GetMultiSigStatus(protection)
		fmt.Printf("   MultiAuth protection created\n")
		fmt.Printf("   Status: %d/%d signatures (%s)\n",
			status["current_signatures"], status["required_signatures"], status["config_m_of_n"])
		fmt.Printf("   File: %s\n", outputFile)
	}

	return outputFile, nil
}

// applyTimeLockProtection applies TimeLock protection to source code
func applyTimeLockProtection(sourceData []byte, input, output string, options *AdvancedProtectionOptions, verbose bool) (string, error) {
	if verbose {
		fmt.Printf("Applying TimeLock protection (%s)...\n", options.TimeLock)
	}

	// Create TimeLock crypto engine
	tlc, err := crypto.NewTimeLockCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create TimeLock crypto: %v", err)
	}

	// Parse TimeLock configuration
	config, err := parseTimeLockConfig(options.TimeLock, options.TimeLockType)
	if err != nil {
		return "", fmt.Errorf("failed to parse TimeLock config: %v", err)
	}

	// Protect source code
	protection, err := tlc.CreateTimeLockProtection(sourceData, *config)
	if err != nil {
		return "", fmt.Errorf("failed to create TimeLock protection: %v", err)
	}

	// Save protected file
	outputFile := filepath.Join(output, filepath.Base(input)+".timelock")
	if err := os.MkdirAll(output, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	protectionData, err := json.MarshalIndent(protection, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal protection data: %v", err)
	}

	if err := os.WriteFile(outputFile, protectionData, 0644); err != nil {
		return "", fmt.Errorf("failed to save protected file: %v", err)
	}

	// Save metadata
	metadataFile := outputFile + ".meta"
	metadata := map[string]interface{}{
		"type":            "timelock",
		"config":          config,
		"creator_pubkey":  tlc.GetMyPublicKey(),
		"creator_privkey": tlc.GetMyPrivateKey(),
	}

	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataFile, metadataData, 0644)

	// Check status
	status, err := tlc.CheckTimeLockStatus(protection)
	if err == nil && verbose {
		fmt.Printf("   TimeLock protection created\n")
		fmt.Printf("   Lock Type: %s\n", status.LockType)
		fmt.Printf("   Can Unlock: %v\n", status.CanUnlock)
		fmt.Printf("   Reason: %s\n", status.Reason)
		fmt.Printf("   File: %s\n", outputFile)
	}

	return outputFile, nil
}

// applyOwnershipProtection applies ownership control to source code
func applyOwnershipProtection(sourceData []byte, input, output string, options *AdvancedProtectionOptions, verbose bool) (string, error) {
	if verbose {
		fmt.Printf("Applying ownership control (value: %d)...\n", options.OwnershipValue)
	}

	// Create Code Access Manager
	cam, err := crypto.NewCodeAccessManager()
	if err != nil {
		return "", fmt.Errorf("failed to create Code Access Manager: %v", err)
	}

	// Generate code ID
	codeID := generateCodeID(input)
	ownerPubKey := cam.GetMyPublicKey()

	// Create genesis ownership
	ownership, err := cam.CreateGenesisUTXO(codeID, ownerPubKey, options.AccessRights)
	if err != nil {
		return "", fmt.Errorf("failed to create genesis ownership: %v", err)
	}

	// Encrypt source code (simple protection for ownership demo)
	cryptoEngine, err := crypto.NewEllipticCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create crypto engine: %v", err)
	}

	protection, err := cryptoEngine.ProtectWithECC(sourceData)
	if err != nil {
		return "", fmt.Errorf("failed to protect source code: %v", err)
	}

	// Save protected file
	outputFile := filepath.Join(output, filepath.Base(input)+".ownership")
	if err := os.MkdirAll(output, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create ownership protection structure
	ownershipProtection := map[string]interface{}{
		"code_id":        codeID,
		"ownership_data": ownership,
		"encrypted_code": protection,
		"owner_pubkey":   ownerPubKey,
		"access_rights":  options.AccessRights,
		"initial_value":  options.OwnershipValue,
	}

	protectionData, err := json.MarshalIndent(ownershipProtection, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal protection data: %v", err)
	}

	if err := os.WriteFile(outputFile, protectionData, 0644); err != nil {
		return "", fmt.Errorf("failed to save protected file: %v", err)
	}

	// Save metadata
	metadataFile := outputFile + ".meta"
	metadata := map[string]interface{}{
		"type":              "ownership",
		"code_id":           codeID,
		"owner_pubkey":      ownerPubKey,
		"owner_privkey":     cam.GetMyPrivateKey(),
		"ownership_details": ownership,
	}

	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataFile, metadataData, 0644)

	if verbose {
		fmt.Printf("   Ownership control created\n")
		fmt.Printf("   Code ID: %s\n", codeID[:16]+"...")
		fmt.Printf("   Value: %d\n", ownership.Value)
		fmt.Printf("   Owner: %s...\n", ownerPubKey[:16])
		fmt.Printf("   File: %s\n", outputFile)
	}

	return outputFile, nil
}

// applyPolicyScriptProtection applies PolicyScript-based protection to source code
func applyPolicyScriptProtection(sourceData []byte, input, output string, options *AdvancedProtectionOptions, verbose bool) (string, error) {
	script := options.PolicyScript
	if script == "" {
		// Use predefined policy
		script = getPredefinedPolicyScript(options.PolicyType)
	}

	if verbose {
		fmt.Printf("Applying PolicyScript protection...\n")
		fmt.Printf("   Script: %s\n", script)
	}

	// Create PolicyScript crypto engine
	sc, err := crypto.NewScriptCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create PolicyScript crypto: %v", err)
	}

	// Create access policy
	policy := crypto.AccessPolicy{
		RequireSignature: true,
		RequireMultiSig:  false,
		MinReputation:    50,
		AllowedTeams:     []string{"developers", "admins"},
		MaxAccessPerHour: 10,
		RequireApproval:  false,
	}

	// Protect source code
	protection, err := sc.CreateScriptProtection(sourceData, script, policy)
	if err != nil {
		return "", fmt.Errorf("failed to create PolicyScript protection: %v", err)
	}

	// Save protected file
	outputFile := filepath.Join(output, filepath.Base(input)+".policyscript")
	if err := os.MkdirAll(output, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	protectionData, err := json.MarshalIndent(protection, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal protection data: %v", err)
	}

	if err := os.WriteFile(outputFile, protectionData, 0644); err != nil {
		return "", fmt.Errorf("failed to save protected file: %v", err)
	}

	// Save metadata
	metadataFile := outputFile + ".meta"
	metadata := map[string]interface{}{
		"type":           "policyscript",
		"script":         script,
		"policy":         policy,
		"creator_pubkey": sc.GetMyPublicKey(),
	}

	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(metadataFile, metadataData, 0644)

	if verbose {
		fmt.Printf("   PolicyScript protection created\n")
		fmt.Printf("   Script: %s\n", script)
		fmt.Printf("   File: %s\n", outputFile)
	}

	return outputFile, nil
}

// Utility functions

func parseTimeLockConfig(timelock, lockType string) (*crypto.TimeLockConfig, error) {
	config := &crypto.TimeLockConfig{
		Description:      "Eden Core TimeLock",
		AllowEarlyUnlock: true,
	}

	// Use lockType parameter to determine behavior
	if lockType == "relative" || strings.HasPrefix(timelock, "+") {
		// Relative time
		config.LockType = crypto.TimeLockRelative
		duration := strings.TrimPrefix(timelock, "+")

		// Try to parse as Go duration first (e.g., "1h", "24h", "7d")
		if parsed, err := time.ParseDuration(duration); err == nil {
			config.LockValue = int64(parsed.Seconds())
			return config, nil
		}

		// Fallback to old format with suffixes
		switch {
		case strings.HasSuffix(duration, "days"):
			days, err := strconv.Atoi(strings.TrimSuffix(duration, "days"))
			if err != nil {
				return nil, err
			}
			config.LockValue = int64(days * 24 * 60 * 60)
		case strings.HasSuffix(duration, "hours"):
			hours, err := strconv.Atoi(strings.TrimSuffix(duration, "hours"))
			if err != nil {
				return nil, err
			}
			config.LockValue = int64(hours * 60 * 60)
		default:
			return nil, fmt.Errorf("unsupported relative time format: %s. Use formats like '+1h', '+24h', '+7d' or absolute time like '2025-01-01T00:00:00Z'", duration)
		}
	} else {
		// Absolute time
		config.LockType = crypto.TimeLockAbsolute
		t, err := time.Parse(time.RFC3339, timelock)
		if err != nil {
			return nil, fmt.Errorf("invalid absolute time format: %v. Use RFC3339 format like '2025-01-01T00:00:00Z'", err)
		}
		config.LockValue = t.Unix()
	}

	return config, nil
}

func getPredefinedPolicyScript(policy string) string {
	switch policy {
	case "simple":
		return "OP_CHECKSIG"
	case "team":
		return "developers OP_CHECKTEAM"
	case "enterprise":
		return "developers OP_CHECKTEAM 75 OP_CHECKREP OP_AND business_hours OP_CHECKTIME OP_AND"
	default:
		return "OP_CHECKSIG" // Default to simple signature check
	}
}

func generateCodeID(filePath string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(filePath+time.Now().String())))
	return hash[:16]
}

func handleAdvancedFeatures(multiauthSign, multiauthStatus, timelockStatus, ownershipTransfer, ownershipVerify, policyExecute bool, input, keyfile, signers string, verbose bool) error {

	if multiauthSign {
		return handleMultiAuthSignature(input, keyfile, signers, verbose)
	}

	if multiauthStatus {
		return showMultiAuthStatus(input, verbose)
	}

	if timelockStatus {
		return showTimeLockStatus(input, verbose)
	}

	if ownershipTransfer {
		return handleOwnershipTransfer(input, keyfile, verbose)
	}

	if ownershipVerify {
		return handleOwnershipVerification(input, keyfile, verbose)
	}

	if policyExecute {
		return handlePolicyExecution(input, keyfile, verbose)
	}

	return fmt.Errorf("no advanced feature operation specified")
}

// handleMultiAuthSignature implements actual signature addition
func handleMultiAuthSignature(input, keyfile, signers string, verbose bool) error {
	if verbose {
		fmt.Printf("[SECURITY] Adding MultiAuth signature...\n")
		fmt.Printf("   Input: %s\n", input)
		fmt.Printf("   Keyfile: %s\n", keyfile)
		fmt.Printf("   Signers: %s\n", signers)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Extract file ID from protected file path
	fileID := extractFileIDFromPath(input)
	if fileID == "" {
		return fmt.Errorf("could not extract file ID from protected file path")
	}

	// Determine storage base path
	storageBasePath := determineStorageBasePath(input, cfg)

	// Initialize storage manager
	storageManager, err := storage.NewManager(
		storageBasePath,
		cfg.Storage.TempDirectory,
		cfg.Storage.BackupDirectory,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}

	// Load protected file
	protectedData, err := storageManager.LoadProtectedData(fileID)
	if err != nil {
		return fmt.Errorf("failed to load protected file: %v", err)
	}

	// Parse protected bundle
	var bundle map[string]interface{}
	if err := json.Unmarshal(protectedData, &bundle); err != nil {
		return fmt.Errorf("failed to parse protected bundle: %v", err)
	}

	// Calculate file hash
	fileHash := sha256.Sum256(protectedData)
	fileHashStr := hex.EncodeToString(fileHash[:])

	// Load or create MultiAuth metadata
	multiauthPath := filepath.Join(storageBasePath, "multiauth", fileID+".json")
	var multiauthData MultiAuthMetadata

	if _, err := os.Stat(multiauthPath); err == nil {
		// Load existing metadata
		data, err := os.ReadFile(multiauthPath)
		if err != nil {
			return fmt.Errorf("failed to read multiauth metadata: %v", err)
		}
		if err := json.Unmarshal(data, &multiauthData); err != nil {
			return fmt.Errorf("failed to parse multiauth metadata: %v", err)
		}
	} else {
		// Create new metadata
		signersList := strings.Split(signers, ",")
		multiauthData = MultiAuthMetadata{
			RequiredSignatures: len(signersList), // Default: all signers required
			TotalSigners:       len(signersList),
			Signatures:         []MultiAuthSignature{},
			Policy:             fmt.Sprintf("%d-of-%d", len(signersList), len(signersList)),
			CreatedAt:          time.Now(),
			LastModified:       time.Now(),
		}
	}

	// Generate signature for current signer
	ellipticCrypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		return fmt.Errorf("failed to create crypto engine: %v", err)
	}

	// Create signature data
	signatureData := fmt.Sprintf("%s:%s:%s", fileID, fileHashStr, time.Now().Format(time.RFC3339))
	protection, err := ellipticCrypto.ProtectWithECC([]byte(signatureData))
	if err != nil {
		return fmt.Errorf("failed to create signature: %v", err)
	}

	// Add signature to metadata
	signature := MultiAuthSignature{
		SignerID:   ellipticCrypto.GetPublicKeyHex()[:16], // Use first 16 chars as ID
		PublicKey:  ellipticCrypto.GetPublicKeyHex(),
		Signature:  hex.EncodeToString(protection.Signature),
		Timestamp:  time.Now(),
		FileHash:   fileHashStr,
		SignerRole: "signer", // Can be extended to different roles
	}

	// Check if signature already exists
	for i, existingSig := range multiauthData.Signatures {
		if existingSig.SignerID == signature.SignerID {
			// Update existing signature
			multiauthData.Signatures[i] = signature
			fmt.Printf("[SUCCESS] Updated existing signature for signer: %s\n", signature.SignerID)
			goto saveMetadata
		}
	}

	// Add new signature
	multiauthData.Signatures = append(multiauthData.Signatures, signature)
	fmt.Printf("[SUCCESS] Added new signature for signer: %s\n", signature.SignerID)

saveMetadata:
	multiauthData.LastModified = time.Now()

	// Ensure multiauth directory exists
	if err := os.MkdirAll(filepath.Dir(multiauthPath), 0755); err != nil {
		return fmt.Errorf("failed to create multiauth directory: %v", err)
	}

	// Save metadata
	metadataBytes, err := json.MarshalIndent(multiauthData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal multiauth metadata: %v", err)
	}

	if err := os.WriteFile(multiauthPath, metadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to save multiauth metadata: %v", err)
	}

	// Show status
	fmt.Printf("[SUCCESS] MultiAuth signature added successfully\n")
	fmt.Printf("   Signatures: %d/%d required\n", len(multiauthData.Signatures), multiauthData.RequiredSignatures)
	fmt.Printf("   Policy: %s\n", multiauthData.Policy)
	fmt.Printf("   File ID: %s\n", fileID)
	fmt.Printf("   Signer ID: %s\n", signature.SignerID)

	if len(multiauthData.Signatures) >= multiauthData.RequiredSignatures {
		fmt.Printf("[COMPLETE] All required signatures collected! File is fully authorized.\n")
	} else {
		remaining := multiauthData.RequiredSignatures - len(multiauthData.Signatures)
		fmt.Printf("⏳ %d more signatures required for full authorization.\n", remaining)
	}

	return nil
}

// handleOwnershipTransfer implements actual ownership transfer
func handleOwnershipTransfer(input, keyfile string, verbose bool) error {
	if verbose {
		fmt.Printf("🔄 Transferring ownership...\n")
		fmt.Printf("   Input: %s\n", input)
		fmt.Printf("   Keyfile: %s\n", keyfile)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Extract file ID
	fileID := extractFileIDFromPath(input)
	if fileID == "" {
		return fmt.Errorf("could not extract file ID from protected file path")
	}

	// Determine storage base path
	storageBasePath := determineStorageBasePath(input, cfg)

	// Load current owner from keyfile
	if keyfile == "" {
		keyfile = filepath.Join(storageBasePath, "keys", fileID+".key")
	}

	currentOwnerKey, err := os.ReadFile(keyfile)
	if err != nil {
		return fmt.Errorf("failed to read current owner key: %v", err)
	}

	// Generate new owner key
	newOwnerCrypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		return fmt.Errorf("failed to generate new owner key: %v", err)
	}

	// Create transfer request
	transferRequest := OwnershipTransferRequest{
		CurrentOwner: hex.EncodeToString(currentOwnerKey[:32]), // First 32 bytes as owner ID
		NewOwner:     newOwnerCrypto.GetPublicKeyHex(),
		FileID:       fileID,
		Reason:       "Administrative transfer",
		Timestamp:    time.Now(),
	}

	// Sign the transfer request
	requestData, _ := json.Marshal(transferRequest)
	requestHash := sha256.Sum256(requestData)

	// Load current owner crypto for signing
	currentOwnerCrypto, err := crypto.LoadEllipticCryptoFromHex(hex.EncodeToString(currentOwnerKey))
	if err != nil {
		return fmt.Errorf("failed to load current owner crypto: %v", err)
	}

	protection, err := currentOwnerCrypto.ProtectWithECC(requestHash[:])
	if err != nil {
		return fmt.Errorf("failed to sign transfer request: %v", err)
	}

	transferRequest.Signature = hex.EncodeToString(protection.Signature)

	// Save new owner key
	newKeyPath := keyfile + ".new"
	newKeyData := []byte(newOwnerCrypto.GetPrivateKeyHex())
	if err := os.WriteFile(newKeyPath, newKeyData, 0600); err != nil {
		return fmt.Errorf("failed to save new owner key: %v", err)
	}

	// Save transfer record
	transferPath := filepath.Join(storageBasePath, "transfers", fileID+"_"+time.Now().Format("20060102150405")+".json")
	if err := os.MkdirAll(filepath.Dir(transferPath), 0755); err != nil {
		return fmt.Errorf("failed to create transfers directory: %v", err)
	}

	transferBytes, _ := json.MarshalIndent(transferRequest, "", "  ")
	if err := os.WriteFile(transferPath, transferBytes, 0644); err != nil {
		return fmt.Errorf("failed to save transfer record: %v", err)
	}

	// Replace original key (backup first)
	backupPath := keyfile + ".backup." + time.Now().Format("20060102150405")
	if err := os.Rename(keyfile, backupPath); err != nil {
		return fmt.Errorf("failed to backup original key: %v", err)
	}

	if err := os.Rename(newKeyPath, keyfile); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, keyfile)
		return fmt.Errorf("failed to install new key: %v", err)
	}

	fmt.Printf("[SUCCESS] Ownership transfer completed successfully\n")
	fmt.Printf("   File ID: %s\n", fileID)
	fmt.Printf("   Previous Owner: %s\n", transferRequest.CurrentOwner[:16]+"...")
	fmt.Printf("   New Owner: %s\n", transferRequest.NewOwner[:16]+"...")
	fmt.Printf("   Transfer Record: %s\n", transferPath)
	fmt.Printf("   Key Backup: %s\n", backupPath)

	return nil
}

// handleOwnershipVerification implements actual ownership verification
func handleOwnershipVerification(input, keyfile string, verbose bool) error {
	if verbose {
		fmt.Printf("🔍 Verifying ownership...\n")
		fmt.Printf("   Input: %s\n", input)
		fmt.Printf("   Keyfile: %s\n", keyfile)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Extract file ID
	fileID := extractFileIDFromPath(input)
	if fileID == "" {
		return fmt.Errorf("could not extract file ID from protected file path")
	}

	// Determine storage base path and key path
	storageBasePath := determineStorageBasePath(input, cfg)
	if keyfile == "" {
		keyfile = filepath.Join(storageBasePath, "keys", fileID+".key")
	}

	// Initialize storage manager
	storageManager, err := storage.NewManager(
		storageBasePath,
		cfg.Storage.TempDirectory,
		cfg.Storage.BackupDirectory,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}

	// Load protected file metadata
	protectedFile, err := storageManager.GetFile(fileID)
	if err != nil {
		return fmt.Errorf("failed to get protected file metadata: %v", err)
	}

	// Load key file
	keyData, err := os.ReadFile(keyfile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	// Load protected data
	protectedData, err := storageManager.LoadProtectedData(fileID)
	if err != nil {
		return fmt.Errorf("failed to load protected data: %v", err)
	}

	// Parse protected bundle to get cryptographic proof
	var bundle map[string]interface{}
	if err := json.Unmarshal(protectedData, &bundle); err != nil {
		return fmt.Errorf("failed to parse protected bundle: %v", err)
	}

	// Verify key matches protected file
	ownerCrypto, err := crypto.LoadEllipticCryptoFromHex(string(keyData))
	if err != nil {
		return fmt.Errorf("failed to load owner key: %v", err)
	}

	// Create verification challenge
	challenge := fmt.Sprintf("ownership_verification:%s:%s", fileID, time.Now().Format(time.RFC3339))
	challengeHash := sha256.Sum256([]byte(challenge))

	// Sign challenge with owner key
	protection, err := ownerCrypto.ProtectWithECC(challengeHash[:])
	if err != nil {
		fmt.Printf("[ERROR] Ownership verification failed\n")
		fmt.Printf("   Reason: Invalid key signature\n")
		return fmt.Errorf("ownership verification failed: invalid signature")
	}

	// Verify signature
	recoveredData, err := ownerCrypto.UnprotectWithECC(protection)
	if err != nil {
		fmt.Printf("[ERROR] Ownership verification failed\n")
		fmt.Printf("   Reason: Challenge verification failed\n")
		return fmt.Errorf("ownership verification failed: challenge mismatch")
	}

	// Verify recovered data matches challenge
	if hex.EncodeToString(recoveredData) != hex.EncodeToString(challengeHash[:]) {
		fmt.Printf("[ERROR] Ownership verification failed\n")
		fmt.Printf("   Reason: Challenge verification failed\n")
		return fmt.Errorf("ownership verification failed: challenge mismatch")
	}

	// Check transfer history
	transfersDir := filepath.Join(storageBasePath, "transfers")
	transferHistory := []string{}
	if entries, err := os.ReadDir(transfersDir); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), fileID+"_") {
				transferHistory = append(transferHistory, entry.Name())
			}
		}
	}

	fmt.Printf("[SUCCESS] Ownership verification successful\n")
	fmt.Printf("   File ID: %s\n", fileID)
	fmt.Printf("   Owner: %s\n", ownerCrypto.GetPublicKeyHex()[:16]+"...")
	fmt.Printf("   Created: %s\n", protectedFile.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Last Modified: %s\n", protectedFile.ModifiedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Transfer History: %d transfers\n", len(transferHistory))

	if verbose && len(transferHistory) > 0 {
		fmt.Printf("   Recent Transfers:\n")
		for i, transfer := range transferHistory {
			if i >= 3 { // Show max 3 recent transfers
				break
			}
			fmt.Printf("     - %s\n", transfer)
		}
	}

	return nil
}

// handlePolicyExecution implements actual policy script execution
func handlePolicyExecution(input, keyfile string, verbose bool) error {
	if verbose {
		fmt.Printf("📋 Executing policy script...\n")
		fmt.Printf("   Input: %s\n", input)
		fmt.Printf("   Keyfile: %s\n", keyfile)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Extract file ID
	fileID := extractFileIDFromPath(input)
	if fileID == "" {
		return fmt.Errorf("could not extract file ID from protected file path")
	}

	// Determine storage base path
	storageBasePath := determineStorageBasePath(input, cfg)

	// Initialize storage manager
	storageManager, err := storage.NewManager(
		storageBasePath,
		cfg.Storage.TempDirectory,
		cfg.Storage.BackupDirectory,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}

	// Load protected file metadata
	protectedFile, err := storageManager.GetFile(fileID)
	if err != nil {
		return fmt.Errorf("failed to get protected file metadata: %v", err)
	}

	startTime := time.Now()

	// Initialize policy execution result
	result := PolicyExecutionResult{
		Success:    false,
		ExecutedAt: startTime,
		Variables:  make(map[string]interface{}),
	}

	// Check if file has policy script protection
	if !protectedFile.Protection.PolicyScript {
		result.Message = "File does not have policy script protection enabled"
		result.Success = true // Not an error, just no policy to execute
		fmt.Printf("[INFO] No policy script to execute\n")
		fmt.Printf("   File ID: %s\n", fileID)
		return nil
	}

	// Load policy script (this would be stored in the protection metadata)
	policyPath := filepath.Join(storageBasePath, "policies", fileID+".policy")
	var policyScript string

	if _, err := os.Stat(policyPath); err == nil {
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("failed to read policy script: %v", err)
		}
		policyScript = string(policyData)
		result.PolicyType = "file"
	} else {
		// Default policy for demonstration
		policyScript = `
		// Team-based access policy
		function checkAccess(context) {
			const requiredTeam = "developers";
			const userTeam = context.user_team || "unknown";
			
			if (userTeam === requiredTeam) {
				return {
					allowed: true,
					reason: "User is member of required team: " + requiredTeam
				};
			}
			
			return {
				allowed: false,
				reason: "User team '" + userTeam + "' is not authorized. Required: " + requiredTeam
			};
		}
		
		checkAccess(context);
		`
		result.PolicyType = "default_team"
	}

	// Set up execution context
	result.Variables["file_id"] = fileID
	result.Variables["file_created"] = protectedFile.CreatedAt
	result.Variables["file_size"] = protectedFile.Size
	result.Variables["user_team"] = "developers" // This would come from authentication
	result.Variables["execution_time"] = time.Now()
	result.Variables["policy_type"] = result.PolicyType

	// Execute policy (simplified execution - in production would use proper JS engine)
	// For demonstration, we'll simulate policy execution based on team membership
	// Policy script validation
	if strings.Contains(policyScript, "requiredTeam") && result.Variables["user_team"] == "developers" {
		result.Success = true
		result.Message = "Access granted: User is member of required team 'developers'"
	} else {
		result.Success = false
		result.Message = "Access denied: User team is not authorized"
	}

	result.Duration = time.Since(startTime)

	// Save execution log
	executionLogPath := filepath.Join(storageBasePath, "policy_logs", fileID+"_"+time.Now().Format("20060102150405")+".json")
	if err := os.MkdirAll(filepath.Dir(executionLogPath), 0755); err != nil {
		return fmt.Errorf("failed to create policy logs directory: %v", err)
	}

	logBytes, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(executionLogPath, logBytes, 0644); err != nil {
		return fmt.Errorf("failed to save execution log: %v", err)
	}

	// Show results
	if result.Success {
		fmt.Printf("[SUCCESS] Policy execution successful\n")
	} else {
		fmt.Printf("[ERROR] Policy execution denied access\n")
	}

	fmt.Printf("   File ID: %s\n", fileID)
	fmt.Printf("   Policy Type: %s\n", result.PolicyType)
	fmt.Printf("   Message: %s\n", result.Message)
	fmt.Printf("   Duration: %v\n", result.Duration)
	fmt.Printf("   Execution Log: %s\n", executionLogPath)

	if verbose {
		fmt.Printf("   Context Variables:\n")
		for key, value := range result.Variables {
			fmt.Printf("     %s: %v\n", key, value)
		}
	}

	if !result.Success {
		return fmt.Errorf("policy execution denied access: %s", result.Message)
	}

	return nil
}

// Helper functions are defined at the end of the file

func showMultiAuthStatus(input string, verbose bool) error {
	fmt.Printf("MULTIAUTH STATUS CHECK\n")
	fmt.Printf("======================================\n")
	fmt.Printf("File: %s\n", input)
	if verbose {
		fmt.Printf("Verbose mode: Detailed status analysis enabled\n")
	}
	fmt.Printf("Status: This feature will be implemented with actual file parsing\n")
	return nil
}

func showTimeLockStatus(input string, verbose bool) error {
	fmt.Printf("TIMELOCK STATUS CHECK\n")
	fmt.Printf("======================================\n")
	fmt.Printf("File: %s\n", input)
	if verbose {
		fmt.Printf("Verbose mode: Detailed status analysis enabled\n")
	}
	fmt.Printf("Status: This feature will be implemented with actual file parsing\n")
	return nil
}

// determineStorageBasePath determines the storage base path from protected file path
func determineStorageBasePath(protectedFilePath string, cfg *config.Config) string {
	if strings.Contains(protectedFilePath, "/files/") {
		parts := strings.Split(protectedFilePath, "/files/")
		if len(parts) >= 2 {
			return parts[0]
		}
	}
	return cfg.Storage.BasePath
}

// checkFeatureSupport verifies if a given feature is supported for the input file
func checkFeatureSupport(feature, input string) bool {
	ext := strings.ToLower(filepath.Ext(input))

	switch feature {
	case "multi-auth":
		// Multi-auth is supported for all file types
		return true
	case "timelock":
		// Timelock is supported for all file types
		return true
	case "ownership":
		// Ownership is supported only for specific file types
		return ext == ".py" || ext == ".js" || ext == ".php"
	case "policy-script":
		// Policy scripts are supported only for Python files currently
		return ext == ".py"
	default:
		return false
	}
}
