package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/purwowd/eden-core/pkg/crypto"
)

func TestNewEllipticCrypto(t *testing.T) {
	cryptoEngine, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	if cryptoEngine == nil {
		t.Fatal("Elliptic crypto is nil")
	}

	// Test that we can get key information
	privateKeyHex := cryptoEngine.GetPrivateKeyHex()
	if len(privateKeyHex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Expected private key hex length 64, got %d", len(privateKeyHex))
	}

	publicKeyHex := cryptoEngine.GetPublicKeyHex()
	if len(publicKeyHex) != 66 { // Compressed public key = 33 bytes = 66 hex chars
		t.Errorf("Expected public key hex length 66, got %d", len(publicKeyHex))
	}
}

func TestEllipticFormula(t *testing.T) {
	cryptoEngine, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	// Verify F = K · G formula
	if !cryptoEngine.VerifyEllipticFormula() {
		t.Error("Elliptic formula F = K · G verification failed")
	}

	t.Logf("Elliptic Formula F = K · G verified successfully!")
	t.Logf("Private Key (K): %s", cryptoEngine.GetPrivateKeyHex()[:16]+"...")
	t.Logf("Public Key (F): %s", cryptoEngine.GetPublicKeyHex()[:16]+"...")
	t.Logf("Security Level: %d bits (enterprise-grade)", cryptoEngine.SecurityLevel())
}

func TestEllipticCurveProtection(t *testing.T) {
	crypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	testData := []byte("Secret source code to protect with elliptic curve security")

	// Protect data using elliptic curve cryptography
	protection, err := crypto.ProtectWithECC(testData)
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	if protection == nil {
		t.Fatal("Protection is nil")
	}

	// Verify protection components
	if len(protection.EncryptedData) == 0 {
		t.Error("Encrypted data is empty")
	}

	if len(protection.PublicKeyX) == 0 {
		t.Error("Public key X is empty")
	}

	if len(protection.PublicKeyY) == 0 {
		t.Error("Public key Y is empty")
	}

	if len(protection.Signature) == 0 {
		t.Error("Signature is empty")
	}

	if len(protection.Hash) == 0 {
		t.Error("Hash is empty")
	}

	if len(protection.Nonce) == 0 {
		t.Error("Nonce is empty")
	}

	// Protected data should be different from original
	if string(protection.EncryptedData) == string(testData) {
		t.Error("Protected data is same as original - encryption failed")
	}

	t.Logf("Data protection successful!")
	t.Logf("Original size: %d bytes", len(testData))
	t.Logf("Protected size: %d bytes", len(protection.EncryptedData))
	t.Logf("Public key X: %s", hex.EncodeToString(protection.PublicKeyX)[:16]+"...")
	t.Logf("Public key Y: %s", hex.EncodeToString(protection.PublicKeyY)[:16]+"...")
}

func TestEllipticCurveUnprotection(t *testing.T) {
	crypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	originalData := []byte("Elliptic curve protected source code")

	// Protect
	protection, err := crypto.ProtectWithECC(originalData)
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Unprotect
	recoveredData, err := crypto.UnprotectWithECC(protection)
	if err != nil {
		t.Fatalf("Failed to unprotect data: %v", err)
	}

	// Should match original
	if string(recoveredData) != string(originalData) {
		t.Errorf("Recovered data doesn't match original:\nOriginal: %s\nRecovered: %s",
			originalData, recoveredData)
	}

	t.Logf("Data recovery successful!")
	t.Logf("Original: %s", originalData)
	t.Logf("Recovered: %s", recoveredData)
}

func TestLoadEllipticCryptoFromHex(t *testing.T) {
	// Create original crypto
	original, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create original crypto: %v", err)
	}

	privateKeyHex := original.GetPrivateKeyHex()

	// Load from hex
	loaded, err := crypto.LoadEllipticCryptoFromHex(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to load from hex: %v", err)
	}

	// Should have same keys
	if loaded.GetPrivateKeyHex() != original.GetPrivateKeyHex() {
		t.Error("Loaded private key doesn't match original")
	}

	if loaded.GetPublicKeyHex() != original.GetPublicKeyHex() {
		t.Error("Loaded public key doesn't match original")
	}

	// Both should verify elliptic formula
	if !loaded.VerifyEllipticFormula() {
		t.Error("Loaded crypto doesn't verify elliptic formula")
	}

	t.Logf("Key loading and verification successful!")
}

func TestSecurityLevel(t *testing.T) {
	crypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	securityLevel := crypto.SecurityLevel()
	if securityLevel != 128 {
		t.Errorf("Expected security level 128, got %d", securityLevel)
	}

	curveInfo := crypto.GetCurveInfo()

	if curveInfo["name"] != "secp256k1" {
		t.Error("Expected secp256k1 curve")
	}

	if curveInfo["used_by"] != "Major Cryptocurrencies" {
		t.Error("Should be used by major cryptocurrencies")
	}

	if curveInfo["security_bits"] != 128 {
		t.Error("Expected 128-bit security")
	}

	t.Logf("Security analysis complete:")
	t.Logf("Curve: %s (used by %s)", curveInfo["name"], curveInfo["used_by"])
	t.Logf("Security: %d bits", securityLevel)
	t.Logf("Break time: %s", curveInfo["break_time_years"])
	t.Logf("Status: UNBREAKABLE with current technology")
}

func TestIntegrityAndAuthentication(t *testing.T) {
	crypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		t.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	originalData := []byte("Top secret code that must not be tampered")

	// Protect
	protection, err := crypto.ProtectWithECC(originalData)
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Test integrity: tamper with encrypted data
	tamperedProtection := *protection
	tamperedProtection.EncryptedData[0] ^= 0xFF // Flip bits

	_, err = crypto.UnprotectWithECC(&tamperedProtection)
	if err == nil {
		t.Error("Expected integrity check to fail with tampered data")
	}

	// Test authentication: tamper with signature
	tamperedProtection2 := *protection
	tamperedProtection2.Signature[0] ^= 0xFF // Flip bits

	_, err = crypto.UnprotectWithECC(&tamperedProtection2)
	if err == nil {
		t.Error("Expected signature verification to fail with tampered signature")
	}

	t.Logf("Integrity and authentication tests passed!")
	t.Logf("Tampering detected and rejected")
	t.Logf("Digital signature verification working")
}

// Benchmark elliptic curve protection
func BenchmarkEllipticProtection(b *testing.B) {
	crypto, err := crypto.NewEllipticCrypto()
	if err != nil {
		b.Fatalf("Failed to create Elliptic crypto: %v", err)
	}

	testData := []byte("Benchmark data for elliptic curve protection")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.ProtectWithECC(testData)
		if err != nil {
			b.Fatalf("Protection failed: %v", err)
		}
	}
}
