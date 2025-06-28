package crypto

import (
	"bytes"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	t.Run("GenerateKey", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		if len(key) != KeySize {
			t.Errorf("Expected key size %d, got %d", KeySize, len(key))
		}
	})

	t.Run("GenerateKeyPair", func(t *testing.T) {
		pub, priv, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		if len(pub) == 0 || len(priv) == 0 {
			t.Error("Generated keys should not be empty")
		}

		if bytes.Equal(pub, priv) {
			t.Error("Public and private keys should be different")
		}
	})
}

func TestKeyDerivation(t *testing.T) {
	t.Run("DeriveKey", func(t *testing.T) {
		password := []byte("test password")
		salt := []byte("test salt")

		key1, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("Key derivation failed: %v", err)
		}

		key2, err := DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("Second key derivation failed: %v", err)
		}

		if !bytes.Equal(key1, key2) {
			t.Error("Derived keys should be identical for same input")
		}
	})

	t.Run("DifferentSalts", func(t *testing.T) {
		password := []byte("test password")
		salt1 := []byte("salt1")
		salt2 := []byte("salt2")

		key1, err := DeriveKey(password, salt1)
		if err != nil {
			t.Fatalf("First key derivation failed: %v", err)
		}

		key2, err := DeriveKey(password, salt2)
		if err != nil {
			t.Fatalf("Second key derivation failed: %v", err)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Keys derived with different salts should be different")
		}
	})
}
