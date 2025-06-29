package network

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/purwowd/eden-core/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn interface for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  bytes.NewBuffer(nil),
		writeBuf: bytes.NewBuffer(nil),
	}
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error)  { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func setupSecureTransfer(t *testing.T) (*SecureTransferProtocol, *SecureTransferProtocol, *mockConn) {
	// Create shared ECC instance
	ecc, err := crypto.NewEllipticCrypto()
	require.NoError(t, err, "Failed to create ECC")

	// Get key pair
	privKeyHex := ecc.GetPrivateKeyHex()

	// Create config
	config := &TransferConfig{
		ChunkSize:     1024,
		WriteTimeout:  time.Second,
		RetryAttempts: 3,
	}

	// Create sender
	sender, err := NewSecureTransfer(config)
	require.NoError(t, err, "Failed to create sender")
	sender.ecc = ecc

	// Create receiver with same key
	receiver, err := NewSecureTransfer(config)
	require.NoError(t, err, "Failed to create receiver")
	receiverECC, err := crypto.LoadEllipticCryptoFromHex(privKeyHex)
	require.NoError(t, err, "Failed to load receiver ECC")
	receiver.ecc = receiverECC

	// Create mock connection
	conn := newMockConn()

	return sender, receiver, conn
}

func TestSecureTransfer(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		code    []byte
		wantErr bool
	}{
		{
			name:    "Basic source code",
			code:    []byte(`package main; func main() { println("hello") }`),
			wantErr: false,
		},
		{
			name:    "Empty code",
			code:    []byte{},
			wantErr: true,
		},
		{
			name:    "Large source code",
			code:    bytes.Repeat([]byte("large code test "), 1000),
			wantErr: false,
		},
		{
			name:    "Special characters",
			code:    []byte(`func specialChars() { return "!@#$%^&*()" }`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, receiver, conn := setupSecureTransfer(t)

			// Send code
			err := sender.SendProtectedCode(conn, tt.code)
			if tt.wantErr {
				assert.Error(t, err, "Expected error for invalid input")
				return
			}
			require.NoError(t, err, "SendProtectedCode failed")

			// Copy written data to read buffer for receiving
			conn.readBuf.Write(conn.writeBuf.Bytes())

			// Receive code
			received, err := receiver.ReceiveProtectedCode(conn)
			require.NoError(t, err, "ReceiveProtectedCode failed")

			// Verify
			assert.Equal(t, tt.code, received, "Received code doesn't match original")
		})
	}
}

func TestSecureTransferTampering(t *testing.T) {
	sender, receiver, conn := setupSecureTransfer(t)

	// Original code
	originalCode := []byte(`package main; func main() { println("sensitive") }`)

	// Send code
	err := sender.SendProtectedCode(conn, originalCode)
	require.NoError(t, err)

	// Read the transmitted data
	transmitted := conn.writeBuf.Bytes()

	// Parse header to find protection data
	protSize := binary.BigEndian.Uint32(transmitted[0:4])
	hashSize := binary.BigEndian.Uint32(transmitted[4:8])

	// Calculate offsets
	protStart := 8 // After header
	protEnd := protStart + int(protSize)
	hashStart := protEnd
	_ = hashStart + int(hashSize) // Full message size

	// Tamper with the protected data
	protData := transmitted[protStart:protEnd]
	// Modify the encrypted data part within the protection
	var protection crypto.EllipticCurveProtection
	err = json.Unmarshal(protData, &protection)
	require.NoError(t, err)

	// Tamper with encrypted data
	for i := 0; i < 10 && i < len(protection.EncryptedData); i++ {
		protection.EncryptedData[i] ^= 0xFF
	}

	// Re-marshal the protection
	tamperedProt, err := json.Marshal(protection)
	require.NoError(t, err)

	// Reconstruct the tampered transmission
	tamperedTransmission := make([]byte, 0, len(transmitted))
	tamperedTransmission = append(tamperedTransmission, transmitted[:protStart]...)
	tamperedTransmission = append(tamperedTransmission, tamperedProt...)
	tamperedTransmission = append(tamperedTransmission, transmitted[protEnd:]...)

	// Setup receiving
	conn.readBuf.Write(tamperedTransmission)

	// Try to receive tampered code
	_, err = receiver.ReceiveProtectedCode(conn)
	assert.Error(t, err, "Expected error due to tampering")
	assert.Contains(t, err.Error(), "tampered", "Error should indicate tampering")
}

func TestSecureTransferStats(t *testing.T) {
	sender, receiver, conn := setupSecureTransfer(t)

	// Test code
	testCode := []byte(`package main; func main() { println("test stats") }`)

	// Send and receive code multiple times
	for i := 0; i < 3; i++ {
		// Clear buffers
		conn.writeBuf.Reset()
		conn.readBuf.Reset()

		// Send
		err := sender.SendProtectedCode(conn, testCode)
		require.NoError(t, err)

		// Copy to read buffer
		conn.readBuf.Write(conn.writeBuf.Bytes())

		// Receive
		_, err = receiver.ReceiveProtectedCode(conn)
		require.NoError(t, err)
	}

	// Check stats
	stats := sender.GetStats()
	assert.Equal(t, int64(3), stats.OperationsCount, "Should have 3 send operations")
	assert.True(t, stats.EncryptionTime > 0, "Should have encryption time")
	assert.False(t, stats.LastOperation.IsZero(), "Should have last operation time")

	stats = receiver.GetStats()
	assert.Equal(t, int64(3), stats.OperationsCount, "Should have 3 receive operations")
	assert.True(t, stats.DecryptionTime > 0, "Should have decryption time")
	assert.False(t, stats.LastOperation.IsZero(), "Should have last operation time")
}

func TestSecureTransferEdgeCases(t *testing.T) {
	sender, _, conn := setupSecureTransfer(t)

	// Test nil code
	err := sender.SendProtectedCode(conn, nil)
	assert.Error(t, err, "Should error on nil code")

	// Test very small code
	tinyCode := []byte(`x`)
	err = sender.SendProtectedCode(conn, tinyCode)
	assert.NoError(t, err, "Should handle tiny code")

	// Test invalid connection
	err = sender.SendProtectedCode(nil, []byte(`test`))
	assert.Error(t, err, "Should error on nil connection")
}
