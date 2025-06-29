package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/purwowd/eden-core/pkg/crypto"
)

// SecureTransferConfig represents configuration for secure code transfer
type SecureTransferConfig struct {
	TransportKey   []byte        // Key for transport encryption
	ChunkSize      int           // Size of each chunk for streaming
	Timeout        time.Duration // Network timeout
	RetryAttempts  int           // Number of retry attempts
	VerifyChecksum bool          // Whether to verify checksum after transfer
}

// SecureTransferProtocol handles secure code transfer using ECC
type SecureTransferProtocol struct {
	config *TransferConfig
	ecc    *crypto.EllipticCrypto
	stats  *TransferStats
}

// TransferConfig holds configuration for secure transfer
type TransferConfig struct {
	ChunkSize     int           `json:"chunk_size"`
	WriteTimeout  time.Duration `json:"write_timeout"`
	RetryAttempts int           `json:"retry_attempts"`
}

// TransferStats tracks performance metrics
type TransferStats struct {
	EncryptionTime  time.Duration
	DecryptionTime  time.Duration
	OperationsCount int64
	LastOperation   time.Time
	mu              sync.RWMutex
}

// ProtectedData represents protected code bundle
type ProtectedData struct {
	Protection *crypto.EllipticCurveProtection
	Hash       []byte
}

// NewSecureTransfer creates a new secure transfer protocol using ECC
func NewSecureTransfer(config *TransferConfig) (*SecureTransferProtocol, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Initialize ECC for encryption and signatures
	ecc, err := crypto.NewEllipticCrypto()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ECC: %v", err)
	}

	return &SecureTransferProtocol{
		config: config,
		ecc:    ecc,
		stats:  &TransferStats{},
	}, nil
}

// SendProtectedCode sends protected code securely using ECC
func (st *SecureTransferProtocol) SendProtectedCode(conn net.Conn, code []byte) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}
	if code == nil {
		return fmt.Errorf("code cannot be nil")
	}
	if len(code) == 0 {
		return fmt.Errorf("code cannot be empty")
	}

	start := time.Now()

	// Calculate integrity hash before protection
	hash := sha256.Sum256(code)

	// Protect code using ECC
	protection, err := st.ecc.ProtectWithECC(code)
	if err != nil {
		return fmt.Errorf("failed to protect code with ECC: %v", err)
	}

	// Create protected data bundle
	bundle := &ProtectedData{
		Protection: protection,
		Hash:       hash[:],
	}

	// Send protected data
	if err := st.sendProtectedData(conn, bundle); err != nil {
		return fmt.Errorf("failed to send protected data: %v", err)
	}

	// Update stats
	st.updateStats(start, len(code), true)
	return nil
}

// ReceiveProtectedCode receives and verifies protected code
func (st *SecureTransferProtocol) ReceiveProtectedCode(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection cannot be nil")
	}

	start := time.Now()

	// Receive protected data
	bundle, err := st.receiveProtectedData(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive protected data: %v", err)
	}

	// Unprotect code using ECC
	code, err := st.ecc.UnprotectWithECC(bundle.Protection)
	if err != nil {
		return nil, fmt.Errorf("failed to unprotect code with ECC: %v", err)
	}

	// Verify integrity
	hash := sha256.Sum256(code)
	if !bytes.Equal(hash[:], bundle.Hash) {
		return nil, fmt.Errorf("integrity check failed: code has been tampered")
	}

	// Update stats
	st.updateStats(start, len(code), false)
	return code, nil
}

// Internal helper functions

func (st *SecureTransferProtocol) sendProtectedData(conn net.Conn, data *ProtectedData) error {
	// Marshal protection data
	protBytes, err := json.Marshal(data.Protection)
	if err != nil {
		return fmt.Errorf("failed to marshal protection: %v", err)
	}

	// Prepare header with sizes
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(protBytes)))
	binary.BigEndian.PutUint32(header[4:8], uint32(len(data.Hash)))

	// Send header
	if err := st.writeWithTimeout(conn, header); err != nil {
		return fmt.Errorf("failed to send header: %v", err)
	}

	// Send protection data
	if err := st.writeWithTimeout(conn, protBytes); err != nil {
		return fmt.Errorf("failed to send protection data: %v", err)
	}

	// Send hash
	if err := st.writeWithTimeout(conn, data.Hash); err != nil {
		return fmt.Errorf("failed to send hash: %v", err)
	}

	return nil
}

func (st *SecureTransferProtocol) receiveProtectedData(conn net.Conn) (*ProtectedData, error) {
	// Read header
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	protSize := binary.BigEndian.Uint32(header[0:4])
	hashSize := binary.BigEndian.Uint32(header[4:8])

	if protSize == 0 || hashSize == 0 {
		return nil, fmt.Errorf("invalid data sizes in header")
	}

	// Read protection data
	protBytes := make([]byte, protSize)
	if _, err := io.ReadFull(conn, protBytes); err != nil {
		return nil, fmt.Errorf("failed to read protection data: %v", err)
	}

	// Read hash
	hash := make([]byte, hashSize)
	if _, err := io.ReadFull(conn, hash); err != nil {
		return nil, fmt.Errorf("failed to read hash: %v", err)
	}

	// Unmarshal protection
	var protection crypto.EllipticCurveProtection
	if err := json.Unmarshal(protBytes, &protection); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protection: %v", err)
	}

	return &ProtectedData{
		Protection: &protection,
		Hash:       hash,
	}, nil
}

func (st *SecureTransferProtocol) writeWithTimeout(conn net.Conn, data []byte) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}

	deadline := time.Now().Add(st.config.WriteTimeout)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}
	_, err := conn.Write(data)
	return err
}

func (st *SecureTransferProtocol) updateStats(start time.Time, bytes int, isEncryption bool) {
	duration := time.Since(start)

	st.stats.mu.Lock()
	defer st.stats.mu.Unlock()

	if isEncryption {
		st.stats.EncryptionTime += duration
	} else {
		st.stats.DecryptionTime += duration
	}

	st.stats.OperationsCount++
	st.stats.LastOperation = time.Now()
}

// GetStats returns current transfer statistics
func (st *SecureTransferProtocol) GetStats() *TransferStats {
	st.stats.mu.RLock()
	defer st.stats.mu.RUnlock()

	// Create a copy of stats without the mutex
	statsCopy := &TransferStats{
		EncryptionTime:  st.stats.EncryptionTime,
		DecryptionTime:  st.stats.DecryptionTime,
		OperationsCount: st.stats.OperationsCount,
		LastOperation:   st.stats.LastOperation,
	}
	return statsCopy
}
