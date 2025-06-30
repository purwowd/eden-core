package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"
)

// KeyDistributionConfig represents configuration for key distribution
type KeyDistributionConfig struct {
	RotationInterval time.Duration
	KeySize          int
	MaxNodes         int
	QuorumSize       int
	RetryInterval    time.Duration
	NetworkTimeout   time.Duration
	TLSConfig        *tls.Config
	Port             int
}

// NetworkNode represents a network node for key distribution
type NetworkNode struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	IsActive bool   `json:"is_active"`
}

// KeyDistributionService manages secure key distribution
type KeyDistributionService struct {
	config       KeyDistributionConfig
	privateKey   *ecdsa.PrivateKey
	nodeKeys     map[string]*NodeKeyInfo
	networkNodes map[string]*NetworkNode
	mu           sync.RWMutex
}

// NodeKeyInfo represents key information for a node
type NodeKeyInfo struct {
	PublicKey    *ecdsa.PublicKey
	LastRotation time.Time
	KeyVersion   uint64
	IsAuthorized bool
}

// NetworkMessage represents a message sent over the network
type NetworkMessage struct {
	Type      string      `json:"type"`
	From      string      `json:"from"`
	To        string      `json:"to"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
	Signature []byte      `json:"signature"`
}

// NewKeyDistributionService creates a new key distribution service
func NewKeyDistributionService(config KeyDistributionConfig) (*KeyDistributionService, error) {
	// Generate service key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate service key: %v", err)
	}

	// Set default configuration values
	if config.NetworkTimeout == 0 {
		config.NetworkTimeout = 30 * time.Second
	}
	if config.Port == 0 {
		config.Port = 8443
	}

	return &KeyDistributionService{
		config:       config,
		privateKey:   privateKey,
		nodeKeys:     make(map[string]*NodeKeyInfo),
		networkNodes: make(map[string]*NetworkNode),
	}, nil
}

// RegisterNode registers a new node for key distribution
func (kds *KeyDistributionService) RegisterNode(nodeID string, publicKey *ecdsa.PublicKey) error {
	kds.mu.Lock()
	defer kds.mu.Unlock()

	if len(kds.nodeKeys) >= kds.config.MaxNodes {
		return fmt.Errorf("maximum number of nodes reached")
	}

	kds.nodeKeys[nodeID] = &NodeKeyInfo{
		PublicKey:    publicKey,
		LastRotation: time.Now(),
		KeyVersion:   1,
		IsAuthorized: true,
	}

	return nil
}

// RegisterNetworkNode registers a network node with address information
func (kds *KeyDistributionService) RegisterNetworkNode(nodeID, address string, port int) error {
	kds.mu.Lock()
	defer kds.mu.Unlock()

	kds.networkNodes[nodeID] = &NetworkNode{
		ID:       nodeID,
		Address:  address,
		Port:     port,
		IsActive: true,
	}

	return nil
}

// DistributeKey securely distributes a new key to registered nodes
func (kds *KeyDistributionService) DistributeKey(key []byte) error {
	kds.mu.RLock()
	defer kds.mu.RUnlock()

	// Ensure we have enough nodes for quorum
	if len(kds.nodeKeys) < kds.config.QuorumSize {
		return fmt.Errorf("insufficient nodes for key distribution")
	}

	// Prepare key distribution package
	distribution := &KeyDistributionPackage{
		Key:        key,
		Version:    time.Now().UnixNano(),
		ValidUntil: time.Now().Add(kds.config.RotationInterval),
		Signatures: make(map[string][]byte),
	}

	// Sign the key package
	if err := kds.signDistribution(distribution); err != nil {
		return fmt.Errorf("failed to sign distribution: %v", err)
	}

	// Distribute to each node with actual network transmission
	var wg sync.WaitGroup
	errors := make(chan error, len(kds.nodeKeys))

	for nodeID, info := range kds.nodeKeys {
		if !info.IsAuthorized {
			continue
		}

		wg.Add(1)
		go func(nodeID string, info *NodeKeyInfo) {
			defer wg.Done()
			if err := kds.sendKeyToNodeWithNetwork(nodeID, info, distribution); err != nil {
				errors <- fmt.Errorf("failed to send key to node %s: %v", nodeID, err)
			}
		}(nodeID, info)
	}

	// Wait for all distributions to complete
	wg.Wait()
	close(errors)

	// Collect any errors
	var distributionErrors []error
	for err := range errors {
		distributionErrors = append(distributionErrors, err)
	}

	// Return error if too many distributions failed
	if len(distributionErrors) > len(kds.nodeKeys)/2 {
		return fmt.Errorf("key distribution failed to majority of nodes: %v", distributionErrors)
	}

	return nil
}

// KeyDistributionPackage represents a secure key distribution package
type KeyDistributionPackage struct {
	Key        []byte
	Version    int64
	ValidUntil time.Time
	Signatures map[string][]byte
}

// sendKeyToNodeWithNetwork implements actual network transmission
func (kds *KeyDistributionService) sendKeyToNodeWithNetwork(nodeID string, info *NodeKeyInfo, dist *KeyDistributionPackage) error {
	// Get network node information
	networkNode, exists := kds.networkNodes[nodeID]
	if !exists {
		return fmt.Errorf("no network information for node %s", nodeID)
	}

	if !networkNode.IsActive {
		return fmt.Errorf("node %s is not active", nodeID)
	}

	// Encrypt key package with node's public key
	encryptedPackage, err := kds.encryptForNode(dist, info.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt package for node: %v", err)
	}

	// Create network message
	message := &NetworkMessage{
		Type:      "KEY_DISTRIBUTION",
		From:      "key-distribution-service",
		To:        nodeID,
		Timestamp: time.Now(),
		Data:      encryptedPackage,
	}

	// Sign the message
	if err := kds.signMessage(message); err != nil {
		return fmt.Errorf("failed to sign message: %v", err)
	}

	// Establish secure connection with retry mechanism
	var conn net.Conn
	var connErr error
	for retries := 0; retries < 3; retries++ {
		conn, connErr = kds.establishSecureConnection(networkNode.Address, networkNode.Port)
		if connErr == nil {
			break
		}
		time.Sleep(kds.config.RetryInterval)
	}

	if connErr != nil {
		return fmt.Errorf("failed to establish connection after retries: %v", connErr)
	}
	defer conn.Close()

	// Send message over secure connection
	if err := kds.sendMessage(conn, message); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	// Wait for acknowledgment
	ack, err := kds.receiveAcknowledgment(conn)
	if err != nil {
		return fmt.Errorf("failed to receive acknowledgment: %v", err)
	}

	if !ack.Success {
		return fmt.Errorf("node rejected key distribution: %s", ack.Message)
	}

	// Update local state on successful transmission
	info.LastRotation = time.Now()
	info.KeyVersion = uint64(dist.Version)

	return nil
}

// establishSecureConnection creates a TLS connection to the target node
func (kds *KeyDistributionService) establishSecureConnection(address string, port int) (net.Conn, error) {
	// Create TLS configuration
	tlsConfig := kds.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false, // In production, properly configure certificates
		}
	}

	// Establish connection with timeout
	dialer := &net.Dialer{
		Timeout: kds.config.NetworkTimeout,
	}

	target := fmt.Sprintf("%s:%d", address, port)
	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %v", err)
	}

	return conn, nil
}

// sendMessage sends a message over the connection
func (kds *KeyDistributionService) sendMessage(conn net.Conn, message *NetworkMessage) error {
	// Set write deadline
	if err := conn.SetWriteDeadline(time.Now().Add(kds.config.NetworkTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	// Serialize message to JSON
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	// Send message length first (4 bytes)
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(len(messageBytes) >> 24)
	lengthBytes[1] = byte(len(messageBytes) >> 16)
	lengthBytes[2] = byte(len(messageBytes) >> 8)
	lengthBytes[3] = byte(len(messageBytes))

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send message length: %v", err)
	}

	// Send message data
	if _, err := conn.Write(messageBytes); err != nil {
		return fmt.Errorf("failed to send message data: %v", err)
	}

	return nil
}

// AcknowledgmentMessage represents an acknowledgment response
type AcknowledgmentMessage struct {
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// receiveAcknowledgment receives an acknowledgment from the node
func (kds *KeyDistributionService) receiveAcknowledgment(conn net.Conn) (*AcknowledgmentMessage, error) {
	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(kds.config.NetworkTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}

	// Read message length
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read acknowledgment length: %v", err)
	}

	length := int(lengthBytes[0])<<24 | int(lengthBytes[1])<<16 | int(lengthBytes[2])<<8 | int(lengthBytes[3])

	// Read message data
	messageBytes := make([]byte, length)
	if _, err := conn.Read(messageBytes); err != nil {
		return nil, fmt.Errorf("failed to read acknowledgment data: %v", err)
	}

	// Deserialize acknowledgment
	var ack AcknowledgmentMessage
	if err := json.Unmarshal(messageBytes, &ack); err != nil {
		return nil, fmt.Errorf("failed to deserialize acknowledgment: %v", err)
	}

	return &ack, nil
}

// encryptForNode encrypts a package for a specific node
func (kds *KeyDistributionService) encryptForNode(dist *KeyDistributionPackage, nodePublicKey *ecdsa.PublicKey) ([]byte, error) {
	// Serialize the distribution package
	packageBytes, err := json.Marshal(dist)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize package: %v", err)
	}

	// For simplicity, we'll use the public key to derive an encryption key
	// In production, use proper ECIES encryption
	keyBytes, err := x509.MarshalPKIXPublicKey(nodePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Create encryption key from public key hash
	hash := sha256.Sum256(keyBytes)
	encryptionKey := hash[:]

	// Simple XOR encryption (in production, use AES-GCM)
	encrypted := make([]byte, len(packageBytes))
	for i, b := range packageBytes {
		encrypted[i] = b ^ encryptionKey[i%len(encryptionKey)]
	}

	return encrypted, nil
}

// signMessage signs a network message
func (kds *KeyDistributionService) signMessage(message *NetworkMessage) error {
	// Serialize message data for signing
	dataBytes, err := json.Marshal(message.Data)
	if err != nil {
		return fmt.Errorf("failed to serialize message data: %v", err)
	}

	// Create hash of message content
	hash := sha256.Sum256(dataBytes)

	// Sign with service private key
	r, s, err := ecdsa.Sign(rand.Reader, kds.privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign message: %v", err)
	}

	// Store signature
	message.Signature = append(r.Bytes(), s.Bytes()...)
	return nil
}

// Internal helper functions

func (kds *KeyDistributionService) signDistribution(dist *KeyDistributionPackage) error {
	// Create distribution hash
	hash := sha256.Sum256(append(dist.Key,
		append([]byte(fmt.Sprintf("%d", dist.Version)),
			[]byte(dist.ValidUntil.Format(time.RFC3339))...)...))

	// Sign with service private key
	r, s, err := ecdsa.Sign(rand.Reader, kds.privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign distribution: %v", err)
	}

	// Store signature
	signature := append(r.Bytes(), s.Bytes()...)
	dist.Signatures["service"] = signature

	return nil
}

// Legacy method for backwards compatibility
func (kds *KeyDistributionService) sendKeyToNode(nodeID string, info *NodeKeyInfo, dist *KeyDistributionPackage) error {
	return kds.sendKeyToNodeWithNetwork(nodeID, info, dist)
}

// ExportPublicKey exports the service's public key in PEM format
func (kds *KeyDistributionService) ExportPublicKey() ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(&kds.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
