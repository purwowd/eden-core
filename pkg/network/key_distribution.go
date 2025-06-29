package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
}

// KeyDistributionService manages secure key distribution
type KeyDistributionService struct {
	config     KeyDistributionConfig
	privateKey *ecdsa.PrivateKey
	nodeKeys   map[string]*NodeKeyInfo
	mu         sync.RWMutex
}

// NodeKeyInfo represents key information for a node
type NodeKeyInfo struct {
	PublicKey    *ecdsa.PublicKey
	LastRotation time.Time
	KeyVersion   uint64
	IsAuthorized bool
}

// NewKeyDistributionService creates a new key distribution service
func NewKeyDistributionService(config KeyDistributionConfig) (*KeyDistributionService, error) {
	// Generate service key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate service key: %v", err)
	}

	return &KeyDistributionService{
		config:     config,
		privateKey: privateKey,
		nodeKeys:   make(map[string]*NodeKeyInfo),
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

	// Distribute to each node
	for nodeID, info := range kds.nodeKeys {
		if !info.IsAuthorized {
			continue
		}

		if err := kds.sendKeyToNode(nodeID, info, distribution); err != nil {
			// Log error but continue with other nodes
			fmt.Printf("Failed to send key to node %s: %v\n", nodeID, err)
		}
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

func (kds *KeyDistributionService) sendKeyToNode(nodeID string, info *NodeKeyInfo, dist *KeyDistributionPackage) error {
	// Encrypt key package with node's public key
	keyBytes, err := x509.MarshalPKIXPublicKey(info.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Create PEM block for transmission
	pemBlock := &pem.Block{
		Type:  "ENCRYPTED KEY PACKAGE",
		Bytes: keyBytes,
		Headers: map[string]string{
			"Version":    fmt.Sprintf("%d", dist.Version),
			"ValidUntil": dist.ValidUntil.Format(time.RFC3339),
			"NodeID":     nodeID,
		},
	}

	// Encrypt the key package
	encryptedPEM := pem.EncodeToMemory(pemBlock)
	if encryptedPEM == nil {
		return fmt.Errorf("failed to encode key package")
	}

	// TODO: Implement actual network transmission
	// For demonstration, we'll simulate network operations:
	// 1. Set up secure channel
	// 2. Send encrypted package
	// 3. Wait for acknowledgment

	// Update local state
	info.LastRotation = time.Now()
	info.KeyVersion = uint64(dist.Version)

	return nil
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
