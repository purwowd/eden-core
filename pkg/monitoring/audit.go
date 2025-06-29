package monitoring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuditEventType represents different types of auditable events
type AuditEventType string

const (
	EventProtection   AuditEventType = "PROTECTION"
	EventAccess       AuditEventType = "ACCESS"
	EventModification AuditEventType = "MODIFICATION"
	EventKeyRotation  AuditEventType = "KEY_ROTATION"
	EventIntegrity    AuditEventType = "INTEGRITY"
	EventSecurity     AuditEventType = "SECURITY"
)

// AuditEvent represents a security-relevant event
type AuditEvent struct {
	ID        string                 `json:"id"`
	Type      AuditEventType         `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	User      string                 `json:"user"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Status    string                 `json:"status"`
	Details   map[string]interface{} `json:"details"`
	Risk      string                 `json:"risk_level"`
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	enabled    bool
	logPath    string
	riskMatrix map[string]string
}

// NewAuditLogger creates a new security audit logger
func NewAuditLogger(config map[string]interface{}) (*AuditLogger, error) {
	logger := &AuditLogger{
		enabled: true,
		riskMatrix: map[string]string{
			"key_rotation":        "HIGH",
			"integrity_violation": "CRITICAL",
			"unauthorized_access": "HIGH",
			"protection_failure":  "MEDIUM",
		},
	}

	if path, ok := config["log_path"].(string); ok {
		logger.logPath = path
	}

	return logger, nil
}

// LogProtectionEvent logs code protection events
func (al *AuditLogger) LogProtectionEvent(action, resource string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:        generateEventID(),
		Type:      EventProtection,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Resource:  resource,
		Details:   details,
		Risk:      al.calculateRisk(action),
	}

	return al.logEvent(event)
}

// LogSecurityEvent logs security-related events
func (al *AuditLogger) LogSecurityEvent(action, resource string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:        generateEventID(),
		Type:      EventSecurity,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Resource:  resource,
		Details:   details,
		Risk:      al.calculateRisk(action),
	}

	return al.logEvent(event)
}

// LogIntegrityEvent logs code integrity events
func (al *AuditLogger) LogIntegrityEvent(resource string, report map[string]interface{}) error {
	event := &AuditEvent{
		ID:        generateEventID(),
		Type:      EventIntegrity,
		Timestamp: time.Now().UTC(),
		Action:    "integrity_check",
		Resource:  resource,
		Details:   report,
		Risk:      al.calculateRisk("integrity_check"),
	}

	return al.logEvent(event)
}

// LogAuditEvent logs a security-related event with proper storage
func LogAuditEvent(event AuditEvent) error {
	// Create structured log entry
	entry := map[string]interface{}{
		"id":        event.ID,
		"type":      event.Type,
		"timestamp": event.Timestamp,
		"user":      event.User,
		"action":    event.Action,
		"resource":  event.Resource,
		"status":    event.Status,
		"details":   event.Details,
		"risk":      event.Risk,
	}

	// Convert to JSON for storage
	logBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %v", err)
	}

	// Store in secure audit log file with append-only permissions
	logFile := filepath.Join("logs", "audit.log")
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Open file in append mode with restrictive permissions
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %v", err)
	}
	defer f.Close()

	// Write log entry with newline
	if _, err := f.Write(append(logBytes, '\n')); err != nil {
		return fmt.Errorf("failed to write audit log: %v", err)
	}

	return nil
}

// Internal helper functions

func (al *AuditLogger) logEvent(event *AuditEvent) error {
	if !al.enabled {
		return nil
	}

	// Convert event to JSON
	eventJSON, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %v", err)
	}

	// TODO: Implement proper log storage (e.g., secure database)
	// For now, just print to stdout
	fmt.Printf("AUDIT EVENT: %s\n", string(eventJSON))

	return nil
}

func (al *AuditLogger) calculateRisk(action string) string {
	if risk, ok := al.riskMatrix[action]; ok {
		return risk
	}
	return "LOW"
}

func generateEventID() string {
	return fmt.Sprintf("EVT-%d", time.Now().UnixNano())
}
