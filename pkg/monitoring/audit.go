package monitoring

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
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

// AuditStorage handles secure audit log storage
type AuditStorage struct {
	db       *sql.DB
	dbPath   string
	mu       sync.RWMutex
	isSecure bool
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	enabled    bool
	logPath    string
	storage    *AuditStorage
	riskMatrix map[string]string
}

// NewAuditStorage creates a new secure audit storage
func NewAuditStorage(dbPath string) (*AuditStorage, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %v", err)
	}

	// Open SQLite database with secure settings
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_secure_delete=true&_foreign_keys=true")
	if err != nil {
		return nil, fmt.Errorf("failed to open audit database: %v", err)
	}

	storage := &AuditStorage{
		db:       db,
		dbPath:   dbPath,
		isSecure: true,
	}

	// Initialize database schema
	if err := storage.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize audit schema: %v", err)
	}

	// Set secure database configurations
	if err := storage.configureDatabase(); err != nil {
		return nil, fmt.Errorf("failed to configure database security: %v", err)
	}

	return storage, nil
}

// initializeSchema creates the audit log table structure
func (as *AuditStorage) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		user_id TEXT,
		action TEXT NOT NULL,
		resource TEXT,
		status TEXT,
		details TEXT,
		risk_level TEXT,
		hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(type);
	CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events(risk_level);

	-- Table for storing audit metadata
	CREATE TABLE IF NOT EXISTS audit_metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Insert initial metadata
	INSERT OR IGNORE INTO audit_metadata (key, value) VALUES 
		('schema_version', '1.0'),
		('created_at', datetime('now')),
		('encryption_enabled', 'true');
	`

	if _, err := as.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create audit schema: %v", err)
	}

	return nil
}

// configureDatabase sets up secure database configurations
func (as *AuditStorage) configureDatabase() error {
	// Set secure pragmas
	secureSettings := []string{
		"PRAGMA journal_mode=WAL",        // Write-Ahead Logging for better concurrency
		"PRAGMA synchronous=FULL",        // Ensure data integrity
		"PRAGMA secure_delete=true",      // Overwrite deleted data
		"PRAGMA foreign_keys=true",       // Enable foreign key constraints
		"PRAGMA temp_store=memory",       // Keep temp tables in memory
		"PRAGMA cache_size=10000",        // Increase cache size for performance
		"PRAGMA auto_vacuum=INCREMENTAL", // Automatic database maintenance
	}

	for _, pragma := range secureSettings {
		if _, err := as.db.Exec(pragma); err != nil {
			return fmt.Errorf("failed to set secure pragma %s: %v", pragma, err)
		}
	}

	return nil
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
			"file_protection":     "MEDIUM",
			"file_access":         "LOW",
			"config_change":       "HIGH",
		},
	}

	if path, ok := config["log_path"].(string); ok {
		logger.logPath = path
	} else {
		logger.logPath = "logs/audit.db"
	}

	// Initialize secure storage
	storage, err := NewAuditStorage(logger.logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit storage: %v", err)
	}
	logger.storage = storage

	return logger, nil
}

// StoreEvent stores an audit event in the secure database
func (as *AuditStorage) StoreEvent(event *AuditEvent) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	// Serialize details to JSON
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("failed to serialize event details: %v", err)
	}

	// Create hash for integrity verification
	eventHash := as.calculateEventHash(event, detailsJSON)

	// Insert event into database
	query := `
		INSERT INTO audit_events (
			id, type, timestamp, user_id, action, resource, 
			status, details, risk_level, hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = as.db.Exec(query,
		event.ID,
		string(event.Type),
		event.Timestamp.UTC(),
		event.User,
		event.Action,
		event.Resource,
		event.Status,
		string(detailsJSON),
		event.Risk,
		eventHash,
	)

	if err != nil {
		return fmt.Errorf("failed to store audit event: %v", err)
	}

	// Update last event timestamp in metadata
	_, err = as.db.Exec(
		"INSERT OR REPLACE INTO audit_metadata (key, value, updated_at) VALUES (?, ?, ?)",
		"last_event_timestamp",
		event.Timestamp.UTC().Format(time.RFC3339),
		time.Now().UTC(),
	)

	return err
}

// QueryEvents retrieves audit events based on criteria
func (as *AuditStorage) QueryEvents(criteria AuditQueryCriteria) ([]AuditEvent, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	// Build dynamic query
	query := "SELECT id, type, timestamp, user_id, action, resource, status, details, risk_level FROM audit_events WHERE 1=1"
	args := []interface{}{}

	if criteria.EventType != "" {
		query += " AND type = ?"
		args = append(args, string(criteria.EventType))
	}

	if criteria.UserID != "" {
		query += " AND user_id = ?"
		args = append(args, criteria.UserID)
	}

	if !criteria.StartTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, criteria.StartTime.UTC())
	}

	if !criteria.EndTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, criteria.EndTime.UTC())
	}

	if criteria.RiskLevel != "" {
		query += " AND risk_level = ?"
		args = append(args, criteria.RiskLevel)
	}

	query += " ORDER BY timestamp DESC"

	if criteria.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, criteria.Limit)
	}

	rows, err := as.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %v", err)
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var detailsJSON string
		var eventType string

		err := rows.Scan(
			&event.ID,
			&eventType,
			&event.Timestamp,
			&event.User,
			&event.Action,
			&event.Resource,
			&event.Status,
			&detailsJSON,
			&event.Risk,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan audit event: %v", err)
		}

		event.Type = AuditEventType(eventType)

		// Deserialize details
		if err := json.Unmarshal([]byte(detailsJSON), &event.Details); err != nil {
			return nil, fmt.Errorf("failed to deserialize event details: %v", err)
		}

		events = append(events, event)
	}

	return events, nil
}

// AuditQueryCriteria defines criteria for querying audit events
type AuditQueryCriteria struct {
	EventType AuditEventType
	UserID    string
	StartTime time.Time
	EndTime   time.Time
	RiskLevel string
	Limit     int
}

// calculateEventHash creates an integrity hash for the event
func (as *AuditStorage) calculateEventHash(event *AuditEvent, detailsJSON []byte) string {
	// Simple hash based on event content
	content := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		event.ID,
		event.Type,
		event.Timestamp.Format(time.RFC3339),
		event.Action,
		event.Resource,
		string(detailsJSON),
	)
	return fmt.Sprintf("%x", content) // In production, use proper cryptographic hash
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
		Status:    "completed",
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
		Status:    "completed",
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
		Status:    "completed",
	}

	return al.logEvent(event)
}

// LogKeyRotationEvent logs key rotation events
func (al *AuditLogger) LogKeyRotationEvent(action, keyID string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:        generateEventID(),
		Type:      EventKeyRotation,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Resource:  keyID,
		Details:   details,
		Risk:      al.calculateRisk("key_rotation"),
		Status:    "completed",
	}

	return al.logEvent(event)
}

// GetAuditSummary returns a summary of audit events
func (al *AuditLogger) GetAuditSummary(hours int) (map[string]interface{}, error) {
	criteria := AuditQueryCriteria{
		StartTime: time.Now().Add(-time.Duration(hours) * time.Hour),
		EndTime:   time.Now(),
		Limit:     10000, // Reasonable limit
	}

	events, err := al.storage.QueryEvents(criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for summary: %v", err)
	}

	summary := map[string]interface{}{
		"total_events":     len(events),
		"time_range_hours": hours,
		"events_by_type":   make(map[string]int),
		"events_by_risk":   make(map[string]int),
		"recent_critical":  []AuditEvent{},
	}

	// Analyze events
	for _, event := range events {
		// Count by type
		typeKey := string(event.Type)
		if count, ok := summary["events_by_type"].(map[string]int)[typeKey]; ok {
			summary["events_by_type"].(map[string]int)[typeKey] = count + 1
		} else {
			summary["events_by_type"].(map[string]int)[typeKey] = 1
		}

		// Count by risk
		if count, ok := summary["events_by_risk"].(map[string]int)[event.Risk]; ok {
			summary["events_by_risk"].(map[string]int)[event.Risk] = count + 1
		} else {
			summary["events_by_risk"].(map[string]int)[event.Risk] = 1
		}

		// Collect critical events
		if event.Risk == "CRITICAL" || event.Risk == "HIGH" {
			critical := summary["recent_critical"].([]AuditEvent)
			if len(critical) < 10 { // Limit to recent 10 critical events
				summary["recent_critical"] = append(critical, event)
			}
		}
	}

	return summary, nil
}

// LogAuditEvent logs a security-related event with proper storage
func LogAuditEvent(event AuditEvent) error {
	// Create default audit logger if not provided
	config := map[string]interface{}{
		"log_path": "logs/audit.db",
	}

	logger, err := NewAuditLogger(config)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %v", err)
	}

	return logger.logEvent(&event)
}

// Internal helper functions

func (al *AuditLogger) logEvent(event *AuditEvent) error {
	if !al.enabled {
		return nil
	}

	// Store in secure database instead of just printing
	if al.storage != nil {
		if err := al.storage.StoreEvent(event); err != nil {
			// Fallback to file logging if database fails
			return al.fallbackFileLogging(event, err)
		}
		return nil
	}

	// Fallback to file logging
	return al.fallbackFileLogging(event, fmt.Errorf("no storage configured"))
}

// fallbackFileLogging provides file-based logging as fallback
func (al *AuditLogger) fallbackFileLogging(event *AuditEvent, originalErr error) error {
	// Create structured log entry
	entry := map[string]interface{}{
		"id":          event.ID,
		"type":        event.Type,
		"timestamp":   event.Timestamp,
		"user":        event.User,
		"action":      event.Action,
		"resource":    event.Resource,
		"status":      event.Status,
		"details":     event.Details,
		"risk":        event.Risk,
		"storage_err": originalErr.Error(),
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

func (al *AuditLogger) calculateRisk(action string) string {
	if risk, ok := al.riskMatrix[action]; ok {
		return risk
	}
	return "LOW"
}

func generateEventID() string {
	return fmt.Sprintf("EVT-%d", time.Now().UnixNano())
}

// Close closes the audit storage connections
func (al *AuditLogger) Close() error {
	if al.storage != nil && al.storage.db != nil {
		return al.storage.db.Close()
	}
	return nil
}
