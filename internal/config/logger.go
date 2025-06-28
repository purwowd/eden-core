package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the log level
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// String returns string representation of log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component"`
	Operation string                 `json:"operation,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	FileID    string                 `json:"file_id,omitempty"`
	Duration  string                 `json:"duration,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

// Logger provides structured logging capabilities
type Logger struct {
	config      *LoggingConfig
	level       LogLevel
	writer      io.Writer
	mu          sync.Mutex
	isJSON      bool
	component   string
	logFile     *os.File
	rotateSize  int64
	currentSize int64
}

// NewLogger creates a new logger instance
func NewLogger(config *LoggingConfig, component string) (*Logger, error) {
	logger := &Logger{
		config:     config,
		component:  component,
		rotateSize: int64(config.MaxSize) * 1024 * 1024, // Convert MB to bytes
		isJSON:     config.Format == "json",
	}

	// Parse log level
	level, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %v", err)
	}
	logger.level = level

	// Setup writer
	if err := logger.setupWriter(); err != nil {
		return nil, fmt.Errorf("failed to setup logger writer: %v", err)
	}

	return logger, nil
}

// Debug logs a debug message
func (l *Logger) Debug(message string, data ...map[string]interface{}) {
	l.log(LogLevelDebug, message, "", data...)
}

// Info logs an info message
func (l *Logger) Info(message string, data ...map[string]interface{}) {
	l.log(LogLevelInfo, message, "", data...)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, data ...map[string]interface{}) {
	l.log(LogLevelWarn, message, "", data...)
}

// Error logs an error message
func (l *Logger) Error(message string, err error, data ...map[string]interface{}) {
	errorStr := ""
	if err != nil {
		errorStr = err.Error()
	}
	l.log(LogLevelError, message, errorStr, data...)
}

// LogOperation logs an operation with timing
func (l *Logger) LogOperation(operation, message string, duration time.Duration, data ...map[string]interface{}) {
	entry := l.createLogEntry(LogLevelInfo, message, "")
	entry.Operation = operation
	entry.Duration = duration.String()

	if len(data) > 0 {
		entry.Data = data[0]
	}

	l.writeEntry(entry)
}

// LogSecurity logs security-related events
func (l *Logger) LogSecurity(event, userID, fileID string, data ...map[string]interface{}) {
	entry := l.createLogEntry(LogLevelInfo, fmt.Sprintf("Security event: %s", event), "")
	entry.UserID = userID
	entry.FileID = fileID

	if len(data) > 0 {
		entry.Data = data[0]
	}

	l.writeEntry(entry)
}

// LogAccess logs access events
func (l *Logger) LogAccess(operation, userID, fileID string, success bool, data ...map[string]interface{}) {
	level := LogLevelInfo
	message := fmt.Sprintf("Access %s: %s", operation, "SUCCESS")

	if !success {
		level = LogLevelWarn
		message = fmt.Sprintf("Access %s: %s", operation, "FAILED")
	}

	entry := l.createLogEntry(level, message, "")
	entry.Operation = operation
	entry.UserID = userID
	entry.FileID = fileID

	if len(data) > 0 {
		entry.Data = data[0]
	}

	l.writeEntry(entry)
}

// LogPerformance logs performance metrics
func (l *Logger) LogPerformance(operation string, duration time.Duration, metrics map[string]interface{}) {
	entry := l.createLogEntry(LogLevelInfo, fmt.Sprintf("Performance: %s", operation), "")
	entry.Operation = operation
	entry.Duration = duration.String()
	entry.Data = metrics

	l.writeEntry(entry)
}

// Close closes the logger and any open files
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// Internal methods

func (l *Logger) log(level LogLevel, message, errorStr string, data ...map[string]interface{}) {
	if level < l.level {
		return // Skip logs below current level
	}

	entry := l.createLogEntry(level, message, errorStr)

	if len(data) > 0 {
		entry.Data = data[0]
	}

	l.writeEntry(entry)
}

func (l *Logger) createLogEntry(level LogLevel, message, errorStr string) *LogEntry {
	entry := &LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Message:   message,
		Component: l.component,
		Error:     errorStr,
	}

	// Add caller information for debug level
	if level == LogLevelDebug || level == LogLevelError {
		if pc, file, line, ok := runtime.Caller(3); ok {
			function := runtime.FuncForPC(pc).Name()
			entry.Caller = fmt.Sprintf("%s:%d %s", filepath.Base(file), line, function)
		}
	}

	return entry
}

func (l *Logger) writeEntry(entry *LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var output string

	if l.isJSON {
		// JSON format
		data, err := json.Marshal(entry)
		if err != nil {
			// Fallback to simple format if JSON marshal fails
			output = fmt.Sprintf("[%s] %s %s: %s\n",
				entry.Timestamp, entry.Level, entry.Component, entry.Message)
		} else {
			output = string(data) + "\n"
		}
	} else {
		// Human readable format
		output = l.formatHumanReadable(entry)
	}

	// Write to configured output
	_, err := l.writer.Write([]byte(output))
	if err != nil {
		// Fallback to stderr if write fails
		fmt.Fprintf(os.Stderr, "Logger write error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Failed log entry: %s", output)
	}

	// Track size for rotation
	if l.logFile != nil {
		l.currentSize += int64(len(output))
		if l.currentSize > l.rotateSize {
			l.rotateLog()
		}
	}
}

func (l *Logger) formatHumanReadable(entry *LogEntry) string {
	var parts []string

	// Basic format: [timestamp] LEVEL component: message
	basic := fmt.Sprintf("[%s] %s %s: %s",
		entry.Timestamp, entry.Level, entry.Component, entry.Message)
	parts = append(parts, basic)

	// Add operation if present
	if entry.Operation != "" {
		parts = append(parts, fmt.Sprintf("op=%s", entry.Operation))
	}

	// Add user ID if present
	if entry.UserID != "" {
		parts = append(parts, fmt.Sprintf("user=%s", entry.UserID))
	}

	// Add file ID if present
	if entry.FileID != "" {
		parts = append(parts, fmt.Sprintf("file=%s", entry.FileID))
	}

	// Add duration if present
	if entry.Duration != "" {
		parts = append(parts, fmt.Sprintf("duration=%s", entry.Duration))
	}

	// Add error if present
	if entry.Error != "" {
		parts = append(parts, fmt.Sprintf("error=%s", entry.Error))
	}

	// Add caller if present
	if entry.Caller != "" {
		parts = append(parts, fmt.Sprintf("caller=%s", entry.Caller))
	}

	// Add data if present
	if len(entry.Data) > 0 {
		for k, v := range entry.Data {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}

	return strings.Join(parts, " ") + "\n"
}

func (l *Logger) setupWriter() error {
	switch l.config.Output {
	case "stdout":
		l.writer = os.Stdout
	case "stderr":
		l.writer = os.Stderr
	default:
		// File output
		if err := l.setupFileWriter(l.config.Output); err != nil {
			return err
		}
	}

	return nil
}

func (l *Logger) setupFileWriter(filename string) error {
	// Ensure log directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Open log file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	l.logFile = file
	l.writer = file

	// Get current file size
	if stat, err := file.Stat(); err == nil {
		l.currentSize = stat.Size()
	}

	return nil
}

func (l *Logger) rotateLog() {
	if l.logFile == nil {
		return
	}

	// Close current file
	l.logFile.Close()

	// Create rotated filename with timestamp
	originalName := l.config.Output
	timestamp := time.Now().Format("20060102-150405")
	rotatedName := fmt.Sprintf("%s.%s", originalName, timestamp)

	// Rename current file
	if err := os.Rename(originalName, rotatedName); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to rotate log file: %v\n", err)
		return
	}

	// Create new log file
	if err := l.setupFileWriter(originalName); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create new log file: %v\n", err)
		return
	}

	// Clean up old log files
	l.cleanupOldLogs()

	l.currentSize = 0
}

func (l *Logger) cleanupOldLogs() {
	if l.config.MaxBackups <= 0 {
		return
	}

	dir := filepath.Dir(l.config.Output)
	baseFilename := filepath.Base(l.config.Output)

	// Find all rotated log files
	files, err := filepath.Glob(filepath.Join(dir, baseFilename+".*"))
	if err != nil {
		return
	}

	// Remove excess files
	if len(files) > l.config.MaxBackups {
		// Sort by modification time and remove oldest
		for i := 0; i < len(files)-l.config.MaxBackups; i++ {
			os.Remove(files[i])
		}
	}

	// Remove files older than MaxAge days
	if l.config.MaxAge > 0 {
		cutoff := time.Now().AddDate(0, 0, -l.config.MaxAge)
		for _, file := range files {
			if stat, err := os.Stat(file); err == nil {
				if stat.ModTime().Before(cutoff) {
					os.Remove(file)
				}
			}
		}
	}
}

func parseLogLevel(levelStr string) (LogLevel, error) {
	switch strings.ToLower(levelStr) {
	case "debug":
		return LogLevelDebug, nil
	case "info":
		return LogLevelInfo, nil
	case "warn", "warning":
		return LogLevelWarn, nil
	case "error":
		return LogLevelError, nil
	default:
		return LogLevelInfo, fmt.Errorf("unknown log level: %s", levelStr)
	}
}

// Global logger instance
var globalLogger *Logger
var loggerOnce sync.Once

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config *LoggingConfig) error {
	var err error
	loggerOnce.Do(func() {
		globalLogger, err = NewLogger(config, "eden-core")
	})
	return err
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		// Create a default logger if none exists
		defaultConfig := &LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stderr",
		}
		logger, _ := NewLogger(defaultConfig, "eden-core")
		return logger
	}
	return globalLogger
}

// CloseGlobalLogger closes the global logger
func CloseGlobalLogger() error {
	if globalLogger != nil {
		return globalLogger.Close()
	}
	return nil
}
