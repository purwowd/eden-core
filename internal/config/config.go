package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the main application configuration
type Config struct {
	Environment string            `json:"environment"`
	Server      ServerConfig      `json:"server"`
	Security    SecurityConfig    `json:"security"`
	Storage     StorageConfig     `json:"storage"`
	Logging     LoggingConfig     `json:"logging"`
	Performance PerformanceConfig `json:"performance"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	KeyDirectory   string        `json:"key_directory"`
	MaxFileSize    int64         `json:"max_file_size"`
	AllowedFormats []string      `json:"allowed_formats"`
	SessionTimeout time.Duration `json:"session_timeout"`
	RequireHTTPS   bool          `json:"require_https"`
	RateLimitRPS   int           `json:"rate_limit_rps"`
}

// StorageConfig holds storage-related configuration
type StorageConfig struct {
	BasePath        string `json:"base_path"`
	TempDirectory   string `json:"temp_directory"`
	BackupDirectory string `json:"backup_directory"`
	MaxRetries      int    `json:"max_retries"`
	CleanupInterval string `json:"cleanup_interval"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	Output     string `json:"output"`
	MaxSize    int    `json:"max_size"`
	MaxAge     int    `json:"max_age"`
	MaxBackups int    `json:"max_backups"`
}

// PerformanceConfig holds performance tuning configuration
type PerformanceConfig struct {
	MaxWorkers     int           `json:"max_workers"`
	ChunkSize      int           `json:"chunk_size"`
	CacheSize      int           `json:"cache_size"`
	PoolSize       int           `json:"pool_size"`
	ProcessTimeout time.Duration `json:"process_timeout"`
}

// Load loads configuration from environment variables and config files
func Load() (*Config, error) {
	config := &Config{
		Environment: getEnvString("EDEN_ENV", "development"),
		Server: ServerConfig{
			Host:         getEnvString("EDEN_HOST", "localhost"),
			Port:         getEnvInt("EDEN_PORT", 8080),
			ReadTimeout:  getEnvDuration("EDEN_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("EDEN_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("EDEN_IDLE_TIMEOUT", 120*time.Second),
		},
		Security: SecurityConfig{
			KeyDirectory:   getEnvString("EDEN_KEY_DIR", "./keys"),
			MaxFileSize:    getEnvInt64("EDEN_MAX_FILE_SIZE", 100*1024*1024), // 100MB
			AllowedFormats: getEnvStringSlice("EDEN_ALLOWED_FORMATS", "py,js,php,go,java,rb,pl"),
			SessionTimeout: getEnvDuration("EDEN_SESSION_TIMEOUT", 24*time.Hour),
			RequireHTTPS:   getEnvBool("EDEN_REQUIRE_HTTPS", false),
			RateLimitRPS:   getEnvInt("EDEN_RATE_LIMIT", 100),
		},
		Storage: StorageConfig{
			BasePath:        getEnvString("EDEN_STORAGE_PATH", "./protected"),
			TempDirectory:   getEnvString("EDEN_TEMP_DIR", "/tmp/eden"),
			BackupDirectory: getEnvString("EDEN_BACKUP_DIR", "./backups"),
			MaxRetries:      getEnvInt("EDEN_MAX_RETRIES", 3),
			CleanupInterval: getEnvString("EDEN_CLEANUP_INTERVAL", "24h"),
		},
		Logging: LoggingConfig{
			Level:      getEnvString("EDEN_LOG_LEVEL", "info"),
			Format:     getEnvString("EDEN_LOG_FORMAT", "json"),
			Output:     getEnvString("EDEN_LOG_OUTPUT", "stdout"),
			MaxSize:    getEnvInt("EDEN_LOG_MAX_SIZE", 100),
			MaxAge:     getEnvInt("EDEN_LOG_MAX_AGE", 30),
			MaxBackups: getEnvInt("EDEN_LOG_MAX_BACKUPS", 10),
		},
		Performance: PerformanceConfig{
			MaxWorkers:     getEnvInt("EDEN_MAX_WORKERS", 4),
			ChunkSize:      getEnvInt("EDEN_CHUNK_SIZE", 8192),
			CacheSize:      getEnvInt("EDEN_CACHE_SIZE", 1000),
			PoolSize:       getEnvInt("EDEN_POOL_SIZE", 10),
			ProcessTimeout: getEnvDuration("EDEN_PROCESS_TIMEOUT", 5*time.Minute),
		},
	}

	// Load from config file if exists
	if configFile := getEnvString("EDEN_CONFIG_FILE", ""); configFile != "" {
		if err := loadFromFile(config, configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file: %v", err)
		}
	}

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %v", err)
	}

	// Ensure directories exist
	if err := ensureDirectories(config); err != nil {
		return nil, fmt.Errorf("failed to create directories: %v", err)
	}

	return config, nil
}

// loadFromFile loads configuration from JSON file
func loadFromFile(config *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, config)
}

// validate validates the configuration
func validate(config *Config) error {
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Server.Port)
	}

	if config.Security.MaxFileSize <= 0 {
		return fmt.Errorf("max file size must be positive")
	}

	if config.Performance.MaxWorkers <= 0 {
		return fmt.Errorf("max workers must be positive")
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[config.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

// ensureDirectories creates necessary directories
func ensureDirectories(config *Config) error {
	dirs := []string{
		config.Security.KeyDirectory,
		config.Storage.BasePath,
		config.Storage.TempDirectory,
		config.Storage.BackupDirectory,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// Helper functions for environment variables
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvStringSlice(key, defaultValue string) []string {
	value := getEnvString(key, defaultValue)
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}
