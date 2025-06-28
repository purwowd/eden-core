package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "eden-config-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name    string
		envVars map[string]string
		want    *Config
		wantErr bool
	}{
		{
			name: "default config",
			want: &Config{
				Environment: "development",
				Server: ServerConfig{
					Host:         "localhost",
					Port:         8080,
					ReadTimeout:  30 * time.Second,
					WriteTimeout: 30 * time.Second,
					IdleTimeout:  120 * time.Second,
				},
				Security: SecurityConfig{
					KeyDirectory:   "./keys",
					MaxFileSize:    100 * 1024 * 1024,
					AllowedFormats: []string{"py", "js", "php", "go", "java", "rb", "pl"},
					SessionTimeout: 24 * time.Hour,
					RequireHTTPS:   false,
					RateLimitRPS:   100,
				},
				Storage: StorageConfig{
					BasePath:        "./protected",
					TempDirectory:   "/tmp/eden",
					BackupDirectory: "./backups",
					MaxRetries:      3,
					CleanupInterval: "24h",
				},
				Logging: LoggingConfig{
					Level:      "info",
					Format:     "json",
					Output:     "stdout",
					MaxSize:    100,
					MaxAge:     30,
					MaxBackups: 10,
				},
				Performance: PerformanceConfig{
					MaxWorkers:     4,
					ChunkSize:      8192,
					CacheSize:      1000,
					PoolSize:       10,
					ProcessTimeout: 5 * time.Minute,
				},
			},
			wantErr: false,
		},
		{
			name: "custom config from env",
			envVars: map[string]string{
				"EDEN_ENV":          "production",
				"EDEN_HOST":         "0.0.0.0",
				"EDEN_PORT":         "9000",
				"EDEN_LOG_LEVEL":    "debug",
				"EDEN_STORAGE_PATH": filepath.Join(tmpDir, "storage"),
				"EDEN_KEY_DIR":      filepath.Join(tmpDir, "keys"),
			},
			want: &Config{
				Environment: "production",
				Server: ServerConfig{
					Host:         "0.0.0.0",
					Port:         9000,
					ReadTimeout:  30 * time.Second,
					WriteTimeout: 30 * time.Second,
					IdleTimeout:  120 * time.Second,
				},
				Security: SecurityConfig{
					KeyDirectory:   filepath.Join(tmpDir, "keys"),
					MaxFileSize:    100 * 1024 * 1024,
					AllowedFormats: []string{"py", "js", "php", "go", "java", "rb", "pl"},
					SessionTimeout: 24 * time.Hour,
					RequireHTTPS:   false,
					RateLimitRPS:   100,
				},
				Storage: StorageConfig{
					BasePath:        filepath.Join(tmpDir, "storage"),
					TempDirectory:   "/tmp/eden",
					BackupDirectory: "./backups",
					MaxRetries:      3,
					CleanupInterval: "24h",
				},
				Logging: LoggingConfig{
					Level:      "debug",
					Format:     "json",
					Output:     "stdout",
					MaxSize:    100,
					MaxAge:     30,
					MaxBackups: 10,
				},
				Performance: PerformanceConfig{
					MaxWorkers:     4,
					ChunkSize:      8192,
					CacheSize:      1000,
					PoolSize:       10,
					ProcessTimeout: 5 * time.Minute,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			got, err := Load()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want.Environment, got.Environment)
			assert.Equal(t, tt.want.Server, got.Server)
			assert.Equal(t, tt.want.Security, got.Security)
			assert.Equal(t, tt.want.Storage, got.Storage)
			assert.Equal(t, tt.want.Logging, got.Logging)
			assert.Equal(t, tt.want.Performance, got.Performance)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Server: ServerConfig{
					Port: 8080,
				},
				Security: SecurityConfig{
					MaxFileSize: 1024 * 1024,
				},
				Performance: PerformanceConfig{
					MaxWorkers: 4,
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			config: &Config{
				Server: ServerConfig{
					Port: -1,
				},
				Security: SecurityConfig{
					MaxFileSize: 1024 * 1024,
				},
				Performance: PerformanceConfig{
					MaxWorkers: 4,
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			config: &Config{
				Server: ServerConfig{
					Port: 8080,
				},
				Security: SecurityConfig{
					MaxFileSize: 1024 * 1024,
				},
				Performance: PerformanceConfig{
					MaxWorkers: 4,
				},
				Logging: LoggingConfig{
					Level: "invalid",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "eden-config-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	config := &Config{
		Security: SecurityConfig{
			KeyDirectory: filepath.Join(tmpDir, "keys"),
		},
		Storage: StorageConfig{
			BasePath:        filepath.Join(tmpDir, "protected"),
			TempDirectory:   filepath.Join(tmpDir, "temp"),
			BackupDirectory: filepath.Join(tmpDir, "backups"),
		},
	}

	// Test directory creation
	err = ensureDirectories(config)
	assert.NoError(t, err)

	// Verify directories exist
	dirs := []string{
		config.Security.KeyDirectory,
		config.Storage.BasePath,
		config.Storage.TempDirectory,
		config.Storage.BackupDirectory,
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	}
}

func TestEnvironmentHelpers(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		wantProd    bool
		wantDev     bool
	}{
		{
			name:        "production environment",
			environment: "production",
			wantProd:    true,
			wantDev:     false,
		},
		{
			name:        "development environment",
			environment: "development",
			wantProd:    false,
			wantDev:     true,
		},
		{
			name:        "other environment",
			environment: "staging",
			wantProd:    false,
			wantDev:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Environment: tt.environment}
			assert.Equal(t, tt.wantProd, config.IsProduction())
			assert.Equal(t, tt.wantDev, config.IsDevelopment())
		})
	}
}
