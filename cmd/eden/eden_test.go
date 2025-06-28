package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMainCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		setup    func() error
		cleanup  func() error
		validate func(t *testing.T)
	}{
		{
			name:    "help command",
			args:    []string{"-help"},
			wantErr: false,
		},
		{
			name:    "version command",
			args:    []string{"-version"},
			wantErr: false,
		},
		{
			name:    "invalid flag",
			args:    []string{"-invalid"},
			wantErr: true,
		},
		{
			name: "protect command",
			args: []string{"-protect", "testfile.py"},
			setup: func() error {
				return os.WriteFile("testfile.py", []byte("print('test')"), 0644)
			},
			cleanup: func() error {
				return os.Remove("testfile.py")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				err := tt.setup()
				assert.NoError(t, err)
			}

			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = append([]string{"eden"}, tt.args...)

			if tt.cleanup != nil {
				defer func() {
					err := tt.cleanup()
					assert.NoError(t, err)
				}()
			}

			if tt.validate != nil {
				tt.validate(t)
			}
		})
	}
}

func TestAdvancedFeatures(t *testing.T) {
	tests := []struct {
		name    string
		feature string
		input   string
		want    bool
	}{
		{
			name:    "test multi-auth protection",
			feature: "multi-auth",
			input:   "test.py",
			want:    true,
		},
		{
			name:    "test timelock protection",
			feature: "timelock",
			input:   "test.py",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			err := os.WriteFile(tt.input, []byte("print('test')"), 0644)
			assert.NoError(t, err)
			defer os.Remove(tt.input)

			result := checkFeatureSupport(tt.feature, tt.input)
			assert.Equal(t, tt.want, result)
		})
	}
}
