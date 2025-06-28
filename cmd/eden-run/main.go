package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <protected_file.eden>\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -q, --quiet    Silent mode (suppress Eden banner)\n")
		fmt.Fprintf(os.Stderr, "  -h, --help     Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s myapp.eden\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s -q myapp.eden\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	var protectedFile string
	var quietMode bool

	// Parse arguments
	for i, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help":
			fmt.Printf("Eden Run - Seamless execution of protected .eden files\n\n")
			fmt.Printf("Usage: %s [options] <protected_file.eden>\n\n", filepath.Base(os.Args[0]))
			fmt.Printf("Options:\n")
			fmt.Printf("  -q, --quiet    Silent mode (suppress Eden banner)\n")
			fmt.Printf("  -h, --help     Show this help message\n\n")
			fmt.Printf("Examples:\n")
			fmt.Printf("  %s myapp.eden           # Run protected file with banner\n", filepath.Base(os.Args[0]))
			fmt.Printf("  %s -q myapp.eden        # Run protected file silently\n", filepath.Base(os.Args[0]))
			fmt.Printf("  %s --quiet myapp.eden   # Run protected file silently\n", filepath.Base(os.Args[0]))
			os.Exit(0)
		case "-q", "--quiet":
			quietMode = true
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "Error: Unknown option '%s'\n", arg)
				fmt.Fprintf(os.Stderr, "Use '%s --help' for usage information.\n", filepath.Base(os.Args[0]))
				os.Exit(1)
			}
			if protectedFile == "" {
				protectedFile = arg
			} else {
				fmt.Fprintf(os.Stderr, "Error: Multiple files specified. Only one .eden file can be processed at a time.\n")
				os.Exit(1)
			}
		}
		_ = i
	}

	if protectedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: No protected file specified\n")
		fmt.Fprintf(os.Stderr, "Use '%s --help' for usage information.\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	// Validate file extension
	if !strings.HasSuffix(strings.ToLower(protectedFile), ".eden") {
		fmt.Fprintf(os.Stderr, "Error: File must have .eden extension (got: %s)\n", protectedFile)
		os.Exit(1)
	}

	// Check if file exists
	if _, err := os.Stat(protectedFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Protected file '%s' not found\n", protectedFile)
		os.Exit(1)
	}

	// Get the directory where this binary is located
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not determine executable path: %v\n", err)
		os.Exit(1)
	}

	binDir := filepath.Dir(execPath)
	edenBinary := filepath.Join(binDir, "eden")

	// Check if eden binary exists
	if _, err := os.Stat(edenBinary); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Eden binary not found at '%s'\n", edenBinary)
		fmt.Fprintf(os.Stderr, "Make sure eden-run is in the same directory as the eden binary.\n")
		os.Exit(1)
	}

	// Prepare command arguments
	args := []string{"-run", "-input", protectedFile}
	if quietMode {
		args = append([]string{"-quiet"}, args...)
	}

	// Execute the protected file through Eden Core
	cmd := exec.Command(edenBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// Preserve the original exit code
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: Failed to execute protected file: %v\n", err)
		os.Exit(1)
	}
}
