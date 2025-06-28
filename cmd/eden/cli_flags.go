package main

import "flag"

// CLIFlags represents all command line flags
type CLIFlags struct {
	// Core operations
	Protect   *bool
	Run       *bool
	Deprotect *bool

	// Input/Output
	Input   *string
	Output  *string
	Keyfile *string

	// Options
	Recursive *bool
	Languages *string
	Verbose   *bool
	Quiet     *bool

	// Advanced Security Features
	MultiAuth      *string
	Signers        *string
	TimeLock       *string
	TimeLockType   *string
	OwnershipMode  *bool
	OwnershipValue *int64
	AccessRights   *string
	PolicyScript   *string
	PolicyType     *string

	// Advanced Feature Management
	MultiAuthSign     *bool
	MultiAuthStatus   *bool
	TimeLockStatus    *bool
	OwnershipTransfer *bool
	OwnershipVerify   *bool
	PolicyExecute     *bool

	// Network Operations
	BroadcastCode *bool
	VerifyAccess  *bool
	JoinNetwork   *bool
	NetworkStats  *bool

	// Utilities
	Examples  *bool
	Demo      *bool
	Security  *bool
	Benchmark *bool
}

// ParseFlags parses command line flags and returns CLIFlags struct
func ParseFlags() *CLIFlags {
	flags := &CLIFlags{
		// Core operations
		Protect:   flag.Bool("protect", false, "Protect source files with advanced security"),
		Run:       flag.Bool("run", false, "Run protected files"),
		Deprotect: flag.Bool("deprotect", false, "Remove protection from files"),

		// Input/Output
		Input:   flag.String("input", "", "Input file or directory path"),
		Output:  flag.String("output", "./protected", "Output directory for protected files"),
		Keyfile: flag.String("key", "", "Key file path"),

		// Options
		Recursive: flag.Bool("recursive", false, "Process directories recursively"),
		Languages: flag.String("languages", "py,js,php,go,java,rb,pl", "Comma-separated list of file extensions to process"),
		Verbose:   flag.Bool("verbose", false, "Enable verbose output"),
		Quiet:     flag.Bool("quiet", false, "Suppress banner and minimize output"),

		// Advanced Security Features
		MultiAuth:      flag.String("multiauth", "", "MultiAuth configuration (e.g., '2-of-3')"),
		Signers:        flag.String("signers", "", "Comma-separated list of signer keys"),
		TimeLock:       flag.String("timelock", "", "TimeLock configuration (e.g., '24h' or '2024-12-25T00:00:00Z')"),
		TimeLockType:   flag.String("timelock-type", "relative", "TimeLock type: 'relative', 'absolute', or 'block'"),
		OwnershipMode:  flag.Bool("ownership-mode", false, "Enable ownership protection"),
		OwnershipValue: flag.Int64("ownership-value", 1000000, "Ownership access value"),
		AccessRights:   flag.String("access-rights", "", "Comma-separated access rights"),
		PolicyScript:   flag.String("policyscript", "", "Policy script for access control"),
		PolicyType:     flag.String("policy-type", "team", "Policy type: 'team', 'time', 'reputation'"),

		// Advanced Feature Management
		MultiAuthSign:     flag.Bool("multiauth-sign", false, "Sign with MultiAuth"),
		MultiAuthStatus:   flag.Bool("multiauth-status", false, "Check MultiAuth status"),
		TimeLockStatus:    flag.Bool("timelock-status", false, "Check TimeLock status"),
		OwnershipTransfer: flag.Bool("ownership-transfer", false, "Transfer ownership"),
		OwnershipVerify:   flag.Bool("ownership-verify", false, "Verify ownership"),
		PolicyExecute:     flag.Bool("policy-execute", false, "Execute policy script"),

		// Network Operations
		BroadcastCode: flag.Bool("broadcast", false, "Broadcast protected code to network"),
		VerifyAccess:  flag.Bool("verify-access", false, "Verify access permissions"),
		JoinNetwork:   flag.Bool("join-network", false, "Join zero trust network"),
		NetworkStats:  flag.Bool("network-stats", false, "Show network statistics"),

		// Utilities
		Examples:  flag.Bool("examples", false, "Show usage examples"),
		Demo:      flag.Bool("demo", false, "Run advanced features demo"),
		Security:  flag.Bool("security", false, "Show security analysis"),
		Benchmark: flag.Bool("benchmark", false, "Run performance benchmarks"),
	}

	flag.Parse()
	return flags
}
