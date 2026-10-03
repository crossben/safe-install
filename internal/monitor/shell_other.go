//go:build !linux

package monitor

// Supported reports whether monitoring can run here: only on Linux.
func Supported() error { return ErrUnsupportedOS }

// RunShell is never reached outside Linux (no session can be created).
func RunShell([]string) int { return 1 }
