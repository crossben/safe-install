//go:build !linux

package sandbox

import "errors"

// ABI is 0: Landlock is Linux-only.
func ABI() int { return 0 }

// Exec is unavailable outside Linux.
func Exec(Policy, string) error { return errUnsupported }

// Apply is unavailable outside Linux.
func Apply(Policy) error { return errUnsupported }

var errUnsupported = errors.New("the sandbox is Linux-only")
