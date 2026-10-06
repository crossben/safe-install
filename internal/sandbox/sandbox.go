// Package sandbox confines approved install scripts with Landlock (Linux):
// the script can read the system and the project, write only the package,
// the project's node_modules, temp and package caches, and cannot open the
// rest of the user's home or (by default) the network.
package sandbox

import (
	"errors"
	"fmt"
	"strings"
)

// Landlock ABI versions that matter here.
const (
	abiFiles = 1  // filesystem restrictions
	abiTCP   = 4  // TCP connect/bind
	abiUDP   = 10 // UDP connect/send (DNS)
)

// Errors from Check.
var (
	ErrUnavailable      = errors.New("the sandbox needs Landlock (Linux 5.13+, enabled in the kernel)")
	ErrNoNetworkControl = errors.New("this kernel's Landlock cannot block the network (needs Linux 6.7+); pass --sandbox-net to sandbox files only")
)

// Policy describes one script's sandbox.
type Policy struct {
	Project  string   // project root: readable; its node_modules writable
	Package  string   // the package whose script runs: writable
	ReadOnly []string // extra readable paths
	AllowNet bool     // leave the network open
}

// Check reports whether the sandbox can be enforced as asked on this kernel.
func Check(allowNet bool) error { return check(ABI(), allowNet) }

func check(abi int, allowNet bool) error {
	switch {
	case abi < abiFiles:
		return ErrUnavailable
	case abi < abiTCP && !allowNet:
		return ErrNoNetworkControl
	}
	return nil
}

// Capabilities describes what the kernel lets the sandbox enforce.
func Capabilities() string {
	v := ABI()
	var parts []string
	if v >= abiFiles {
		parts = append(parts, "files")
	}
	if v >= abiTCP {
		parts = append(parts, "TCP")
	}
	if v >= abiUDP {
		parts = append(parts, "UDP")
	}
	if len(parts) == 0 {
		return "nothing (Landlock unavailable)"
	}
	return strings.Join(parts, " + ")
}

// Summary is a one-line description for the CLI.
func Summary(allowNet bool) string {
	net := "network blocked"
	switch {
	case allowNet:
		net = "network allowed"
	case ABI() < abiUDP:
		net = "TCP blocked (UDP needs a newer kernel)"
	}
	return fmt.Sprintf("sandbox: home folder hidden, writes limited to the package, node_modules, temp and caches; %s", net)
}
