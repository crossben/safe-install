//go:build linux

package sandbox

import "testing"

func TestABIProbe(t *testing.T) {
	t.Logf("Landlock ABI %d, enforces: %s", ABI(), Capabilities())
}
