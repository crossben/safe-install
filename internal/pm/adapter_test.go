package pm

import (
	"errors"
	"testing"
)

func TestFor(t *testing.T) {
	a, err := For(NPM)
	if err != nil || a.Name() != NPM {
		t.Fatalf("For(npm) = %v, %v", a, err)
	}
	for _, k := range []Kind{PNPM, Yarn, Bun} {
		if _, err := For(k); !errors.Is(err, ErrNotYetSupported) {
			t.Errorf("For(%s) err = %v, want ErrNotYetSupported", k, err)
		}
	}
}
