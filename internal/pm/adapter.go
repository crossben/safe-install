package pm

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrNotYetSupported is returned for package managers detected but not driven yet.
var ErrNotYetSupported = errors.New("not supported yet")

// Adapter drives one package manager.
type Adapter interface {
	Name() Kind
	// InstallNoScripts installs dependencies in dir with every lifecycle
	// script disabled. args are passed through to the package manager.
	InstallNoScripts(ctx context.Context, dir string, args []string, stdout, stderr io.Writer) error
}

// For returns the adapter for k.
func For(k Kind) (Adapter, error) {
	switch k {
	case NPM:
		return npmAdapter{}, nil
	case PNPM, Yarn, Bun:
		return nil, fmt.Errorf("%s: %w (coming in a later release)", k, ErrNotYetSupported)
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownPM, k)
}
