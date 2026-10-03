package pm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrNotYetSupported is returned for package managers detected but not driven yet.
var ErrNotYetSupported = errors.New("not supported yet")

// Adapter drives one package manager.
type Adapter interface {
	Name() Kind
	// InstallNoScripts installs dependencies in dir with every lifecycle
	// script disabled.
	InstallNoScripts(ctx context.Context, dir string, opts InstallOptions) error
}

// InstallOptions configures an install.
type InstallOptions struct {
	Args           []string  // passed through to the package manager
	Before         time.Time // resolve only versions published before this; zero disables
	Stdout, Stderr io.Writer
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
