package analyze

import (
	"testing"

	"github.com/crossben/safe-install/internal/ecosystem"
)

func TestRuleScopes(t *testing.T) {
	npmOnlyRules := map[string]bool{"SI-POP-002": true}
	for _, r := range Rules {
		for _, e := range []ecosystem.Ecosystem{ecosystem.NPM, "", ecosystem.PyPI, ecosystem.Packagist} {
			want := e.Or() == ecosystem.NPM || !npmOnlyRules[r.ID()]
			if r.ID() == "SI-BLD-001" {
				want = e == ecosystem.PyPI
			}
			if r.ID() == "SI-PLG-001" {
				want = e == ecosystem.Packagist
			}
			if got := appliesTo(r, e); got != want {
				t.Errorf("%s applies to %q = %v, want %v", r.ID(), e, got, want)
			}
		}
	}
}
