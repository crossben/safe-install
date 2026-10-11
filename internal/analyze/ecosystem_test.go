package analyze

import (
	"testing"

	"github.com/crossben/safe-install/internal/ecosystem"
)

func TestRuleScopes(t *testing.T) {
	npmOnlyRules := map[string]bool{"SI-REC-002": true, "SI-POP-001": true, "SI-POP-002": true}
	for _, r := range Rules {
		for _, e := range []ecosystem.Ecosystem{ecosystem.NPM, "", ecosystem.PyPI, ecosystem.Packagist} {
			want := e.Or() == ecosystem.NPM || !npmOnlyRules[r.ID()]
			if got := appliesTo(r, e); got != want {
				t.Errorf("%s applies to %q = %v, want %v", r.ID(), e, got, want)
			}
		}
	}
}
