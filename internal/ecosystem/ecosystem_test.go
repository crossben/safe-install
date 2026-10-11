package ecosystem

import "testing"

func TestOSVName(t *testing.T) {
	for e, want := range map[Ecosystem]string{"": "npm", NPM: "npm", PyPI: "PyPI", Packagist: "Packagist"} {
		if got := e.OSVName(); got != want {
			t.Errorf("%q.OSVName() = %q, want %q", e, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		e          Ecosystem
		name, want string
	}{
		{PyPI, "Django", "django"},
		{PyPI, "zope.interface", "zope-interface"},
		{PyPI, "Typing_Extensions", "typing-extensions"},
		{PyPI, "a-_.b", "a-b"},
		{Packagist, "Monolog/Monolog", "monolog/monolog"},
		{NPM, "@Scope/Pkg", "@Scope/Pkg"},
	} {
		if got := Normalize(c.e, c.name); got != c.want {
			t.Errorf("Normalize(%s, %q) = %q, want %q", c.e, c.name, got, c.want)
		}
	}
}
