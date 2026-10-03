package analyze

import (
	"sort"
	"strings"
)

// Explanation documents one rule for `safe-install explain`.
type Explanation struct {
	ID, Title, Why, Fix string
}

var explanations = []Explanation{
	{"SI-SCR-001", "Package runs install scripts",
		"preinstall/install/postinstall scripts run arbitrary code on your machine during install. Most malicious packages use them.",
		"Read the script. If it is expected (native builds, binary downloads from the project's own release), approve it: safe-install approve <pkg>."},
	{"SI-SCR-002", "Install script downloads and executes code",
		"Piping a download into a shell (curl | sh, iwr | iex, encoded PowerShell) runs code nobody reviewed, fetched at install time.",
		"Do not approve. Find out why the package does this; report it to the registry if it looks malicious."},
	{"SI-SCR-003", "Install script evaluates dynamic or encoded code",
		"eval, new Function and long encoded blobs are how malware hides its payload from review.",
		"Inspect the decoded code before approving. Legitimate install scripts rarely need this."},
	{"SI-SCR-004", "Install script touches credentials",
		"Reading ~/.ssh, ~/.npmrc, cloud credentials or token variables during install is the classic way to steal secrets.",
		"Do not approve unless you understand exactly why the package needs them."},
	{"SI-SCR-005", "Install scripts changed since approval",
		"The scripts, or the files they run, differ from what was approved, as happens when a package is compromised.",
		"Review the new scripts, then approve again: safe-install approve <pkg>."},
	{"SI-REC-001", "Version published recently",
		"Compromised releases are usually caught and unpublished within days. Waiting minReleaseAge before using a version avoids most of them.",
		"Wait, pin an older version, or exempt a trusted fast-moving package with minReleaseAgeExclude in .safe-install.json."},
	{"SI-REC-002", "Unusual publisher on a recent release",
		"A release published without the provenance its predecessor had, or by someone who never published the package before, is what a stolen token looks like.",
		"Check the package's repository and release notes for this version before using it."},
	{"SI-DEP-001", "Deprecated or missing version",
		"Deprecated versions get no fixes; a version missing from the registry was likely unpublished, sometimes for being malicious.",
		"Upgrade to a supported version."},
	{"SI-INT-001", "Lockfile hash does not match the registry",
		"The tarball your lockfile expects is not the one the registry serves: the lockfile was edited or the package was tampered with.",
		"Do not install. Regenerate the lockfile from a trusted state and find out how it changed."},
	{"SI-INT-002", "Package downloaded from outside the registry",
		"A lockfile entry pointing at another host can serve anything, bypassing the registry.",
		"Make sure the URL is expected (a private mirror); otherwise regenerate the lockfile."},
}

// Explain returns the explanation for a rule ID (case-insensitive).
func Explain(id string) (Explanation, bool) {
	for _, e := range explanations {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return Explanation{}, false
}

// Explanations returns every rule, sorted by ID.
func Explanations() []Explanation {
	out := append([]Explanation(nil), explanations...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
