package sandbox

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		abi      int
		allowNet bool
		want     error
	}{
		{0, false, ErrUnavailable},
		{0, true, ErrUnavailable},
		{3, false, ErrNoNetworkControl},
		{3, true, nil},
		{4, false, nil},
		{8, false, nil},
	}
	for _, c := range cases {
		if err := check(c.abi, c.allowNet); !errors.Is(err, c.want) {
			t.Errorf("check(abi %d, net %v) = %v, want %v", c.abi, c.allowNet, err, c.want)
		}
	}
}
