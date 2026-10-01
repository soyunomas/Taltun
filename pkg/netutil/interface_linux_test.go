package netutil

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestContainsFileExists(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "short error", err: errors.New("oops"), want: false},
		{name: "errno", err: syscall.EEXIST, want: true},
		{name: "wrapped errno", err: fmt.Errorf("netlink: %w", syscall.EEXIST), want: true},
		{name: "text fallback", err: errors.New("route add: file exists"), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsFileExists(tt.err); got != tt.want {
				t.Fatalf("containsFileExists(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
