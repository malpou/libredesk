package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The kubelet rewrites a projected token in place; every reconnect must send the new one.
func TestPasswordFromFileRereadsOnEveryCall(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := passwordFromFile("libredesk/libredesk", file)

	if u, p := creds(); u != "libredesk/libredesk" || p != "first" {
		t.Fatalf("got %q/%q, want libredesk/libredesk/first", u, p)
	}
	if err := os.WriteFile(file, []byte("rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, p := creds(); p != "rotated" {
		t.Fatalf("password %q after rotation, want rotated", p)
	}
}
