package vfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalBackend_PathNormalizationAndTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "smb-vfs-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "sub")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	testFile := filepath.Join(subDir, "hello.txt")
	if err := os.WriteFile(testFile, []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}

	backend, err := NewLocalBackend(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. Windows backslash path should resolve to sub/hello.txt
	h, err := backend.Open(ctx, OpenOptions{Path: `sub\hello.txt`, Disposition: DispositionOpen})
	if err != nil {
		t.Fatalf("open with backslash failed: %v", err)
	}
	_ = h.Close(ctx)

	// 2. Traversal attempt should be rejected with an error
	_, err = backend.Open(ctx, OpenOptions{Path: `..\..\etc\passwd`, Disposition: DispositionOpen})
	if err == nil {
		t.Fatalf("expected error on path traversal, got nil")
	}

	// 3. Forward slash traversal attempt should also be rejected
	_, err = backend.Open(ctx, OpenOptions{Path: `../../etc/passwd`, Disposition: DispositionOpen})
	if err == nil {
		t.Fatalf("expected error on path traversal, got nil")
	}
}
