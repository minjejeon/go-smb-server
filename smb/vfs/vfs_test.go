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

func TestLocalBackend_RenameEscapeAndMove(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "smb-rename-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subA := filepath.Join(tmpDir, "subA")
	subB := filepath.Join(tmpDir, "subB")
	if err := os.Mkdir(subA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(subB, 0755); err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(subA, "test.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	backend, _ := NewLocalBackend(tmpDir)
	ctx := context.Background()

	h, err := backend.Open(ctx, OpenOptions{Path: `subA\test.txt`, Disposition: DispositionOpen})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(ctx)

	renamer, ok := h.(Renamer)
	if !ok {
		t.Fatal("expected Renamer interface")
	}

	// 1. Rename with ".." escape must fail
	if err := renamer.Rename(ctx, "..", true); err == nil {
		t.Fatal("expected error renaming to .., got nil")
	}
	if err := renamer.Rename(ctx, `..\escape.txt`, true); err == nil {
		t.Fatal("expected error renaming to ../escape.txt, got nil")
	}

	// 2. Safe move from subA to subB should succeed
	if err := renamer.Rename(ctx, `subB\moved.txt`, true); err != nil {
		t.Fatalf("failed to move file to subB: %v", err)
	}

	// Check that moved file exists in subB
	if _, err := os.Stat(filepath.Join(subB, "moved.txt")); err != nil {
		t.Fatalf("expected moved.txt in subB, got error: %v", err)
	}
}

