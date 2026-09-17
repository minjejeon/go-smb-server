# Comprehensive Improvements Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Comprehensively resolve critical security vulnerabilities, stability DoS flaws, protocol spec violations, and compatibility bugs in `go-smb-server`.

**Architecture:** Strengthen the VFS layer with Windows path normalization and strict root boundary/symlink validation; introduce connection-level panic recovery and request size boundaries; fix directory enumeration cursor pagination; fix compound request signing order; and promote file locks/oplocks to server/share scope.

**Tech Stack:** Go 1.26 (Pure Go, stdlib `path`, `path/filepath`, `os`, `sync`, `net`, `crypto`), SMB2/SMB3 Wire Protocol.

---

### Task 1: VFS Path Normalization & Root Boundary Enforcement

**Files:**
- Modify: `smb/vfs/vfs.go`
- Test: `smb/vfs/vfs_test.go`

**Step 1: Write the failing test**
Create `smb/vfs/vfs_test.go` testing that Windows backslash paths (`dir\file.txt`) and directory traversal attacks (`../../etc/passwd`) are correctly normalized and confined to the share root.

```go
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

	// 2. Traversal attempt should be rejected
	_, err = backend.Open(ctx, OpenOptions{Path: `..\..\etc\passwd`, Disposition: DispositionOpen})
	if err == nil {
		t.Fatalf("expected error on path traversal, got nil")
	}
}
```

**Step 2: Run test to verify it fails**
Run: `go test -v ./smb/vfs`
Expected: FAIL (backslash path cannot be opened or traversal not rejected with permission error)

**Step 3: Write minimal implementation**
In `smb/vfs/vfs.go`:
- Implement `cleanPath(p string) string` that converts `\` to `/` and runs `path.Clean("/" + p)`.
- Implement `safeFullPath(root, p string) (string, error)` that verifies `filepath.Rel(b.Root, full)` does not escape.
- Update `LocalBackend.fullPath`, `Remove`, `Mkdir`, `Open`, and `CopyChunk`.

**Step 4: Run test to verify it passes**
Run: `go test -v ./smb/vfs`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/vfs/vfs.go smb/vfs/vfs_test.go
git commit -m "fix(vfs): normalize Windows path separators and enforce root boundary"
```

---

### Task 2: VFS `Rename` Directory Escape Prevention & File Move

**Files:**
- Modify: `smb/vfs/vfs.go`
- Test: `smb/vfs/vfs_test.go`

**Step 1: Write the failing test**
Add test in `smb/vfs/vfs_test.go` ensuring `Rename("..")` or `Rename("../escaped.txt")` is rejected, and moving files between subdirectories is permitted safely within the share root.

```go
func TestLocalBackend_RenameEscapeAndMove(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "smb-rename-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subA := filepath.Join(tmpDir, "subA")
	subB := filepath.Join(tmpDir, "subB")
	_ = os.Mkdir(subA, 0755)
	_ = os.Mkdir(subB, 0755)

	filePath := filepath.Join(subA, "test.txt")
	_ = os.WriteFile(filePath, []byte("data"), 0644)

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
}
```

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestLocalBackend_RenameEscapeAndMove ./smb/vfs`
Expected: FAIL

**Step 3: Write minimal implementation**
In `smb/vfs/vfs.go`:
Update `localHandle.Rename` to resolve target path against `b.Root` using `safeFullPath`, ensuring target is inside root and not a directory escape.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestLocalBackend_RenameEscapeAndMove ./smb/vfs`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/vfs/vfs.go smb/vfs/vfs_test.go
git commit -m "fix(vfs): prevent directory traversal on rename and support cross-dir move"
```

---

### Task 3: Read-Only Share Support

**Files:**
- Modify: `smb/vfs/vfs.go`
- Modify: `smb/server/dispatch.go`
- Test: `smb/server/server_test.go`

**Step 1: Write the failing test**
In `smb/server/server_test.go`, test that mounting a read-only share allows read operations but rejects create/write/delete with `STATUS_ACCESS_DENIED`.

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestReadOnlyShare ./smb/server`
Expected: FAIL

**Step 3: Write minimal implementation**
- In `smb/vfs/vfs.go`: Add `ReadOnly() bool` to `Share` interface and implement in `DiskShare` via `WithReadOnly(bool)` or `NewReadOnlyDiskShare()`.
- In `smb/server/dispatch.go`: In `handleCreate`, `handleWrite`, `handleSetInfo`, return `StatusAccessDenied` if `tr.share.ReadOnly()`.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestReadOnlyShare ./smb/server`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/vfs/vfs.go smb/server/dispatch.go smb/server/server_test.go
git commit -m "feat(vfs,server): add read-only share enforcement"
```

---

### Task 4: Server Panic Recovery & DoS Bounds Validation

**Files:**
- Modify: `smb/server/server.go`
- Modify: `smb/server/dispatch.go`
- Test: `smb/server/server_test.go`

**Step 1: Write the failing test**
Test that `handleRead` with `req.Length > maxRead` returns `StatusInvalidParameter` and does not crash, and test that unexpected panics in a connection handler are caught without killing the server.

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestReadLengthValidation ./smb/server`
Expected: FAIL

**Step 3: Write minimal implementation**
- In `smb/server/server.go`: Add `defer func() { if r := recover(); r != nil { ... } }()` in `serveConn`.
- In `smb/server/dispatch.go`:
  - In `handleRead`: check `req.Length > c.srv.maxRead` or `int64(req.Offset) < 0`; return `StatusInvalidParameter`.
  - In `handleWrite`: check `uint32(len(req.Data)) > c.srv.maxWrite` or `int64(req.Offset) < 0`; return `StatusInvalidParameter`.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestReadLengthValidation ./smb/server`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/server/server.go smb/server/dispatch.go smb/server/server_test.go
git commit -m "fix(server): add panic recovery and enforce read/write size bounds against DoS"
```

---

### Task 5: Directory Enumeration Pagination

**Files:**
- Modify: `smb/server/dispatch.go`
- Modify: `smb/server/server.go`
- Test: `smb/server/server_test.go`

**Step 1: Write the failing test**
Test querying a directory containing 200 files with a small `OutputBufferLength` (e.g. 500 bytes) over multiple consecutive `QueryDirectory` calls, verifying that all 200 files are returned across pages.

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestDirectoryPagination ./smb/server`
Expected: FAIL (stops after first buffer and returns no more files)

**Step 3: Write minimal implementation**
- In `openHandle`: Add `cachedEntries []vfs.FileInfo` and `enumCursor int`.
- In `handleQueryDirectory`:
  - Cache entries on first query.
  - Iterate starting from `enumCursor`.
  - When buffer limit is reached, save `enumCursor` and do NOT set `enumDone = true`.
  - Only set `enumDone = true` when `enumCursor >= len(cachedEntries)`.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestDirectoryPagination ./smb/server`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/server/dispatch.go smb/server/server.go smb/server/server_test.go
git commit -m "fix(server): support pagination in query directory enumeration"
```

---

### Task 6: Compound Related Operations Signing Verification

**Files:**
- Modify: `smb/server/server.go`
- Test: `smb/server/server_test.go`

**Step 1: Write the failing test**
Test a signed compound request containing related ops (e.g. Create + Write), verifying that signature verification passes.

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestSignedCompoundRelated ./smb/server`
Expected: FAIL

**Step 3: Write minimal implementation**
In `smb/server/server.go`:
Move the signature verification block (`sess.signer.Verify(sub)`) to execute BEFORE mutating `sub[fo:fo+16]` with `lastFileId`.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestSignedCompoundRelated ./smb/server`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/server/server.go smb/server/server_test.go
git commit -m "fix(server): verify message signature before modifying compound request buffer"
```

---

### Task 7: Multi-Session File Lock and Oplock Synchronization

**Files:**
- Modify: `smb/server/server.go`
- Modify: `smb/server/lock_ioctl.go`
- Modify: `smb/server/dispatch.go`
- Test: `smb/server/server_test.go`

**Step 1: Write the failing test**
Test two separate client connections opening the same file, where Client 1 acquires an exclusive byte-range lock on [0, 100], and verify that Client 2 is blocked from conflicting lock/write.

**Step 2: Run test to verify it fails**
Run: `go test -v -run TestMultiSessionLockConflict ./smb/server`
Expected: FAIL

**Step 3: Write minimal implementation**
- Move `lockMgrSet` and `oplockTable` to `Server` or `Share` scope so they are shared across sessions.
- In `handleRead` and `handleWrite`: check lock conflicts against the shared lock manager.

**Step 4: Run test to verify it passes**
Run: `go test -v -run TestMultiSessionLockConflict ./smb/server`
Expected: PASS

**Step 5: Commit**
```bash
git add smb/server/server.go smb/server/lock_ioctl.go smb/server/dispatch.go smb/server/server_test.go
git commit -m "fix(server): synchronize file locks and oplocks across multiple sessions"
```

---

### Task 8: Full Regression & AIX Cross-Compile Verification

**Files:**
- All packages

**Step 1: Run full unit & integration tests on Linux**
```bash
go test -v ./...
go test -tags=integration -v ./...
```
Expected: PASS

**Step 2: Run Big-Endian emulation tests (s390x)**
```bash
for pkg in wire signing encryption ntlmssp kerberos server; do
  GOOS=linux GOARCH=s390x go test -c "./smb/$pkg" -o "./smb/$pkg/$pkg.test"
  docker run --rm -v $(pwd):/app --platform linux/s390x alpine "/app/smb/$pkg/$pkg.test"
  rm "./smb/$pkg/$pkg.test"
done
```
Expected: PASS

**Step 3: AIX 64-bit XCOFF cross-compile**
```bash
GOOS=aix GOARCH=ppc64 go build ./...
for dir in examples/*; do
  if [ -d "$dir" ]; then
    GOOS=aix GOARCH=ppc64 go build -o "$dir/$(basename $dir).aix" "./$dir"
    rm -f "$dir/$(basename $dir).aix"
  fi
done
```
Expected: All binaries build with exit code 0.

**Step 4: Final commit and status update**
```bash
git add docs/plans/task.md
git commit -m "chore: complete comprehensive improvements roadmap"
```
