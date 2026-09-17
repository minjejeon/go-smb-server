# Comprehensive Improvements Design Document

**Date:** 2026-09-17  
**Status:** Approved  
**Target Repository:** `https://github.com/minjejeon/go-smb-server`  

---

## 1. Objectives

This design addresses all critical security vulnerabilities, stability issues, protocol spec violations, and compatibility bugs identified in `go-smb-server`:
1. Prevent Denial of Service (DoS) crashes from unvalidated read/write lengths and unhandled panics.
2. Eliminate path traversal and boundary escapes in VFS (`fullPath`, `Rename`, symlinks).
3. Ensure full compatibility with Windows SMB clients by normalizing path separators (`\` -> `/`).
4. Fix directory enumeration pagination so that directories with large numbers of files can be fully scanned.
5. Fix compound related request signing verification order.
6. Synchronize file locking and oplocks across multiple sessions/connections.
7. Support read-only share configurations.

---

## 2. Architecture & Detailed Design

### 2.1 VFS Security & Path Normalization (`smb/vfs/vfs.go`)
* **Path Normalization**:
  * Normalize incoming paths: replace all `\` with `/`, remove trailing/leading spaces.
  * Clean path via `path.Clean("/" + p)`.
* **Root Boundary Checks**:
  * Form candidate path `target := filepath.Join(b.Root, filepath.FromSlash(clean))`.
  * Verify `rel, err := filepath.Rel(b.Root, target)`: if `err != nil` or `strings.HasPrefix(rel, "..")`, reject with `os.ErrPermission`.
  * If symlink evaluation is needed, resolve symlink with `filepath.EvalSymlinks` and confirm target is still prefixed by `b.Root`.
* **Rename Boundary Checks**:
  * Normalize `newPath`.
  * Check destination directory and reject `..` or attempts to escape the root directory.
  * Support cross-directory file moves within the same share.
* **Read-Only Support**:
  * Add `ReadOnly bool` to `DiskShare`.
  * If a share is read-only, mutating operations (`Create` with write disposition, `Write`, `Remove`, `Rename`, `SetInfo`) return `StatusAccessDenied`.

### 2.2 Server Stability & Crash Protection (`smb/server/server.go`, `smb/server/dispatch.go`)
* **Panic Recovery**:
  * In `serveConn`, add `defer func() { if r := recover(); r != nil { cn.log.Error("recovered from panic in connection handler", "err", r); } }()` to prevent process-level termination.
* **Input Validation**:
  * In `handleRead`:
    * Check `req.Length > c.srv.maxRead`: return `StatusInvalidParameter`.
    * Check `int64(req.Offset) < 0`: return `StatusInvalidParameter`.
  * In `handleWrite`:
    * Check `uint32(len(req.Data)) > c.srv.maxWrite`: return `StatusInvalidParameter`.
    * Check `int64(req.Offset) < 0`: return `StatusInvalidParameter`.

### 2.3 Directory Enumeration Pagination (`smb/server/dispatch.go`)
* **Pagination State**:
  * `openHandle` maintains `cachedEntries []vfs.FileInfo` and `enumCursor int`.
  * On initial `Enumerate`, read entries once into `cachedEntries` or lazily buffer.
  * On each `QueryDirectoryRequest`, fill response until `OutputBufferLength` is reached.
  * Advance `enumCursor`. Only set `enumDone = true` when `enumCursor >= len(cachedEntries)`.
  * If client sets `QueryDirRestartScans`, reset `enumCursor = 0` and `enumDone = false`.

### 2.4 Compound Request Signing Verification (`smb/server/server.go`)
* **Verification Order**:
  * For related operations (`FlagRelatedOps`), verify message signature `sess.signer.Verify(sub)` **before** replacing `lastFileId` in `sub`.
  * This preserves the client's signature over the unaltered transmitted payload.

### 2.5 Multi-Session Lock & Oplock Synchronization (`smb/server/server.go`)
* **Centralized Lock Manager**:
  * Move `lockMgrSet` and `oplockTable` from individual `tree` struct to `Share` or `Server`.
  * Before processing `handleRead` and `handleWrite`, verify that requested offset and length do not conflict with active exclusive locks held by other sessions.

---

## 3. Verification & Testing Strategy

1. **Unit Tests**:
   * Add test cases for path traversal (e.g., `..\..\etc\passwd`, `\Windows\Path\file.txt`).
   * Add test cases for `ReadRequest` exceeding `maxRead` and negative offset handling.
   * Add test cases for directory pagination with 200+ mock files.
   * Add test cases for cross-session locking conflict.
2. **Regression & AIX Cross-Compile Verification**:
   * `go test ./...` on Linux x86_64.
   * `GOOS=aix GOARCH=ppc64 go build ./...` to verify AIX compilation integrity.
   * Big-Endian execution verification via `s390x` container.
