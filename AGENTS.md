# AGENTS.md

Welcome to `go-smb-server`. This repository is a lightweight, pure-Go implementation of an SMB 2/3 (Server Message Block) server.

This document serves as an operational manual and reference guide for AI coding assistants and developers working on this codebase.

---

## 1. Project Overview & Architecture

`go-smb-server` is designed to be:
* **Pure Go (Zero CGO)**: Cross-compiles seamlessly to any Go target, including Linux, macOS, Windows, and IBM AIX (`GOOS=aix GOARCH=ppc64`).
* **Clean wire protocol implementation**: Implements SMB2/SMB3 wire-level packet structures without relying on external C libraries or Samba.
* **Modular components**:
  * `smb/wire`: Packet parsing, binary serialization/deserialization (strictly `encoding/binary.LittleEndian`).
  * `smb/transport`: Direct TCP framing (NetBIOS-over-TCP 4-byte header framing).
  * `smb/signing`: AES-128-CMAC and HMAC-SHA256 message signing.
  * `smb/encryption`: AES-128-CCM / AES-128-GCM transform encryption.
  * `smb/ntlmssp`: SPNEGO / NTLMSSP authentication.
  * `smb/kerberos`: Kerberos authentication via `gokrb5`.
  * `smb/vfs`: Virtual File System interface (`DiskShare`, `LocalBackend`, `PipeBackend`).
  * `smb/server`: SMB connection dispatcher, session management, compound request handler, oplocks, file locks.

---

## 2. Platform Compatibility & Build Guidelines

### Native Testing (Linux x86_64)
```bash
# Run unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...
```

### AIX Cross-Compilation (`GOOS=aix GOARCH=ppc64`)
* AIX runs in **64-bit Big-Endian** mode (`ppc64`).
* SMB wire protocol is strictly **Little-Endian**.
* Never cast byte slices directly to integers via `unsafe.Pointer`. Always use explicit `binary.LittleEndian` or bit-shifts.
```bash
# Cross-compile for AIX
GOOS=aix GOARCH=ppc64 go build ./...

# Build an example binary for AIX
GOOS=aix GOARCH=ppc64 go build -o smb-server-aix ./examples/localdisk
```

### Big-Endian Architecture Verification
To verify Big-Endian execution without an AIX machine, use a Linux `s390x` container:
```bash
# Compile for s390x
GOOS=linux GOARCH=s390x go test -c ./smb/server -o server-s390x.test

# Run under qemu/docker
docker run --rm -v $(pwd):/app --platform linux/s390x alpine /app/server-s390x.test
```

---

## 3. Security & Coding Rules

1. **Defensive Input Validation & DoS Prevention**:
   * All client-provided lengths (`req.Length`, buffer lengths) MUST be validated against server caps (`c.srv.maxRead`, `c.srv.maxWrite`).
   * Never allocate slices (`make([]byte, length)`) directly from untrusted client-supplied numbers without bounds checking.
   * Wrap connection handlers in `recover()` to ensure that unexpected malformed packets close only the offending connection and do not crash the daemon.

2. **Path Traversal & VFS Boundary Enforcement**:
   * Windows SMB clients send paths with backslashes (`\`). Normalize all paths using `strings.ReplaceAll(path, "\\", "/")` before cleaning.
   * Validate that the resolved absolute path starts within the share's root directory (`filepath.Rel(root, target)` must not start with `..`).
   * For symlinks, evaluate target destinations to prevent symlink traversal outside the share root.

3. **Compound Request Integrity**:
   * When handling related compound requests (`FlagRelatedOps`), verify message signatures (`signer.Verify`) **before** modifying the in-memory request buffer with the inherited `FileId`.

4. **Multi-Session Concurrency**:
   * File locks (byte-range locks) and oplocks must be synchronized at the `Share` / `Server` level, not isolated inside individual connection `tree` instances.

---

## 4. Git Remotes & Upstream Policy

* **origin**: `https://github.com/minjejeon/go-smb-server` (main working remote)
* **upstream**: `https://github.com/sonroyaalmerol/go-smb-server` (original upstream)
