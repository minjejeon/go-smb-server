package vfs

import (
	"context"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type Share interface {
	Name() string
	Backend() Backend
}

type DiskShare struct {
	name    string
	backend Backend
}

func NewDiskShare(name string, backend Backend) DiskShare {
	return DiskShare{name: name, backend: backend}
}

func (s DiskShare) Name() string     { return s.name }
func (s DiskShare) Backend() Backend { return s.backend }

const (
	DispositionSupersede   uint32 = 0x00000000
	DispositionOpen        uint32 = 0x00000001
	DispositionCreate      uint32 = 0x00000002
	DispositionOpenIf      uint32 = 0x00000003
	DispositionOverwrite   uint32 = 0x00000004
	DispositionOverwriteIf uint32 = 0x00000005
)

type OpenOptions struct {
	Path        string
	Disposition uint32
	CreateDir   bool
	Append      bool
}

type FileInfo struct {
	Name         string
	Size         int64
	IsDir        bool
	Attributes   uint32
	CreationTime time.Time
	LastAccess   time.Time
	LastWrite    time.Time
	ChangeTime   time.Time
}

type Handle interface {
	Read(ctx context.Context, offset int64, p []byte) (int, error)
	Write(ctx context.Context, offset int64, p []byte) (int, error)
	Close(ctx context.Context) error
	Stat(ctx context.Context) (FileInfo, error)
	Enumerate(ctx context.Context, pattern string) iter.Seq2[FileInfo, error]
}

type Backend interface {
	Open(ctx context.Context, opts OpenOptions) (Handle, error)
}

type Remover interface {
	Remove(ctx context.Context, path string) error
}

type SetInfoer interface {
	SetInfo(ctx context.Context, info *SetInfoRequest) error
}

type SetInfoRequest struct {
	CreationTime   *time.Time
	LastAccessTime *time.Time
	LastWriteTime  *time.Time
	ChangeTime     *time.Time
	Attributes     *uint32
	EndOfFile      *int64
}

type Renamer interface {
	Rename(ctx context.Context, newPath string, replaceIfExists bool) error
}

type Mkdirer interface {
	Mkdir(ctx context.Context, path string) error
}

type Copier interface {
	CopyChunk(ctx context.Context, srcPath string, srcOffset, dstOffset, length int64) error
}

type PipeProcessor interface {
	ProcessPipe(ctx context.Context, input []byte) []byte
}

type LocalBackend struct {
	Root string
}

func NewLocalBackend(root string) (*LocalBackend, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &LocalBackend{Root: abs}, nil
}

func cleanPath(p string) string {
	// Normalize backslashes (Windows client) to forward slashes
	p = strings.ReplaceAll(p, "\\", "/")
	clean := path.Clean("/" + p)
	if clean == "/" {
		return ""
	}
	return strings.TrimPrefix(clean, "/")
}

func (b *LocalBackend) fullPath(p string) (string, error) {
	clean := cleanPath(p)
	full := filepath.Join(b.Root, filepath.FromSlash(clean))

	// Boundary check: ensure target does not escape the share root
	rel, err := filepath.Rel(b.Root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", os.ErrPermission
	}

	// For existing symlinks, evaluate target destination to prevent symlink traversal outside root
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		eval, err := filepath.EvalSymlinks(full)
		if err == nil {
			relEval, err := filepath.Rel(b.Root, eval)
			if err != nil || relEval == ".." || strings.HasPrefix(relEval, ".."+string(filepath.Separator)) {
				return "", os.ErrPermission
			}
		}
	}

	return full, nil
}

func (b *LocalBackend) Remove(_ context.Context, p string) error {
	full, err := b.fullPath(p)
	if err != nil {
		return err
	}
	return os.RemoveAll(full)
}

func (b *LocalBackend) Mkdir(_ context.Context, p string) error {
	full, err := b.fullPath(p)
	if err != nil {
		return err
	}
	return os.MkdirAll(full, 0o755)
}

func (b *LocalBackend) CopyChunk(_ context.Context, srcPath string, srcOffset, dstOffset, length int64) error {
	srcFull, err := b.fullPath(srcPath)
	if err != nil {
		return err
	}
	dstFull := srcFull
	src, err := os.Open(srcFull)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(dstFull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	var buf [65536]byte
	remaining := length
	for remaining > 0 {
		chunk := buf[:]
		if remaining < int64(len(buf)) {
			chunk = buf[:remaining]
		}
		nr, re := src.ReadAt(chunk, srcOffset)
		if nr > 0 {
			_, we := dst.WriteAt(chunk[:nr], dstOffset)
			if we != nil {
				return we
			}
			srcOffset += int64(nr)
			dstOffset += int64(nr)
			remaining -= int64(nr)
		}
		if re != nil {
			return re
		}
		if nr == 0 {
			break
		}
	}
	return nil
}

func (b *LocalBackend) Open(_ context.Context, opts OpenOptions) (Handle, error) {
	full, err := b.fullPath(opts.Path)
	if err != nil {
		return nil, err
	}
	if full == b.Root {
		full = filepath.Join(b.Root, ".")
	}

	flags := getFlags(opts.Disposition, opts.Append)
	if opts.CreateDir {
		if err := os.Mkdir(full, 0o755); err != nil && !os.IsExist(err) {
			return nil, err
		}
		flags &^= os.O_RDWR | os.O_WRONLY
		flags |= os.O_RDONLY
	} else if fi, statErr := os.Stat(full); statErr == nil && fi.IsDir() {
		flags &^= os.O_RDWR | os.O_WRONLY
		flags |= os.O_RDONLY
	}
	f, err := os.OpenFile(full, flags, 0o644)
	if err != nil {
		return nil, err
	}
	return &localHandle{backend: b, f: f, path: full, name: filepath.Base(full)}, nil
}

func getFlags(disp uint32, appendFile bool) int {
	switch disp {
	case DispositionCreate:
		return os.O_CREATE | os.O_EXCL
	case DispositionSupersede:
		return os.O_CREATE | os.O_TRUNC
	case DispositionOverwrite, DispositionOverwriteIf:
		return os.O_CREATE | os.O_TRUNC | os.O_RDWR
	default:
		if appendFile {
			return os.O_APPEND | os.O_CREATE | os.O_RDWR
		}
		return os.O_RDWR
	}
}

type localHandle struct {
	backend *LocalBackend
	f       *os.File
	path    string
	name    string
}

func (h *localHandle) Read(_ context.Context, offset int64, p []byte) (int, error) {
	return h.f.ReadAt(p, offset)
}

func (h *localHandle) Write(_ context.Context, offset int64, p []byte) (int, error) {
	return h.f.WriteAt(p, offset)
}

func (h *localHandle) Close(_ context.Context) error { return h.f.Close() }

func (h *localHandle) Stat(_ context.Context) (FileInfo, error) {
	fi, err := h.f.Stat()
	if err != nil {
		return FileInfo{}, err
	}
	return statToFileInfo(h.name, fi), nil
}

func (h *localHandle) SetInfo(_ context.Context, req *SetInfoRequest) error {
	if req.EndOfFile != nil {
		if err := h.f.Truncate(*req.EndOfFile); err != nil {
			return err
		}
	}
	if req.CreationTime != nil || req.LastAccessTime != nil || req.LastWriteTime != nil {
		atime := time.Now()
		mtime := time.Now()
		if fi, err := h.f.Stat(); err == nil {
			atime = accessTime(fi)
			mtime = fi.ModTime()
		}
		if req.LastAccessTime != nil {
			atime = *req.LastAccessTime
		}
		if req.LastWriteTime != nil {
			mtime = *req.LastWriteTime
		}
		if err := os.Chtimes(h.path, atime, mtime); err != nil {
			return err
		}
	}
	if req.Attributes != nil && *req.Attributes&0x02 != 0 {
		if err := os.Chmod(h.path, 0400); err != nil {
			return err
		}
	}
	return nil
}

func (h *localHandle) Rename(_ context.Context, newPath string, replaceIfExists bool) error {
	if strings.Contains(newPath, "..") {
		return os.ErrPermission
	}
	clean := cleanPath(newPath)
	if clean == "" || clean == "." {
		return os.ErrPermission
	}

	var newFull string
	if h.backend != nil {
		var err error
		newFull, err = h.backend.fullPath(clean)
		if err != nil {
			return err
		}
	} else {
		newFull = filepath.Join(filepath.Dir(h.path), filepath.Base(filepath.FromSlash(clean)))
	}

	if !replaceIfExists {
		if _, err := os.Stat(newFull); err == nil {
			return os.ErrExist
		}
	}
	if err := os.Rename(h.path, newFull); err != nil {
		return err
	}
	h.path = newFull
	h.name = filepath.Base(newFull)
	return nil
}

func (h *localHandle) Enumerate(_ context.Context, pattern string) iter.Seq2[FileInfo, error] {
	return func(yield func(FileInfo, error) bool) {
		entries, err := os.ReadDir(h.f.Name())
		if err != nil {
			yield(FileInfo{}, err)
			return
		}
		for _, e := range entries {
			if pattern != "" {
				matched, err := filepath.Match(pattern, e.Name())
				if err != nil {
					yield(FileInfo{}, fmt.Errorf("vfs: bad search pattern %q: %w", pattern, err))
					return
				}
				if !matched {
					continue
				}
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if !yield(statToFileInfo(e.Name(), fi), nil) {
				return
			}
		}
	}
}

func accessTime(fi fs.FileInfo) time.Time {
	return fi.ModTime()
}

func statToFileInfo(name string, fi fs.FileInfo) FileInfo {
	now := time.Now()
	return FileInfo{
		Name:         name,
		Size:         fi.Size(),
		IsDir:        fi.IsDir(),
		CreationTime: fi.ModTime(),
		LastAccess:   fi.ModTime(),
		LastWrite:    fi.ModTime(),
		ChangeTime:   now,
	}
}
