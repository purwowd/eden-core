// Package adapters provides concrete implementations of interfaces
package adapters

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/purwowd/eden-core/internal/interfaces"
)

// FileSystem provides file system operations
type FileSystem struct{}

// NewFileSystem creates a new FileSystem instance
func NewFileSystem() *FileSystem {
	return &FileSystem{}
}

// ReadFile reads a file and returns its contents
func (fs *FileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes data to a file
func (fs *FileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// Exists checks if a file or directory exists
func (fs *FileSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CreateDirectory creates a directory and all necessary parent directories
func (fs *FileSystem) CreateDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// Remove removes a file or directory
func (fs *FileSystem) Remove(path string) error {
	return os.Remove(path)
}

// OSFileSystem implements FileSystem interface using real OS operations
type OSFileSystem struct{}

// NewOSFileSystem creates a new OS filesystem adapter
func NewOSFileSystem() interfaces.FileSystem {
	return &OSFileSystem{}
}

// ReadFile reads a file and returns its contents
func (fs *OSFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes data to a file
func (fs *OSFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// Exists checks if a file or directory exists
func (fs *OSFileSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// CreateDirectory creates a directory and all necessary parent directories
func (fs *OSFileSystem) CreateDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// Remove removes a file or directory
func (fs *OSFileSystem) Remove(path string) error {
	return os.Remove(path)
}

// Stat returns file information
func (fs *OSFileSystem) Stat(filename string) (interfaces.FileInfo, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	return &OSFileInfo{info}, nil
}

// MkdirAll creates directories
func (fs *OSFileSystem) MkdirAll(path string, perm int) error {
	return os.MkdirAll(path, os.FileMode(perm))
}

// OpenFile opens a file
func (fs *OSFileSystem) OpenFile(name string, flag int, perm int) (interfaces.File, error) {
	file, err := os.OpenFile(name, flag, os.FileMode(perm))
	if err != nil {
		return nil, err
	}
	return &OSFile{file}, nil
}

// TempDir returns temporary directory
func (fs *OSFileSystem) TempDir() string {
	return os.TempDir()
}

// OSFileInfo wraps os.FileInfo
type OSFileInfo struct {
	info os.FileInfo
}

func (fi *OSFileInfo) Name() string       { return fi.info.Name() }
func (fi *OSFileInfo) Size() int64        { return fi.info.Size() }
func (fi *OSFileInfo) Mode() int          { return int(fi.info.Mode()) }
func (fi *OSFileInfo) ModTime() time.Time { return fi.info.ModTime() }
func (fi *OSFileInfo) IsDir() bool        { return fi.info.IsDir() }

// OSFile wraps os.File
type OSFile struct {
	file *os.File
}

func (f *OSFile) Read(p []byte) (n int, err error) {
	return f.file.Read(p)
}

func (f *OSFile) Write(p []byte) (n int, err error) {
	return f.file.Write(p)
}

func (f *OSFile) Close() error {
	return f.file.Close()
}

func (f *OSFile) Stat() (interfaces.FileInfo, error) {
	info, err := f.file.Stat()
	if err != nil {
		return nil, err
	}
	return &OSFileInfo{info}, nil
}

func (f *OSFile) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(offset, whence)
}

// MemoryFileSystem implements FileSystem interface in memory
type MemoryFileSystem struct {
	mu    sync.RWMutex
	files map[string]*memoryFile
}

type memoryFile struct {
	name    string
	content []byte
	isDir   bool
	mode    os.FileMode
}

// NewMemoryFileSystem creates a new memory-based file system
func NewMemoryFileSystem() *MemoryFileSystem {
	return &MemoryFileSystem{
		files: make(map[string]*memoryFile),
	}
}

// ReadFile reads a file from memory
func (fs *MemoryFileSystem) ReadFile(path string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	file, exists := fs.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	if file.isDir {
		return nil, fmt.Errorf("cannot read directory")
	}

	return file.content, nil
}

// WriteFile writes a file to memory
func (fs *MemoryFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.files[path] = &memoryFile{
		name:    path,
		content: data,
		isDir:   false,
		mode:    perm,
	}

	return nil
}

// Exists checks if a file exists in memory
func (fs *MemoryFileSystem) Exists(path string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	_, exists := fs.files[path]
	return exists
}

// CreateDirectory creates a directory in memory
func (fs *MemoryFileSystem) CreateDirectory(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if path already exists
	if _, exists := fs.files[path]; exists {
		return nil // Directory already exists
	}

	// Create directory entry
	fs.files[path] = &memoryFile{
		name:    path,
		content: nil,
		isDir:   true,
		mode:    0755,
	}

	return nil
}

// Remove removes a file from memory
func (fs *MemoryFileSystem) Remove(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.files[path]; !exists {
		return os.ErrNotExist
	}

	delete(fs.files, path)
	return nil
}

// Stat returns file information
func (fs *MemoryFileSystem) Stat(filename string) (interfaces.FileInfo, error) {
	_, exists := fs.files[filename]
	if !exists {
		return nil, &os.PathError{Op: "stat", Path: filename, Err: os.ErrNotExist}
	}
	return &MemoryFileInfo{name: filepath.Base(filename), size: int64(len(fs.files[filename].content))}, nil
}

// MkdirAll creates directories
func (fs *MemoryFileSystem) MkdirAll(path string, perm int) error {
	// In memory filesystem, directories are implicit
	return nil
}

// OpenFile opens a file
func (fs *MemoryFileSystem) OpenFile(name string, flag int, perm int) (interfaces.File, error) {
	return &MemoryFile{name: name, fs: fs}, nil
}

func (fs *MemoryFileSystem) TempDir() string {
	return "/tmp"
}

// MemoryFileInfo implements FileInfo for memory filesystem
type MemoryFileInfo struct {
	name string
	size int64
}

func (fi *MemoryFileInfo) Name() string       { return fi.name }
func (fi *MemoryFileInfo) Size() int64        { return fi.size }
func (fi *MemoryFileInfo) Mode() int          { return 0644 }
func (fi *MemoryFileInfo) ModTime() time.Time { return time.Now() }
func (fi *MemoryFileInfo) IsDir() bool        { return false }

// MemoryFile implements File for memory filesystem
type MemoryFile struct {
	name   string
	fs     *MemoryFileSystem
	offset int64
}

func (f *MemoryFile) Read(p []byte) (n int, err error) {
	data, exists := f.fs.files[f.name]
	if !exists {
		return 0, os.ErrNotExist
	}

	if f.offset >= int64(len(data.content)) {
		return 0, os.ErrClosed
	}

	n = copy(p, data.content[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *MemoryFile) Write(p []byte) (n int, err error) {
	data, exists := f.fs.files[f.name]
	if !exists {
		data = &memoryFile{
			name:    f.name,
			content: nil,
			isDir:   false,
			mode:    0644,
		}
	}

	// Extend slice if needed
	if int64(len(data.content)) < f.offset+int64(len(p)) {
		newContent := make([]byte, f.offset+int64(len(p)))
		copy(newContent, data.content)
		data.content = newContent
	}

	copy(data.content[f.offset:], p)
	f.fs.files[f.name] = data
	f.offset += int64(len(p))
	return len(p), nil
}

func (f *MemoryFile) Close() error {
	return nil
}

func (f *MemoryFile) Stat() (interfaces.FileInfo, error) {
	return f.fs.Stat(f.name)
}

func (f *MemoryFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0: // SEEK_SET
		f.offset = offset
	case 1: // SEEK_CUR
		f.offset += offset
	case 2: // SEEK_END
		if data, exists := f.fs.files[f.name]; exists {
			f.offset = int64(len(data.content)) + offset
		}
	}
	return f.offset, nil
}
