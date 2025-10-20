package storage

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileInfo represents file metadata
type FileInfo struct {
	Name         string
	Path         string
	Size         int64
	LastModified time.Time
}

// StorageBackend defines the interface for file storage operations
type StorageBackend interface {
	// File operations
	SaveFile(path string, content io.Reader) error
	ReadFile(path string) (io.ReadCloser, error)
	DeleteFile(path string) error
	FileExists(path string) (bool, error)
	
	// Directory operations
	ListFiles(path string) ([]FileInfo, error)
	CreateDir(path string) error
	
	// Utility
	GetFileURL(path string) string
}

// LocalStorage implements local filesystem storage
type LocalStorage struct {
	BasePath string
}

// NewLocalStorage creates a new local storage backend
func NewLocalStorage(basePath string) *LocalStorage {
	return &LocalStorage{
		BasePath: basePath,
	}
}

// SaveFile saves a file to local storage
func (l *LocalStorage) SaveFile(path string, content io.Reader) error {
	fullPath := l.getFullPath(path)
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	// Create file
	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Copy content
	_, err = io.Copy(file, content)
	return err
}

// ReadFile reads a file from local storage
func (l *LocalStorage) ReadFile(path string) (io.ReadCloser, error) {
	fullPath := l.getFullPath(path)
	return os.Open(fullPath)
}

// DeleteFile deletes a file from local storage
func (l *LocalStorage) DeleteFile(path string) error {
	fullPath := l.getFullPath(path)
	return os.Remove(fullPath)
}

// FileExists checks if a file exists in local storage
func (l *LocalStorage) FileExists(path string) (bool, error) {
	fullPath := l.getFullPath(path)
	_, err := os.Stat(fullPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// ListFiles lists files in a directory
func (l *LocalStorage) ListFiles(path string) ([]FileInfo, error) {
	fullPath := l.getFullPath(path)
	
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	
	var files []FileInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			files = append(files, FileInfo{
				Name:         entry.Name(),
				Path:         filepath.Join(path, entry.Name()),
				Size:         info.Size(),
				LastModified: info.ModTime(),
			})
		}
	}
	
	return files, nil
}

// CreateDir creates a directory
func (l *LocalStorage) CreateDir(path string) error {
	fullPath := l.getFullPath(path)
	return os.MkdirAll(fullPath, 0755)
}

// GetFileURL returns the file URL (local path)
func (l *LocalStorage) GetFileURL(path string) string {
	return l.getFullPath(path)
}

func (l *LocalStorage) getFullPath(path string) string {
	return filepath.Join(l.BasePath, path)
}

