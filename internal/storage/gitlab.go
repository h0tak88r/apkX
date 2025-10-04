package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GitLabStorage implements file storage using GitLab repository
type GitLabStorage struct {
	ProjectID   string // GitLab project ID (e.g., "e9101230/apkx")
	AccessToken string // GitLab personal access token
	Branch      string // Branch to store files (default: "storage")
	BaseURL     string // GitLab API base URL (default: "https://gitlab.com/api/v4")
	client      *http.Client
}

// NewGitLabStorage creates a new GitLab storage backend
func NewGitLabStorage(projectID, accessToken string) *GitLabStorage {
	return &GitLabStorage{
		ProjectID:   url.PathEscape(projectID),
		AccessToken: accessToken,
		Branch:      "storage",
		BaseURL:     "https://gitlab.com/api/v4",
		client:      &http.Client{Timeout: 60 * time.Second},
	}
}

// FileInfo represents file metadata from GitLab
type FileInfo struct {
	Name         string
	Path         string
	Size         int64
	LastModified time.Time
}

// UploadFile uploads a file to GitLab repository
func (g *GitLabStorage) UploadFile(localPath, remotePath string) error {
	// Read file content
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Encode to base64
	encodedContent := base64.StdEncoding.EncodeToString(content)

	// Check if file already exists
	exists, err := g.FileExists(remotePath)
	if err != nil {
		return fmt.Errorf("failed to check file existence: %w", err)
	}

	if exists {
		// Update existing file
		return g.updateFile(remotePath, encodedContent)
	}

	// Create new file
	return g.createFile(remotePath, encodedContent)
}

// DownloadFile downloads a file from GitLab repository
func (g *GitLabStorage) DownloadFile(remotePath, localPath string) error {
	// Get file content from GitLab
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw?ref=%s",
		g.BaseURL, g.ProjectID, url.PathEscape(remotePath), g.Branch)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	// Create local directory if needed
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to local file
	out, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ListFiles lists files in a directory
func (g *GitLabStorage) ListFiles(remotePath string) ([]FileInfo, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/tree?ref=%s&path=%s",
		g.BaseURL, g.ProjectID, g.Branch, url.QueryEscape(remotePath))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	var items []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var files []FileInfo
	for _, item := range items {
		if item.Type == "blob" { // Only files, not directories
			files = append(files, FileInfo{
				Name: item.Name,
				Path: item.Path,
			})
		}
	}

	return files, nil
}

// DeleteFile deletes a file from GitLab repository
func (g *GitLabStorage) DeleteFile(remotePath string) error {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s",
		g.BaseURL, g.ProjectID, url.PathEscape(remotePath))

	payload := map[string]string{
		"branch":         g.Branch,
		"commit_message": fmt.Sprintf("Delete %s", remotePath),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("DELETE", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// FileExists checks if a file exists in GitLab repository
func (g *GitLabStorage) FileExists(remotePath string) (bool, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s?ref=%s",
		g.BaseURL, g.ProjectID, url.PathEscape(remotePath), g.Branch)

	req, err := http.NewRequest("HEAD", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// createFile creates a new file in GitLab
func (g *GitLabStorage) createFile(remotePath, base64Content string) error {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s",
		g.BaseURL, g.ProjectID, url.PathEscape(remotePath))

	payload := map[string]string{
		"branch":         g.Branch,
		"content":        base64Content,
		"commit_message": fmt.Sprintf("Upload %s", filepath.Base(remotePath)),
		"encoding":       "base64",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// updateFile updates an existing file in GitLab
func (g *GitLabStorage) updateFile(remotePath, base64Content string) error {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s",
		g.BaseURL, g.ProjectID, url.PathEscape(remotePath))

	payload := map[string]string{
		"branch":         g.Branch,
		"content":        base64Content,
		"commit_message": fmt.Sprintf("Update %s", filepath.Base(remotePath)),
		"encoding":       "base64",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// EnsureBranchExists creates the storage branch if it doesn't exist
func (g *GitLabStorage) EnsureBranchExists() error {
	// Check if branch exists
	apiURL := fmt.Sprintf("%s/projects/%s/repository/branches/%s",
		g.BaseURL, g.ProjectID, g.Branch)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check branch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Branch exists
		return nil
	}

	// Create branch
	createURL := fmt.Sprintf("%s/projects/%s/repository/branches", g.BaseURL, g.ProjectID)
	payload := map[string]string{
		"branch": g.Branch,
		"ref":    "main", // Create from main branch
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	createReq, err := http.NewRequest("POST", createURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	createReq.Header.Set("PRIVATE-TOKEN", g.AccessToken)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := g.client.Do(createReq)
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create branch: %d: %s", createResp.StatusCode, string(body))
	}

	return nil
}

// SyncUploadedFiles syncs all local files to GitLab
func (g *GitLabStorage) SyncUploadedFiles(localDir, remoteDir string) error {
	return filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}

		// Convert to forward slashes for GitLab
		remotePath := filepath.Join(remoteDir, relPath)
		remotePath = strings.ReplaceAll(remotePath, "\\", "/")

		// Upload file
		fmt.Printf("Uploading %s to GitLab...\n", relPath)
		if err := g.UploadFile(path, remotePath); err != nil {
			return fmt.Errorf("failed to upload %s: %w", relPath, err)
		}

		return nil
	})
}

// Implementation of StorageBackend interface

// SaveFile saves a file to GitLab (implements StorageBackend)
func (g *GitLabStorage) SaveFile(path string, content io.Reader) error {
	// Read content
	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}

	// Encode to base64
	encodedContent := base64.StdEncoding.EncodeToString(data)

	// Check if file exists
	exists, err := g.FileExists(path)
	if err != nil {
		return fmt.Errorf("failed to check file existence: %w", err)
	}

	if exists {
		return g.updateFile(path, encodedContent)
	}
	return g.createFile(path, encodedContent)
}

// ReadFile reads a file from GitLab (implements StorageBackend)
func (g *GitLabStorage) ReadFile(path string) (io.ReadCloser, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw?ref=%s",
		g.BaseURL, g.ProjectID, url.PathEscape(path), g.Branch)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", g.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("GitLab API error %d: %s", resp.StatusCode, string(body))
	}

	return resp.Body, nil
}

// CreateDir is a no-op for GitLab (directories are created implicitly)
func (g *GitLabStorage) CreateDir(path string) error {
	return nil // GitLab creates directories implicitly
}

// GetFileURL returns the GitLab raw file URL
func (g *GitLabStorage) GetFileURL(path string) string {
	return fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/files/%s/raw?ref=%s&private_token=%s",
		g.ProjectID, url.PathEscape(path), g.Branch, g.AccessToken)
}

