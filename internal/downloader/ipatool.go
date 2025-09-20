package downloader

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// IPAToolDownloader handles iOS app downloads using ipatool
type IPAToolDownloader struct {
	OutputDir string
}

// IPAToolApp represents an iOS app from ipatool
type IPAToolApp struct {
	BundleID    string `json:"bundleId"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Size        int64  `json:"size"`
	Price       string `json:"price"`
	Description string `json:"description"`
	Developer   string `json:"developer"`
	Category    string `json:"category"`
	IconURL     string `json:"iconUrl"`
}

// NewIPAToolDownloader creates a new iOS app downloader
func NewIPAToolDownloader(outputDir string) *IPAToolDownloader {
	return &IPAToolDownloader{
		OutputDir: outputDir,
	}
}

// DownloadApp downloads an iOS app by bundle ID using ipatool
func (d *IPAToolDownloader) DownloadApp(bundleID, version string) (string, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return "", fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(d.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build ipatool command
	args := []string{"download"}

	// Add bundle ID using the correct flag
	args = append(args, "--bundle-identifier", bundleID)

	// Add version if specified
	if version != "" {
		args = append(args, "--external-version-id", version)
	}

	// Add output directory
	args = append(args, "--output", d.OutputDir)

	// Add additional options for better compatibility
	args = append(args, "--format", "text")
	args = append(args, "--purchase")

	// Add keychain passphrase if available, otherwise use interactive mode
	if keychainPassphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE"); keychainPassphrase != "" {
		args = append(args, "--keychain-passphrase", keychainPassphrase)
		args = append(args, "--non-interactive")
	} else {
		// Use interactive mode if no keychain passphrase is provided
		fmt.Println("Note: Running in interactive mode. You may need to enter your keychain passphrase.")
	}

	fmt.Printf("Downloading iOS app: %s (version: %s)\n", bundleID, version)

	// Execute ipatool command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ipatool download failed: %v, output: %s", err, string(output))
	}

	// Find the downloaded IPA file
	ipaPath, err := d.findDownloadedIPA(bundleID)
	if err != nil {
		return "", fmt.Errorf("failed to find downloaded IPA: %v", err)
	}

	fmt.Printf("iOS app downloaded successfully: %s\n", ipaPath)
	return ipaPath, nil
}

// SearchApp searches for iOS apps by name using ipatool
func (d *IPAToolDownloader) SearchApp(query string, limit int) ([]IPAToolApp, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return nil, fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Build search command
	args := []string{"search", query}
	if limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", limit))
	}
	args = append(args, "--format", "json")

	// Execute ipatool search command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipatool search failed: %v, output: %s", err, string(output))
	}

	// Parse JSON output
	var apps []IPAToolApp
	if err := json.Unmarshal(output, &apps); err != nil {
		return nil, fmt.Errorf("failed to parse search results: %v", err)
	}

	return apps, nil
}

// GetAppInfo gets detailed information about an iOS app
func (d *IPAToolDownloader) GetAppInfo(bundleID string) (*IPAToolApp, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return nil, fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Build info command
	args := []string{"info", bundleID, "--format", "json"}

	// Execute ipatool info command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipatool info failed: %v, output: %s", err, string(output))
	}

	// Parse JSON output
	var app IPAToolApp
	if err := json.Unmarshal(output, &app); err != nil {
		return nil, fmt.Errorf("failed to parse app info: %v", err)
	}

	return &app, nil
}

// findDownloadedIPA finds the most recently downloaded IPA file
func (d *IPAToolDownloader) findDownloadedIPA(bundleID string) (string, error) {
	entries, err := os.ReadDir(d.OutputDir)
	if err != nil {
		return "", err
	}

	var latestFile string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := strings.ToLower(entry.Name())
			if strings.HasSuffix(fileName, ".ipa") {
				// Check if this file is related to our bundle ID
				if strings.Contains(entry.Name(), bundleID) ||
					strings.Contains(entry.Name(), strings.ReplaceAll(bundleID, ".", "_")) {

					info, err := entry.Info()
					if err != nil {
						continue
					}

					if info.ModTime().After(latestTime) {
						latestTime = info.ModTime()
						latestFile = filepath.Join(d.OutputDir, entry.Name())
					}
				}
			}
		}
	}

	if latestFile == "" {
		return "", fmt.Errorf("no IPA file found for bundle ID %s", bundleID)
	}

	return latestFile, nil
}

// ListDownloadedIPAs returns a list of all downloaded IPA files
func (d *IPAToolDownloader) ListDownloadedIPAs() ([]string, error) {
	entries, err := os.ReadDir(d.OutputDir)
	if err != nil {
		return nil, err
	}

	var ipaFiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := strings.ToLower(entry.Name())
			if strings.HasSuffix(fileName, ".ipa") {
				ipaFiles = append(ipaFiles, filepath.Join(d.OutputDir, entry.Name()))
			}
		}
	}

	return ipaFiles, nil
}

// CleanupOldIPAs removes IPA files older than the specified duration
func (d *IPAToolDownloader) CleanupOldIPAs(olderThan time.Duration) error {
	entries, err := os.ReadDir(d.OutputDir)
	if err != nil {
		return err
	}

	cutoffTime := time.Now().Add(-olderThan)
	var removedCount int

	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := strings.ToLower(entry.Name())
			if strings.HasSuffix(fileName, ".ipa") {
				info, err := entry.Info()
				if err != nil {
					continue
				}

				if info.ModTime().Before(cutoffTime) {
					filePath := filepath.Join(d.OutputDir, entry.Name())
					if err := os.Remove(filePath); err != nil {
						fmt.Printf("Warning: failed to remove old IPA %s: %v\n", filePath, err)
					} else {
						removedCount++
					}
				}
			}
		}
	}

	if removedCount > 0 {
		fmt.Printf("Cleaned up %d old IPA files\n", removedCount)
	}

	return nil
}
