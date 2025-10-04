package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/h0tak88r/apkX/internal/storage"
)

func main() {
	// Command line flags
	projectID := flag.String("project", "", "GitLab project ID (e.g., 'e9101230/apkx')")
	token := flag.String("token", "", "GitLab personal access token")
	localDir := flag.String("dir", "web-data", "Local directory to sync")
	remoteBase := flag.String("remote", "web-data", "Remote base path in GitLab")
	dryRun := flag.Bool("dry-run", false, "Show what would be uploaded without actually uploading")
	flag.Parse()

	// Validate required flags
	if *projectID == "" {
		log.Fatal("Error: -project flag is required (e.g., 'e9101230/apkx')")
	}

	if *token == "" {
		// Try environment variable
		*token = os.Getenv("GITLAB_TOKEN")
		if *token == "" {
			log.Fatal("Error: -token flag or GITLAB_TOKEN environment variable is required")
		}
	}

	// Check if local directory exists
	if _, err := os.Stat(*localDir); os.IsNotExist(err) {
		log.Fatalf("Error: Directory '%s' does not exist", *localDir)
	}

	fmt.Printf("GitLab Storage Sync Tool\n")
	fmt.Printf("========================\n")
	fmt.Printf("Project:     %s\n", *projectID)
	fmt.Printf("Local Dir:   %s\n", *localDir)
	fmt.Printf("Remote Path: %s\n", *remoteBase)
	fmt.Printf("Dry Run:     %v\n\n", *dryRun)

	// Create GitLab storage client
	gitlab := storage.NewGitLabStorage(*projectID, *token)

	// Ensure storage branch exists
	if !*dryRun {
		fmt.Println("Checking/creating storage branch...")
		if err := gitlab.EnsureBranchExists(); err != nil {
			log.Fatalf("Failed to ensure branch exists: %v", err)
		}
		fmt.Println("✓ Storage branch ready\n")
	}

	// Count files to upload
	fileCount := 0
	totalSize := int64(0)
	filepath.Walk(*localDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			fileCount++
			totalSize += info.Size()
		}
		return nil
	})

	fmt.Printf("Found %d files (%.2f MB) to sync\n\n", fileCount, float64(totalSize)/(1024*1024))

	if *dryRun {
		fmt.Println("Dry run - listing files that would be uploaded:")
		filepath.Walk(*localDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			relPath, _ := filepath.Rel(*localDir, path)
			fmt.Printf("  - %s (%.2f MB)\n", relPath, float64(info.Size())/(1024*1024))
			return nil
		})
		fmt.Println("\nRun without -dry-run flag to actually upload files")
		return
	}

	// Sync files
	fmt.Println("Starting sync...")
	uploaded := 0
	err := filepath.Walk(*localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(*localDir, path)
		if err != nil {
			return err
		}

		// Create remote path
		remotePath := filepath.Join(*remoteBase, relPath)
		remotePath = filepath.ToSlash(remotePath) // Convert to forward slashes

		// Upload file
		fmt.Printf("[%d/%d] Uploading %s (%.2f MB)...", uploaded+1, fileCount, relPath, float64(info.Size())/(1024*1024))
		if err := gitlab.UploadFile(path, remotePath); err != nil {
			fmt.Printf(" ✗ Failed: %v\n", err)
			return nil // Continue with other files
		}
		fmt.Printf(" ✓\n")
		uploaded++
		return nil
	})

	if err != nil {
		log.Fatalf("Sync failed: %v", err)
	}

	fmt.Printf("\n✓ Successfully uploaded %d/%d files to GitLab!\n", uploaded, fileCount)
	fmt.Printf("\nYou can view your files at:\n")
	fmt.Printf("https://gitlab.com/%s/-/tree/storage/%s\n", *projectID, *remoteBase)
}

