package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/h0tak88r/apkX/internal/storage"
)

// GitLab Sync Daemon - automatically syncs web-data to GitLab in background

func main() {
	projectID := flag.String("project", os.Getenv("GITLAB_PROJECT"), "GitLab project ID")
	token := flag.String("token", os.Getenv("GITLAB_TOKEN"), "GitLab access token")
	watchDir := flag.String("dir", "web-data", "Directory to watch and sync")
	interval := flag.Duration("interval", 5*time.Minute, "Sync interval")
	flag.Parse()

	if *projectID == "" || *token == "" {
		log.Fatal("GitLab project and token required (use -project/-token or GITLAB_PROJECT/GITLAB_TOKEN env vars)")
	}

	log.Printf("GitLab Sync Daemon started")
	log.Printf("Project: %s", *projectID)
	log.Printf("Watch directory: %s", *watchDir)
	log.Printf("Sync interval: %s", *interval)

	gitlab := storage.NewGitLabStorage(*projectID, *token)

	// Ensure storage branch exists
	if err := gitlab.EnsureBranchExists(); err != nil {
		log.Printf("Warning: Could not ensure branch exists: %v", err)
	}

	// Initial sync
	syncToGitLab(gitlab, *watchDir)

	// Watch and sync periodically
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for range ticker.C {
		syncToGitLab(gitlab, *watchDir)
	}
}

func syncToGitLab(gitlab *storage.GitLabStorage, watchDir string) {
	log.Printf("Starting sync...")
	
	uploaded := 0
	failed := 0

	filepath.Walk(watchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(watchDir, path)
		if err != nil {
			return nil
		}

		// Check if already uploaded (skip if last modified is old)
		if time.Since(info.ModTime()) > 10*time.Minute {
			return nil // File is old, probably already synced
		}

		// Upload file
		remotePath := filepath.Join(watchDir, relPath)
		remotePath = filepath.ToSlash(remotePath)

		f, err := os.Open(path)
		if err != nil {
			log.Printf("Failed to open %s: %v", path, err)
			failed++
			return nil
		}
		defer f.Close()

		if err := gitlab.SaveFile(remotePath, f); err != nil {
			log.Printf("Failed to upload %s: %v", remotePath, err)
			failed++
		} else {
			log.Printf("✓ Synced: %s", relPath)
			uploaded++
		}

		return nil
	})

	log.Printf("Sync complete: %d uploaded, %d failed", uploaded, failed)
}

