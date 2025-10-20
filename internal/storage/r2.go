package storage

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// CloudflareR2Storage implements file storage using Cloudflare R2
type CloudflareR2Storage struct {
	BucketName    string
	AccountID     string
	AccessKeyID   string
	SecretKey     string
	PublicURL     string // Custom domain URL (optional)
	client        *s3.S3
}

// NewCloudflareR2Storage creates a new Cloudflare R2 storage backend
func NewCloudflareR2Storage(bucketName, accountID, accessKeyID, secretKey, publicURL string) *CloudflareR2Storage {
	// Create AWS session with Cloudflare R2 endpoint
	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String("auto"), // Cloudflare R2 uses "auto" region
		Credentials: credentials.NewStaticCredentials(
			accessKeyID,
			secretKey,
			"", // No session token needed
		),
		Endpoint: aws.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)),
	})

	client := s3.New(sess)

	return &CloudflareR2Storage{
		BucketName:  bucketName,
		AccountID:   accountID,
		AccessKeyID: accessKeyID,
		SecretKey:   secretKey,
		PublicURL:   publicURL,
		client:      client,
	}
}

// SaveFile saves a file to Cloudflare R2
func (r *CloudflareR2Storage) SaveFile(path string, content io.Reader) error {
	// Clean the path
	path = strings.TrimPrefix(path, "/")
	
	// Upload to R2
	_, err := r.client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(path),
		Body:   aws.ReadSeekCloser(content),
	})
	
	if err != nil {
		return fmt.Errorf("failed to upload file to R2: %w", err)
	}
	
	return nil
}

// ReadFile reads a file from Cloudflare R2
func (r *CloudflareR2Storage) ReadFile(path string) (io.ReadCloser, error) {
	// Clean the path
	path = strings.TrimPrefix(path, "/")
	
	result, err := r.client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(path),
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to download file from R2: %w", err)
	}
	
	return result.Body, nil
}

// DeleteFile deletes a file from Cloudflare R2
func (r *CloudflareR2Storage) DeleteFile(path string) error {
	// Clean the path
	path = strings.TrimPrefix(path, "/")
	
	_, err := r.client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(path),
	})
	
	if err != nil {
		return fmt.Errorf("failed to delete file from R2: %w", err)
	}
	
	return nil
}

// FileExists checks if a file exists in Cloudflare R2
func (r *CloudflareR2Storage) FileExists(path string) (bool, error) {
	// Clean the path
	path = strings.TrimPrefix(path, "/")
	
	_, err := r.client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(path),
	})
	
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check file existence in R2: %w", err)
	}
	
	return true, nil
}

// ListFiles lists files in a directory from Cloudflare R2
func (r *CloudflareR2Storage) ListFiles(path string) ([]FileInfo, error) {
	// Clean the path and ensure it ends with /
	path = strings.TrimPrefix(path, "/")
	if path != "" && !strings.HasSuffix(path, "/") {
		path += "/"
	}
	
	result, err := r.client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(r.BucketName),
		Prefix: aws.String(path),
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to list files in R2: %w", err)
	}
	
	var files []FileInfo
	for _, obj := range result.Contents {
		// Skip directories (objects ending with /)
		if strings.HasSuffix(*obj.Key, "/") {
			continue
		}
		
		// Get relative path from the requested directory
		relativePath := strings.TrimPrefix(*obj.Key, path)
		if relativePath == "" {
			continue
		}
		
		files = append(files, FileInfo{
			Name:         filepath.Base(*obj.Key),
			Path:         *obj.Key,
			Size:         *obj.Size,
			LastModified: *obj.LastModified,
		})
	}
	
	return files, nil
}

// CreateDir creates a directory (no-op for R2 as it's object-based)
func (r *CloudflareR2Storage) CreateDir(path string) error {
	// R2 is object-based, directories are implicit
	// We can create a placeholder object to ensure the "directory" exists
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return nil
	}
	
	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	
	// Create a placeholder object
	_, err := r.client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(path + ".gitkeep"),
		Body:   aws.ReadSeekCloser(strings.NewReader("# Directory placeholder\n")),
	})
	
	if err != nil {
		return fmt.Errorf("failed to create directory in R2: %w", err)
	}
	
	return nil
}

// GetFileURL returns the file URL
func (r *CloudflareR2Storage) GetFileURL(path string) string {
	// Clean the path
	path = strings.TrimPrefix(path, "/")
	
	// If custom public URL is provided, use it
	if r.PublicURL != "" {
		return fmt.Sprintf("%s/%s", strings.TrimSuffix(r.PublicURL, "/"), path)
	}
	
	// Otherwise, use the default R2 public URL
	return fmt.Sprintf("https://pub-%s.r2.dev/%s", r.AccountID, path)
}

// EnsureBucketExists checks if the bucket exists and creates it if it doesn't
func (r *CloudflareR2Storage) EnsureBucketExists() error {
	// Check if bucket exists
	_, err := r.client.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(r.BucketName),
	})
	
	if err == nil {
		return nil // Bucket exists
	}
	
	// If bucket doesn't exist, create it
	_, err = r.client.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(r.BucketName),
	})
	
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}
	
	return nil
}
