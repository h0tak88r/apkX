package analyzer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cyinnove/apkX/internal/decompiler"
	"github.com/cyinnove/apkX/internal/utils"
	"gopkg.in/yaml.v3"
)

type Config struct {
	APKFile      string // Path to the APK file
	OutputFile   string // Path to save results
	PatternsFile string // Path to patterns file
	JadxArgs     string // Additional jadx arguments
	JSON         bool   // Save as JSON format
	Verbose      bool   // Enable verbose output
}

type APKScanner struct {
	config    *Config
	patterns  map[string][]string
	tempDir   string
	results   map[string][]string
	resultsMu sync.Mutex
	apkPkg    string
	cacheDir  string
}

type Pattern struct {
	Name       string   `yaml:"name"`
	Regex      string   `yaml:"regex,omitempty"`
	Regexes    []string `yaml:"regexes,omitempty"`
	Confidence string   `yaml:"confidence"`
}

type PatternsConfig struct {
	Patterns []Pattern `yaml:"patterns"`
}

func NewAPKScanner(config *Config) *APKScanner {
	return &APKScanner{
		config:  config,
		results: make(map[string][]string),
	}
}

func (s *APKScanner) Run() error {
	if err := s.validateAPK(); err != nil {
		return fmt.Errorf("APK validation failed: %v", err)
	}
	fmt.Printf("%s=== APK Analysis ===%s\n", utils.ColorGreen, utils.ColorEnd)
	fmt.Printf("Scanning APK: %s\n", s.apkPkg)

	// Create temporary directory
	fmt.Println("Creating temporary directory...")
	if err := s.decompileAPK(); err != nil {
		return fmt.Errorf("failed to decompile APK: %v", err)
	}
	// Only remove temp dir if it's not a cached one
	if s.cacheDir == "" || !strings.HasPrefix(s.tempDir, s.cacheDir) {
		defer os.RemoveAll(s.tempDir)
	}

	// Load patterns
	fmt.Println("Loading patterns...")
	if err := s.loadPatterns(); err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}

	// Scan for matches
	fmt.Println("Scanning for matches...")
	if err := s.scan(); err != nil {
		return fmt.Errorf("failed to scan: %v", err)
	}

	return s.saveResults()
}

func (s *APKScanner) validateAPK() error {
	if _, err := os.Stat(s.config.APKFile); os.IsNotExist(err) {
		return fmt.Errorf("APK file does not exist: %s", s.config.APKFile)
	}
	s.apkPkg = filepath.Base(s.config.APKFile)
	return nil
}

func (s *APKScanner) loadPatterns() error {
	data, err := os.ReadFile(s.config.PatternsFile)
	if err != nil {
		return fmt.Errorf("failed to read patterns file: %v", err)
	}

	var config PatternsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse patterns YAML: %v", err)
	}

	// Validate and compile patterns
	s.patterns = make(map[string][]string)

	// Process patterns from single config
	for _, pattern := range config.Patterns {
		// Skip empty patterns
		if pattern.Name == "" || (pattern.Regex == "" && len(pattern.Regexes) == 0) {
			continue
		}

		var regexes []string
		if pattern.Regex != "" {
			regexes = []string{pattern.Regex}
		} else {
			regexes = pattern.Regexes
		}

		// Validate each regex
		validRegexes := make([]string, 0)
		for _, regex := range regexes {
			if _, err := regexp.Compile(regex); err != nil {
				fmt.Printf("%sWarning: Invalid regex pattern for '%s': %v%s\n",
					utils.ColorWarning, pattern.Name, err, utils.ColorEnd)
				continue
			}
			validRegexes = append(validRegexes, regex)
		}

		if len(validRegexes) > 0 {
			s.patterns[pattern.Name] = validRegexes
		}
	}

	if len(s.patterns) == 0 {
		return fmt.Errorf("no valid patterns found in patterns file")
	}

	fmt.Printf("%s** Loaded %d patterns%s\n",
		utils.ColorBlue, len(s.patterns), utils.ColorEnd)
	return nil
}

func (s *APKScanner) scan() error {
	var wg sync.WaitGroup
	resultsChan := make(chan struct {
		name    string
		matches []string
	})

	// First, collect all relevant files
	var files []string
	err := filepath.Walk(s.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isRelevantFile(info.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error collecting files: %v", err)
	}

	// Create a worker pool for file processing
	numWorkers := 10 // Adjust based on system capabilities
	filesChan := make(chan string)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range filesChan {
				s.processFile(file, resultsChan)
			}
		}()
	}

	// Feed files to workers
	go func() {
		for _, file := range files {
			filesChan <- file
		}
		close(filesChan)
	}()

	// Process results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results as they come in
	for result := range resultsChan {
		s.resultsMu.Lock()
		s.results[result.name] = append(s.results[result.name], result.matches...)
		s.resultsMu.Unlock()
	}

	return nil
}

func (s *APKScanner) processFile(path string, resultsChan chan<- struct {
	name    string
	matches []string
}) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	contentStr := string(content)
	seen := make(map[string]bool)

	for patternName, regexes := range s.patterns {
		var matches []string
		for _, regex := range regexes {
			re, err := regexp.Compile(regex)
			if err != nil {
				continue
			}

			found := re.FindAllString(contentStr, -1)
			for _, match := range found {
				match = strings.TrimSpace(match)
				if !seen[match] && match != "" {
					relPath, _ := filepath.Rel(s.tempDir, path)
					contextMatch := fmt.Sprintf("%s: %s", relPath, match)
					matches = append(matches, contextMatch)
					seen[match] = true
				}
			}
		}

		if len(matches) > 0 {
			resultsChan <- struct {
				name    string
				matches []string
			}{patternName, matches}
		}
	}
}

func (s *APKScanner) getCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".apkx", "cache")
}

func (s *APKScanner) getApkHash() (string, error) {
	f, err := os.Open(s.config.APKFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (s *APKScanner) decompileAPK() error {
	// Setup cache directory
	s.cacheDir = s.getCacheDir()
	if s.cacheDir != "" {
		if err := os.MkdirAll(s.cacheDir, 0755); err != nil {
			return err
		}

		// Get APK hash
		hash, err := s.getApkHash()
		if err != nil {
			return err
		}

		// Check if cached version exists
		cachedDir := filepath.Join(s.cacheDir, hash)
		if _, err := os.Stat(cachedDir); err == nil {
			fmt.Printf("%s** Using cached decompiled APK...%s\n", utils.ColorBlue, utils.ColorEnd)
			s.tempDir = cachedDir
			return nil
		}

		// If not cached, decompile and cache
		tempDir, err := os.MkdirTemp("", "apkleaks-")
		if err != nil {
			return err
		}

		jadx, err := decompiler.NewJadx()
		if err != nil {
			os.RemoveAll(tempDir)
			return err
		}

		fmt.Printf("%s** Decompiling APK (this may take a while)...%s\n", utils.ColorBlue, utils.ColorEnd)
		if err := jadx.Decompile(s.config.APKFile, tempDir, s.config.JadxArgs); err != nil {
			// Check if we have any decompiled files before giving up
			if _, statErr := os.Stat(filepath.Join(tempDir, "sources")); statErr == nil {
				fmt.Printf("%s** Some decompilation errors occurred, but continuing with available files...%s\n", 
					utils.ColorWarning, utils.ColorEnd)
			} else {
				os.RemoveAll(tempDir)
				return fmt.Errorf("failed to decompile APK: %v", err)
			}
		}

		// Move decompiled files to cache
		if err := os.Rename(tempDir, cachedDir); err != nil {
			os.RemoveAll(tempDir)
			return err
		}

		s.tempDir = cachedDir
		return nil
	}

	// Fallback to original behavior if caching is not possible
	tempDir, err := os.MkdirTemp("", "apkleaks-")
	if err != nil {
		return err
	}
	s.tempDir = tempDir

	jadx, err := decompiler.NewJadx()
	if err != nil {
		os.RemoveAll(tempDir)
		return err
	}

	fmt.Printf("%s** Decompiling APK (this may take a while)...%s\n", utils.ColorBlue, utils.ColorEnd)
	if err := jadx.Decompile(s.config.APKFile, tempDir, s.config.JadxArgs); err != nil {
		// Check if we have any decompiled files before giving up
		if _, statErr := os.Stat(filepath.Join(tempDir, "sources")); statErr == nil {
			fmt.Printf("%s** Some decompilation errors occurred, but continuing with available files...%s\n", 
				utils.ColorWarning, utils.ColorEnd)
			return nil
		}
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to decompile APK: %v", err)
	}

	return nil
}

func (s *APKScanner) saveResults() error {
	// Create statistics map for different finding types
	stats := make(map[string]int)
	
	// Count findings by category
	for category, matches := range s.results {
		if len(matches) > 0 {
			stats[category] = len(matches)
		}
	}

	// Print only the summary to terminal
	fmt.Printf("\n%s=== APK Analysis Summary ===%s\n", utils.ColorGreen, utils.ColorEnd)
	if len(stats) == 0 {
		fmt.Printf("%sNo sensitive information found.%s\n", utils.ColorYellow, utils.ColorEnd)
	} else {
		fmt.Printf("%sFound sensitive information in %d categories:%s\n", 
			utils.ColorBlue, len(stats), utils.ColorEnd)
		
		for category, count := range stats {
			fmt.Printf("  • %s: %d findings\n", category, count)
		}
	}

	// Save detailed results to JSON file
	if s.config.OutputFile != "" {
		jsonData, err := json.MarshalIndent(s.results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results to JSON: %v", err)
		}

		if err := os.WriteFile(s.config.OutputFile, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write results to file: %v", err)
		}
		fmt.Printf("\n%sDetailed results saved to: %s%s%s\n", 
			utils.ColorBlue, utils.ColorGreen, s.config.OutputFile, utils.ColorEnd)
	}

	return nil
}

// Helper function to filter relevant files
func isRelevantFile(filename string) bool {
	relevantExts := []string{".java", ".xml", ".txt", ".properties", ".json", ".yaml", ".yml"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, relevantExt := range relevantExts {
		if ext == relevantExt {
			return true
		}
	}
	return false
}
