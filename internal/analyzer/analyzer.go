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
	APKFile      string
	OutputFile   string
	PatternsFile string
	JadxArgs     string
	JSON         bool
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
	fmt.Printf("%s** Scanning APK: %s%s\n", utils.ColorBlue, s.apkPkg, utils.ColorEnd)

	// Create temporary directory
	fmt.Printf("%s** Creating temporary directory...%s\n", utils.ColorBlue, utils.ColorEnd)
	if err := s.decompileAPK(); err != nil {
		return fmt.Errorf("failed to decompile APK: %v", err)
	}
	// Only remove temp dir if it's not a cached one
	if s.cacheDir == "" || !strings.HasPrefix(s.tempDir, s.cacheDir) {
		defer os.RemoveAll(s.tempDir)
	}

	// Load patterns
	fmt.Printf("%s** Loading patterns...%s\n", utils.ColorBlue, utils.ColorEnd)
	if err := s.loadPatterns(); err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}

	// Scan for matches
	fmt.Printf("%s** Scanning for matches...%s\n", utils.ColorBlue, utils.ColorEnd)
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
	matchFound := false
	for result := range resultsChan {
		matchFound = true
		s.resultsMu.Lock()
		s.results[result.name] = append(s.results[result.name], result.matches...)
		s.resultsMu.Unlock()

		fmt.Printf("\n%s[%s]%s\n", utils.ColorGreen, result.name, utils.ColorEnd)
		for _, match := range result.matches {
			fmt.Printf("- %s\n", match)
		}
	}

	if !matchFound {
		fmt.Printf("\n%s** Done with nothing. ¯\\_(ツ)_/¯%s\n", utils.ColorWarning, utils.ColorEnd)
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

		if err := jadx.Decompile(s.config.APKFile, tempDir, s.config.JadxArgs); err != nil {
			os.RemoveAll(tempDir)
			return err
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
		return err
	}
	return jadx.Decompile(s.config.APKFile, s.tempDir, s.config.JadxArgs)
}

func (s *APKScanner) saveResults() error {
	if s.config.OutputFile == "" {
		return nil
	}

	file, err := os.Create(s.config.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	if s.config.JSON {
		output := struct {
			Package string              `json:"package"`
			Results map[string][]string `json:"results"`
		}{
			Package: s.apkPkg,
			Results: s.results,
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "    ")
		return encoder.Encode(output)
	}

	for name, matches := range s.results {
		fmt.Fprintf(file, "[%s]\n", name)
		for _, match := range matches {
			fmt.Fprintf(file, "- %s\n", match)
		}
		fmt.Fprintln(file)
	}

	if s.config.OutputFile != "" {
		fmt.Printf("%s\n** Results saved into '%s%s%s%s'%s.\n",
			utils.ColorHeader,
			utils.ColorEnd,
			utils.ColorGreen,
			s.config.OutputFile,
			utils.ColorHeader,
			utils.ColorEnd)
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
