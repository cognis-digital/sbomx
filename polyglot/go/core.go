package core

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Component represents a software component identified in the app.
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Vendor    string `json:"vendor,omitempty"`
	Type      string `json:"type"` // library, framework, sdk, etc.
	Group     string `json:"group,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// Vulnerability represents a known vulnerability for a component.
type Vulnerability struct {
	ID          string   `json:"id"`
	CVSS        float64  `json:"cvss,omitempty"`
	Summary     string   `json:"summary"`
	Affected    []string `json:"affected_versions"`
	References  []string `json:"references,omitempty"`
}

// PrivacyTracker represents a privacy/tracking capability.
type PrivacyTracker struct {
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

// CycloneDXSBOM is the root SBOM document.
type CycloneDXSBOM struct {
	Version    int                    `json:"specVersion"`
	Components []Component            `json:"components,omitempty"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities,omitempty"`
	Trackers   []PrivacyTracker     `json:"trackers,omitempty"`
	Metadata   *SBOMMetadata        `json:"metadata,omitempty"`
}

// SBOMMetadata holds scanner metadata.
type SBOMMetadata struct {
	Scanner    string `json:"scanner"`
	Version    string `json:"version"`
	Platform   string `json:"platform,omitempty"`
	InputFile  string `json:"input_file,omitempty"`
}

const (
	SBOMSpecVersion = "1.6"
	ScannerName     = "sbomx-core"
)

// Scanner handles file system traversal and initial discovery.
type Scanner struct {
	RootPath    string
	Extensions  []string
	MinSize     int64 // minimum file size to consider
}

func NewScanner(root string, extensions []string, minSize int64) *Scanner {
	if len(extensions) == 0 {
		extensions = []string{".so", ".dylib", ".a", ".framework"}
	}
	return &Scanner{
		RootPath:    root,
		Extensions:  extensions,
		MinSize:     minSize,
	}
}

// Scan traverses the directory and returns matching files.
func (s *Scanner) Scan() ([]string, error) {
	var matches []string
	err := filepath.Walk(s.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and very small files
		if info.IsDir() || info.Size() < s.MinSize {
			return nil
		}

		// Check extension match
		ext := strings.ToLower(filepath.Ext(path))
		for _, e := range s.Extensions {
			if ext == e {
				matches = append(matches, path)
				break
			}
		}

		return nil
	})

	return matches, err
}

// Parser extracts metadata from binary files and archives.
type Parser struct {
	ComponentDB  *ComponentDatabase
	HashCache    map[string]string
	mu            sync.RWMutex
}

// ComponentDatabase stores known component signatures.
type ComponentDatabase struct {
	Signatures     map[string][]string // hash -> [names]
	VersionRanges  map[string][]Range  // name:version -> ranges
}

func NewParser() *Parser {
	return &Parser{
		ComponentDB: &ComponentDatabase{
			Signatures: make(map[string][]string),
			VersionRanges: make(map[string][]Range),
		},
		HashCache: make(map[string]string),
	}
}

// Range represents a version range.
type Range struct {
	Start string `json:"start"`
	End   string `json:"end,omitempty"`
	Op    string `json:"op"` // eq, ge, gt, le, lt
}

func (p *Parser) GetCachedHash(path string) (string, error) {
	p.mu.RLock()
	if h, ok := p.HashCache[path]; ok {
		p.mu.RUnlock()
		return h, nil
	}
	p.mu.RUnlock()

	h, err := computeFileHash(path)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	p.HashCache[path] = h
	p.mu.Unlock()

	return h, nil
}

// ParseBinary extracts component info from a binary file.
func (p *Parser) ParseBinary(path string) ([]Component, error) {
	var components []Component

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try to extract name/version from common patterns
	name, version, vendor := p.extractMetadata(data)

	if name == "" && len(p.ComponentDB.Signatures) > 0 {
		h, _ := computeFileHash(path)
		if names, ok := p.ComponentDB.Signatures[h]; ok {
			for _, n := range names {
				components = append(components, Component{
					Name:   n,
					Version: version,
					Vendor: vendor,
					Type:   "library",
					Hash:   h,
				})
			}
		}
	}

	if name != "" {
		components = append(components, Component{
			Name:    name,
			Version: version,
			Vendor:  vendor,
			Type:    "library",
			Hash:    h,
		})
	}

	return components, nil
}

// extractMetadata attempts to parse common metadata formats.
func (p *Parser) extractMetadata(data []byte) (string, string, string) {
	var name, version, vendor string

	// Try JSON parsing first
	if jsonErr := json.Unmarshal(data, &struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vendor  string `json:"vendor"`
	}{
		Name:    "",
		Version: "",
		Vendor:  "",
	}); jsonErr == nil {
		if data[0] != '{' {
			name = "unknown"
			version = "1.0.0"
			vendor = ""
		}
	}

	// Try text-based parsing for common formats
	text := string(data)

	// Check for Maven/Gradle style coordinates
	mavenRe := regexp.MustCompile(`(?i)(?:com\.|org\.)?([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)` )
	if m := mavenRe.FindStringSubmatch(text); len(m) >= 3 {
		name = strings.Join(m[1:2], ".") + ":" + m[2]
		version, _ = p.extractVersionFromCoords(name, text)
	}

	// Check for CocoaPods style
	cocoapodsRe := regexp.MustCompile(`(?i)(?:Pod|Cocoa).*?([a-zA-Z0-9._-]+)` )
	if m := cocoapodsRe.FindStringSubmatch(text); len(m) >= 2 {
		name = strings.Join(m[1:2], ".") + ":" + m[2]
	}

	// Check for common vendor prefixes
	vendorPrefixes := map[string]string{
		"com.google.android.gms":    "Google",
		"com.facebook.android":      "Meta/Facebook",
		"com.apple":                 "Apple",
		"org.mozilla":               "Mozilla",
	}

	for prefix, v := range vendorPrefixes {
		if strings.Contains(text, prefix) {
			vendor = v
			break
		}
	}

	return name, version, vendor
}

// extractVersionFromCoords tries to parse version from coordinate string.
func (p *Parser) extractVersionFromCoords(coord string, text string) string {
	versionRe := regexp.MustCompile(`(?i)(?:v|ver|version)?([0-9]+\.[0-9]+(\.[0-9]+)?(?:\+[a-zA-Z0-9._-]*)?)`)
	if m := versionRe.FindStringSubmatch(text); len(m) >= 2 {
		return m[1]
	}
	return "unknown"
}

// Matcher matches components against vulnerability and privacy databases.
type Matcher struct {
	VulnDB      *VulnerabilityDatabase
	PrivacyDB   *PrivacyDatabase
	Components  []Component
	mu           sync.RWMutex
}

func NewMatcher() *Matcher {
	return &Matcher{
		VulnDB:     &VulnerabilityDatabase{},
		PrivacyDB:  &PrivacyDatabase{},
		Components: make([]Component, 0),
	}
}

// VulnerabilityDatabase stores known vulnerabilities.
type VulnerabilityDatabase struct {
	Entries      map[string][]Entry // name:version -> [entries]
	LastUpdated  string
}

func (v *VulnerabilityDatabase) Add(name, version string, vuln VulnEntry) {
	key := fmt.Sprintf("%s:%s", name, version)
	if v.Entries == nil {
		v.Entries = make(map[string][]Entry)
	}
	v.Entries[key] = append(v.Entries[key], Entry{Vuln: vuln})
}

// VulnerabilityDatabase stores known privacy trackers.
type PrivacyDatabase struct {
	Entries      map[string][]PrivacyEntry // name -> [entries]
	LastUpdated  string
}

func (p *PrivacyDatabase) Add(name, vendor string, tracker PrivacyEntry) {
	if p.Entries == nil {
		p.Entries = make(map[string][]PrivacyEntry)
	}
	key := fmt.Sprintf("%s:%s", name, vendor)
	p.Entries[key] = append(p.Entries[key], PrivacyEntry{Tracker: tracker})
}

// Entry represents a vulnerability entry.
type VulnEntry struct {
	ID          string   `json:"id"`
	CVSS        float64  `json:"cvss,omitempty"`
	Summary     string   `json:"summary"`
	Affected    []string `json:"affected_versions"`
	References  []string `json:"references,omitempty"`
}

// PrivacyEntry represents a privacy entry.
type PrivacyEntry struct {
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor,omitempty"`
	Categories []string `json:"categories,omitempty"`
}

func (m *Matcher) MatchVulnerabilities() ([]Vulnerability, error) {
	var results []Vulnerability

	for _, comp := range m.Components {
		if len(m.VulnDB.Entries) == 0 {
			continue
		}

		key := fmt.Sprintf("%s:%s", comp.Name, comp.Version)
		if entries, ok := m.VulnDB.Entries[key]; ok {
			for _, e := range entries {
				results = append(results, Vulnerability{
					ID:       e.ID,
					CVSS:     e.CVSS,
					Summary:  e.Summary,
					References: e.References,
				})
			}
		}

		// Also check partial matches (name only)
		if entries, ok := m.VulnDB.Entries[comp.Name]; ok {
			for _, e := range entries {
				results = append(results, Vulnerability{
					ID:       e.ID,
					CVSS:     e.CVSS,
					Summary:  e.Summary,
					References: e.References,
				})
			}
		}
	}

	return results, nil
}

func (m *Matcher) MatchPrivacy() ([]PrivacyTracker, error) {
	var results []PrivacyTracker

	for _, comp := range m.Components {
		if len(m.PrivacyDB.Entries) == 0 {
			continue
		}

		key := fmt.Sprintf("%s:%s", comp.Name, comp.Vendor)
		if entries, ok := m.PrivacyDB.Entries[key]; ok {
			for _, e := range entries {
				results = append(results, PrivacyTracker{
					Name:       e.Tracker.Name,
					Vendor:     e.Tracker.Vendor,
					Categories: e.Tracker.Categories,
				})
			}
		}

		if entries, ok := m.PrivacyDB.Entries[comp.Name]; ok {
			for _, e := range entries {
				results = append(results, PrivacyTracker{
					Name:       e.Tracker.Name,
					Vendor:     e.Tracker.Vendor,
					Categories: e.Tracker.Categories,
				})
			}
		}
	}

	return results, nil
}

// Generator builds the CycloneDX SBOM document.
type Generator struct {
	Components []Component
	Vulns      []Vulnerability
	Trackers   []PrivacyTracker
	Metadata   *SBOMMetadata
}

func NewGenerator(components []Component) *Generator {
	return &Generator{
		Components: components,
		Metadata: &SBOMMetadata{
			Scanner:  ScannerName,
			Version:  "1.0.0",
			Platform: "mobile",
		},
	}
}

func (g *Generator) AddVulnerabilities(vulns []Vulnerability) {
	g.Vulns = vulns
}

func (g *Generator) AddTrackers(trackers []PrivacyTracker) {
	g.Trackers = trackers
}

// Build creates the CycloneDX SBOM.
func (g *Generator) Build() (*CycloneDXSBOM, error) {
	sbom := &CycloneDXSBOM{
		Version:    1,
		Components: g.Components,
		Metadata:   g.Metadata,
	}

	if len(g.Vulns) > 0 {
		sbom.Vulnerabilities = g.Vulns
	}

	if len(g.Trackers) > 0 {
		sbom.Trackers = g.Trackers
	}

	return sbom, nil
}

// MarshalJSON returns the SBOM as JSON bytes.
func (s *CycloneDXSBOM) MarshalJSON() ([]byte, error) {
	return json.Marshal(s)
}

// String returns a formatted string representation.
func (s *CycloneDXSBOM) String() string {
	data, _ := s.MarshalJSON()
	return string(data)
}

// Core orchestrates the entire SBOM generation pipeline.
type Core struct {
	Scanner    *Scanner
	Parser     *Parser
	Matcher    *Matcher
	Generator  *Generator
	mu          sync.Mutex
}

func NewCore(scannerRoot, extensions string, minSize int64) (*Core, error) {
	c := &Core{
		Scanner:   NewScanner(scannerRoot, strings.Split(extensions, ","), minSize),
		Parser:    NewParser(),
		Matcher:   NewMatcher(),
		Generator: NewGenerator(nil),
	}

	return c, nil
}

// Run executes the full pipeline and returns the SBOM.
func (c *Core) Run() (*CycloneDXSBOM, error) {
	var components []Component

	// Step 1: Scan for files
	matches, err := c.Scanner.Scan()
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	if len(matches) == 0 {
		return &CycloneDXSBOM{
			Version:    1,
			Metadata:   c.Generator.Metadata,
		}, nil
	}

	// Step 2: Parse each file for components
	for _, path := range matches {
		compList, err := c.Parser.ParseBinary(path)
		if err != nil {
			continue // Log warning in production
		}

		for _, comp := range compList {
			c.Generator.Components = append(c.Generator.Components, comp)
		}
	}

	// Step 3: Match against vulnerability database
	vulns, _ := c.Matcher.MatchVulnerabilities()
	c.Generator.AddVulnerabilities(vulns)

	// Step 4: Match against privacy database
	trackers, _ :=