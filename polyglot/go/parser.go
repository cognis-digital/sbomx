package parser

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// =============================================================================
// Core Data Types
// =============================================================================

type Component struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Type       string `json:"type"` // "library", "sdk", "framework"
	Arch       string `json:"arch,omitempty"`
	SDKVersion string `json:"sdk_version,omitempty"`
	Source     SourceInfo `json:"source,omitempty"`
}

type SourceInfo struct {
	Path    string `json:"path,omitempty"`
	Bundle  string `json:"bundle,omitempty"`
	License string `json:"license,omitempty"`
}

type VulnerabilityMatch struct {
	CVE         string   `json:"cve"`
	CVSS        float64  `json:"cvss,omitempty"`
	Status      string   `json:"status"` // "affected", "patched"
	PatchVersion string   `json:"patch_version,omitempty"`
	Reference   []string `json:"reference,omitempty"`
}

type ParseResult struct {
	Components    []Component           `json:"components"`
	Vulnerabilities map[string][]VulnerabilityMatch `json:"vulnerabilities"`
	Metadata      Metadata             `json:"metadata"`
	Warnings      []string              `json:"warnings"`
}

type Metadata struct {
	AppName       string            `json:"app_name,omitempty"`
	PackageName   string            `json:"package_name,omitempty"`
	BuildNumber   string            `json:"build_number,omitempty"`
	SDKVersion    string            `json:"sdk_version,omitempty"`
	TotalLibs     int               `json:"total_libs"`
	TotalSDKs     int               `json:"total_sdks"`
	ParseDuration float64           `json:"parse_duration_ms"`
}

// =============================================================================
// Known SDK Manifests (Real-world patterns)
// =============================================================================

var knownSDKManifests = map[string][]string{
	"com.google.android.gms": {
		"libgmscore.so", "libgmsbase.so", "libgmscommon.so",
	},
	"com.google.firebase": {
		"libfirebasecore.so", "libfirebaseauth.so",
	},
	"com.facebook.sdk": {
		"libfbcore.so", "libfbsdkcore.so",
	},
	"com.mixpanel.android": {
		"libmixpanel.so",
	},
}

// =============================================================================
// ELF Parser (Android .so files)
// =============================================================================

type ELFHeader struct {
	Ident   [16]byte
	Type    uint16
	Machine uint16
	Version uint32
	Entry   uint64
	Phoff   uint32
	Shoff   uint32
}

func ParseELFHeader(data []byte) (ELFHeader, error) {
	if len(data) < 52 {
		return ELFHeader{}, fmt.Errorf("too short for ELF header")
	}

	var h ELFHeader
	copy(h.Ident[:], data[0:16])
	binary.LittleEndian.PutUint16(h.Ident[14:], data[16]) // Type at offset 16
	h.Type = binary.LittleEndian.Uint16(data[18:])
	h.Machine = binary.LittleEndian.Uint16(data[20:])
	h.Version = binary.LittleEndian.Uint32(data[22:])
	h.Entry = binary.LittleEndian.Uint64(data[24:32])
	h.Phoff = binary.LittleEndian.Uint32(data[32:36])
	h.Shoff = binary.LittleEndian.Uint32(data[36:40])

	return h, nil
}

func IsELF(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	return bytes.Equal(data[:4], []byte{0x7f, 0x45, 0x4c, 0x46}) // "\x7fELF"
}

// =============================================================================
// Mach-O Parser (iOS .dylib/.framework)
// =============================================================================

type MachOHeader struct {
	Magic   uint32
	Cputype uint16
	Cpusubt uint16
	Flavor  uint16
	Ncmds   uint32
}

func ParseMachOHeader(data []byte) (MachOHeader, error) {
	if len(data) < 28 {
		return MachOHeader{}, fmt.Errorf("too short for Mach-O header")
	}

	var h MachOHeader
	h.Magic = binary.LittleEndian.Uint32(data[0:4])
	h.Cputype = binary.LittleEndian.Uint16(data[4:6])
	h.Cpusubt = binary.LittleEndian.Uint16(data[6:8])
	h.Flavor = binary.LittleEndian.Uint16(data[8:10])
	h.Ncmds = binary.LittleEndian.Uint32(data[12:16])

	return h, nil
}

func IsMachO(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	return magic == 0xfeedface || magic == 0xfeedfacf // FAT or Mach-O
}

// =============================================================================
// SDK Manifest Parser (JSON/XML from embedded files)
// =============================================================================

type JSONManifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Bundle  string            `json:"bundle_id,omitempty"`
	License string            `json:"license,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func ParseJSONManifest(r io.Reader) (*JSONManifest, error) {
	var m JSONManifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return &m, err
	}
	return &m, nil
}

// =============================================================================
// Archive Extractor
// =============================================================================

type ExtractedFile struct {
	Name    string
	Data    []byte
	Headers map[string][]byte // "elf", "macho"
}

func ExtractFromZip(zipPath string) ([]ExtractedFile, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer f.Close()

	zr, err := zip.OpenReader(f.Name())
	if err != nil {
		return nil, fmt.Errorf("read zip: %w", err)
	}
	defer zr.Close()

	var files []ExtractedFile
	for _, file := range zr.File {
		if !file.FileHeader.Modified || file.FileHeader.UncompressedSize == 0 {
			continue
		}

		r, err := file.Open()
		if err != nil {
			continue
		}

		data, _ := io.ReadAll(r)
		files = append(files, ExtractedFile{
			Name:    file.Name,
			Data:    data,
			Headers: make(map[string][]byte),
		})

		if IsELF(data) {
			files[0].Headers["elf"] = data[:min(52, len(data))]
		} else if IsMachO(data) {
			files[0].Headers["macho"] = data[:min(28, len(data))]
		}
	}

	return files, nil
}

// =============================================================================
// Vulnerability Database (Embedded for demo - real app would load from disk/HTTP)
// =============================================================================

type VulnDB struct {
	CVEs    map[string]CVEEntry
	Libs    map[string][]string // library_name -> known CVEs
}

func DefaultVulnDB() *VulnDB {
	db := &VulnDB{
		CVEs:   make(map[string]CVEEntry),
		Libs:   make(map[string][]string),
	}

	// Real CVE data would come from NVD, vendor feeds, etc.
	db.CVEs["CVE-2023-12345"] = CVEEntry{
		CVSS: 7.5,
		PatchVersion: "1.4.2",
		Status: "affected",
	}

	return db
}

type CVEEntry struct {
	CVSS      float64
	PatchVersion string
	Status    string
}

// =============================================================================
// Main Parser Implementation
// =============================================================================

func Parse(zipPath string, vulnDB *VulnDB) (*ParseResult, error) {
	start := time.Now()

	result := &ParseResult{
		Components:      []Component{},
		Vulnerabilities: map[string][]VulnerabilityMatch{},
		Metadata:        Metadata{},
		Warnings:        []string{},
	}

	files, err := ExtractFromZip(zipPath)
	if err != nil {
		return result, fmt.Errorf("extract archive: %w", err)
	}

	result.Metadata.TotalLibs = len(files)

	for _, f := range files {
		// Parse ELF headers for .so files
		if elfHeader, ok := f.Headers["elf"]; ok {
			h, _ := ParseELFHeader(elfHeader)
			if h.Type == 0x2 || h.Type == 0x3 { // ET_EXEC or ET_DYN
				result.Components = append(result.Components, Component{
					Name:       filepath.Base(f.Name),
					Type:       "library",
					Arch:       archFromMachine(h.Machine),
					SDKVersion: elfHeader.Version.String(),
				})
			}
		}

		// Parse Mach-O headers for .dylib/.framework
		if machoHeader, ok := f.Headers["macho"]; ok {
			h, _ := ParseMachOHeader(machoHeader)
			result.Components = append(result.Components, Component{
				Name:       filepath.Base(f.Name),
				Type:       "library",
				Arch:       archFromMachine(h.Cputype),
				SDKVersion: fmt.Sprintf("%d.%d", h.Magic>>16, h.Magic&0xFFFF),
			})
		}

		// Check for SDK manifest files
		if strings.Contains(f.Name, "manifest") || strings.Contains(f.Name, "config.json") {
			r := bytes.NewReader(f.Data)
			if m, err := ParseJSONManifest(r); err == nil && m.Name != "" {
				result.Components = append(result.Components, Component{
					Name:       m.Name,
					Version:    m.Version,
					Type:       "sdk",
					SDKVersion: m.Bundle,
					Source:     SourceInfo{Bundle: m.Bundle},
				})
			}
		}

		// Check against known SDKs
		for _, sdk := range knownSDKManifests {
			if strings.Contains(f.Name, sdk[0]) {
				result.Components = append(result.Components, Component{
					Name:       filepath.Base(f.Name),
					Version:    "detected",
					Type:       "sdk",
					SDKVersion: sdk[0],
				})
			}
		}
	}

	// Match against vulnerability database
	for _, comp := range result.Components {
		if vulnDB != nil && len(vulnDB.CVEs) > 0 {
			result = matchVulnerabilities(comp, *vulnDB, result)
		}
	}

	result.Metadata.ParseDuration = time.Since(start).Seconds() * 1000
	return result, nil
}

func archFromMachine(machine uint16) string {
	switch machine {
	case 0x3E: return "arm"
	case 0x28: return "aarch64"
	case 0x70: return "x86_64"
	case 0x02: return "i386"
	default: return fmt.Sprintf("unknown(0x%04X)", machine)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Vulnerability Matching
// =============================================================================

func matchVulnerabilities(comp Component, db VulnDB, result *ParseResult) *ParseResult {
	for _, cve := range db.CVEs {
		key := fmt.Sprintf("%s@%s", comp.Name, comp.Version)
		
		if strings.Contains(key, "gmscore") || strings.Contains(key, "firebase") {
			result.Vulnerabilities[key] = append(result.Vulnerabilities[key], VulnerabilityMatch{
				CVE:         cve.CVE,
				CVSS:        cve.CVSS,
				Status:      cve.Status,
				PatchVersion: cve.PatchVersion,
				Reference:   []string{"https://nvd.nist.gov/vuln/detail/" + strings.ReplaceAll(cve.CVE, "-", "")},
			})
		}
	}

	return result
}

// =============================================================================
// Demo / Entry Point
// =============================================================================

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sbomx parse <zip_file>")
		os.Exit(0)
	}

	db := DefaultVulnDB()
	result, err := Parse(os.Args[1], db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output as JSON for CycloneDX integration
	jsonBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(jsonBytes))
}