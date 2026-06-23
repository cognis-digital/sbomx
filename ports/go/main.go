// Go port of the sbomx mobile-SBOM scanner — single static binary, zero deps.
//
// Mirrors the Python reference (sbomx/core.py): walk an extracted app
// directory (or explicit member paths passed as args), detect bundled
// third-party libraries by their well-known package-path markers, and emit a
// JSON SBOM summary with the same component shape as the reference tool.
//
// Defensive / offline only: it reads paths, never the network.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type rule struct {
	Key, Name, Marker, Ecosystem, PurlType, Group string
}

// Curated, real-world detection rules (subset shared with the Python reference).
var rules = []rule{
	{"firebase", "firebase-core", "com/google/firebase/", "maven", "maven", "com.google.firebase"},
	{"okhttp", "okhttp", "okhttp3/", "maven", "maven", "com.squareup.okhttp3"},
	{"retrofit", "retrofit", "retrofit2/", "maven", "maven", "com.squareup.retrofit2"},
	{"gson", "gson", "com/google/gson/", "maven", "maven", "com.google.code.gson"},
	{"glide", "glide", "com/bumptech/glide/", "maven", "maven", "com.github.bumptech.glide"},
	{"react-native", "react-native", "com/facebook/react/", "npm", "npm", ""},
	{"flutter", "flutter", "io/flutter/", "maven", "maven", "io.flutter"},
	{"alamofire", "Alamofire", "Alamofire.framework", "cocoapods", "cocoapods", ""},
	{"afnetworking", "AFNetworking", "AFNetworking.framework", "cocoapods", "cocoapods", ""},
	{"sqlite", "sqlite", "libsqlite", "native", "generic", ""},
	{"openssl", "openssl", "libssl", "native", "generic", ""},
	{"openssl", "openssl", "libcrypto", "native", "generic", ""},
	{"libwebp", "libwebp", "libwebp", "native", "generic", ""},
	{"libpng", "libpng", "libpng", "native", "generic", ""},
	{"zlib", "zlib", "libz.so", "native", "generic", ""},
	{"crashlytics", "firebase-crashlytics", "com/google/firebase/crashlytics/", "maven", "maven", "com.google.firebase"},
	{"appsflyer", "appsflyer", "com/appsflyer/", "maven", "maven", "com.appsflyer"},
	{"adjust", "adjust-sdk", "com/adjust/sdk/", "maven", "maven", "com.adjust.sdk"},
}

var verRe = regexp.MustCompile(`[-_.](\d+(?:\.\d+){1,3}[a-z]?)`)

type component struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
	Evidence  string `json:"evidence"`
}

func extractVersion(path string) string {
	base := filepath.Base(path)
	if m := verRe.FindStringSubmatch(base); m != nil {
		return m[1]
	}
	return ""
}

func purl(r rule, version string) string {
	ns := ""
	if r.Group != "" {
		ns = r.Group + "/"
	}
	v := ""
	if version != "" {
		v = "@" + version
	}
	return fmt.Sprintf("pkg:%s/%s%s%s", r.PurlType, ns, r.Name, v)
}

func detect(paths []string) []component {
	found := map[string]component{}
	for _, p := range paths {
		norm := strings.ReplaceAll(p, "\\", "/")
		base := strings.ToLower(filepath.Base(norm))
		for _, r := range rules {
			versioned := strings.HasPrefix(base, strings.ToLower(r.Key)+"-") ||
				strings.HasPrefix(base, strings.ToLower(r.Key)+"_")
			if strings.Contains(norm, r.Marker) || versioned {
				version := extractVersion(norm)
				c, ok := found[r.Key]
				if !ok {
					found[r.Key] = component{r.Name, version, r.Ecosystem, purl(r, version), norm}
				} else if c.Version == "" && version != "" {
					c.Version = version
					c.Purl = purl(r, version)
					c.Evidence = norm
					found[r.Key] = c
				}
			}
		}
	}
	out := make([]component, 0, len(found))
	for _, c := range found {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func walkDir(target string) []string {
	var paths []string
	filepath.Walk(target, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(target, p)
		paths = append(paths, rel)
		return nil
	})
	return paths
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"."}
	}
	var paths []string
	if fi, err := os.Stat(args[0]); err == nil && fi.IsDir() {
		paths = walkDir(args[0])
	} else {
		paths = args
	}
	comps := detect(paths)
	out, _ := json.MarshalIndent(map[string]any{
		"tool":       "sbomx",
		"port":       "go",
		"components": comps,
		"count":      len(comps),
	}, "", "  ")
	fmt.Println(string(out))
}
