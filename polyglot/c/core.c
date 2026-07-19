/*
 * sbomx/core.c - Core SBOM generation engine for mobile apps
 * 
 * Generates CycloneDX SBOM by unpacking native libs/SDKs, matching
 * components against vulnerability and privacy databases.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#define MAX_PATH 4096
#define MAX_LIBS 1024
#define MAX_VULNS 8192
#define MAX_PRIVACY 512
#define CHUNK_SIZE 64 * 1024

/* Data structures */
typedef struct {
    char name[256];
    char version[64];
    char license[256];
    char arch[32];
    char platform[32];
    uint64_t size;
    time_t timestamp;
} LibraryInfo;

typedef struct {
    char name[256];
    char version[64];
    int cve_count;
    int cvss_score;
    char severity[16];
    char description[512];
    char advisory_url[512];
} Vulnerability;

typedef struct {
    char name[256];
    char version[64];
    int tracker_count;
    char categories[2][32];
    char description[512];
} PrivacyInfo;

typedef struct {
    LibraryInfo libs[MAX_LIBS];
    size_t lib_count;
    Vulnerability vulns[MAX_VULNS];
    size_t vuln_count;
    PrivacyInfo privacy[MAX_PRIVACY];
    size_t priv_count;
    char output_path[512];
} SBOMLib;

/* Forward declarations */
static int sbomx_init_core(SBOMLib *sbom, const char *output_path);
static int sbomx_scan_directory(const char *path, LibraryInfo *libs, size_t max_libs);
static int sbomx_extract_archive(const char *archive_path, LibraryInfo *libs, size_t *idx);
static int sbomx_parse_library_metadata(LibraryInfo *lib, const char *file_path);
static int sbomx_match_vulnerabilities(SBOMLib *sbom, SBOMLib *target);
static int sbomx_track_privacy(SBOMLib *sbom, SBOMLib *target);
static void sbomx_generate_cyclonedx(const SBOMLib *sbom, const char *output_path);

/* ============ INITIALIZATION ============ */

int sbomx_init_core(SBOMLib *sbom, const char *output_path) {
    if (!sbom || !output_path) return -1;
    
    memset(sbom, 0, sizeof(*sbom));
    strncpy(sbom->output_path, output_path, sizeof(sbom->output_path) - 1);
    sbom->lib_count = 0;
    sbom->vuln_count = 0;
    sbom->priv_count = 0;
    
    return 0;
}

/* ============ FILE SYSTEM & SCAN ============ */

static int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static int is_regular_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int get_file_size(const char *path, uint64_t *size) {
    struct stat st;
    if (stat(path, &st) == 0) {
        *size = (uint64_t)st.st_size;
        return 1;
    }
    return 0;
}

static int get_file_mtime(const char *path, time_t *mtime) {
    struct stat st;
    if (stat(path, &st) == 0) {
        *mtime = st.st_mtime;
        return 1;
    }
    return 0;
}

/* Scan a directory for library files */
static int sbomx_scan_directory(const char *path, LibraryInfo *libs, size_t max_libs) {
    DIR *dir;
    struct dirent *entry;
    char search_path[MAX_PATH];
    uint64_t total_size = 0;
    time_t now = time(NULL);
    
    if (!dir_open(path)) return -1;
    
    dir_rewind();
    
    while (max_libs > 0 && libs) {
        entry = dir_read(dir, &search_path);
        
        if (!entry || !is_regular_file(search_path)) continue;
        
        /* Check for library patterns */
        const char *ext = strrchr(search_path, '.');
        int is_library = 0;
        
        if (ext) {
            size_t len = strlen(ext);
            if (len < 4) continue;
            
            /* Common mobile library extensions */
            if (strncasecmp(ext, ".so", 3) == 0 ||
                strncasecmp(ext, ".a", 2) == 0 ||
                strncasecmp(ext, ".jar", 4) == 0 ||
                strncasecmp(ext, ".aar", 4) == 0 ||
                strncasecmp(ext, ".dylib", 6) == 0 ||
                strncasecmp(ext, ".framework", 11) == 0) {
                is_library = 1;
            }
        }
        
        if (!is_library) continue;
        
        /* Get file metadata */
        uint64_t size = 0;
        time_t mtime = now;
        
        get_file_size(search_path, &size);
        get_file_mtime(search_path, &mtime);
        
        /* Extract library name from path/filename */
        char name[256] = {0};
        strncpy(name, search_path, sizeof(name) - 1);
        
        /* Clean up name - remove common prefixes/suffixes */
        if (strlen(name) > 32) {
            const char *last_slash = strrchr(name, '/');
            if (last_slash) {
                strncpy(name, last_slash + 1, sizeof(name) - 1);
            }
        }
        
        /* Remove version suffix for matching */
        size_t nlen = strlen(name);
        while (nlen > 0 && (isdigit((unsigned char)name[nlen-1]) || 
                           name[nlen-1] == '.' || name[nlen-1] == '_')) {
            name[--nlen] = '\0';
        }
        
        /* Create library entry */
        strncpy(libs[libs->lib_count].name, name, sizeof(libs[libs->lib_count].name) - 1);
        libs[libs->lib_count].size = size;
        libs[libs->lib_count].timestamp = mtime;
        
        /* Parse version from filename if present */
        const char *ver_start = strrchr(name, '_');
        if (!ver_start) ver_start = name + strlen(name);
        
        strncpy(libs[libs->lib_count].version, ver_start, sizeof(libs[libs->lib_count].version) - 1);
        
        /* Default values */
        strcpy(libs[libs->lib_count].license, "UNKNOWN");
        strcpy(libs[libs->lib_count].arch, "generic");
        strcpy(libs[libs->lib_count].platform, "mobile");
        
        libs->lib_count++;
        max_libs--;
    }
    
    dir_close(dir);
    return (int)libs->lib_count;
}

/* ============ ARCHIVE EXTRACTION ============ */

static int is_archive(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    
    size_t len = strlen(ext);
    if (len < 4) return 0;
    
    /* Check for archive formats */
    if (strncasecmp(ext, ".tar", 4) == 0 ||
        strncasecmp(ext, ".tar.gz", 7) == 0 ||
        strncasecmp(ext, ".tgz", 4) == 0 ||
        strncasecmp(ext, ".tar.bz2", 8) == 0 ||
        strncasecmp(ext, ".tbz2", 5) == 0 ||
        strncasecmp(ext, ".zip", 4) == 0 ||
        strncasecmp(ext, ".jar", 4) == 0 ||
        strncasecmp(ext, ".aar", 4) == 0) {
        return 1;
    }
    
    return 0;
}

/* Simple tar extraction - extracts to temp directory */
static int extract_tar(const char *src, const char *dst) {
    FILE *f = fopen(src, "rb");
    if (!f) return -1;
    
    /* Create destination directory */
    mkdir(dst, 0755);
    
    unsigned char header[512];
    int got_header = 1;
    
    while (got_header && fread(header, 1, 512, f)) {
        if (!memcmp(header, "ustar", 5) || !memcmp(header, "POSIX", 5)) {
            /* Valid tar header */
            unsigned char *name = header + 257;
            size_t namelen = 0;
            
            while (namelen < 100 && name[namelen] != '\0') {
                namelen++;
            }
            
            if (namelen > 0) {
                char path[MAX_PATH];
                strncpy(path, name, sizeof(path) - 1);
                
                /* Skip directories */
                if (!is_directory(path)) {
                    char full_path[MAX_PATH + MAX_PATH];
                    snprintf(full_path, sizeof(full_path), "%s/%s", dst, path);
                    
                    /* Create parent directory */
                    char *parent = strrchr(full_path, '/');
                    if (parent) {
                        *parent = '\0';
                        mkdir(parent, 0755);
                    }
                }
            }
        } else {
            got_header = 0;
        }
    }
    
    fclose(f);
    return 0;
}

/* Simple zip extraction */
static int extract_zip(const char *src, const char *dst) {
    FILE *f = fopen(src, "rb");
    if (!f) return -1;
    
    /* ZIP local file header signature */
    unsigned long sig = 0x04034b50;
    
    while (sig == 0x04034b50 && fread(&sig, sizeof(sig), 1, f)) {
        unsigned char extra[6];
        
        /* Extract filename length and extra field length */
        int name_len = ((unsigned char)fgetc(f) << 8 | (unsigned char)fgetc(f));
        int extra_len = ((unsigned char)fgetc(f) << 8 | (unsigned char)fgetc(f));
        int comment_len = ((unsigned char)fgetc(f) << 8 | (unsigned char)fgetc(f));
        
        /* Read filename */
        char name[256];
        if (name_len < 256) {
            fread(name, 1, name_len, f);
            name[name_len] = '\0';
            
            /* Create destination path */
            char full_path[MAX_PATH + MAX_PATH];
            snprintf(full_path, sizeof(full_path), "%s/%s", dst, name);
            
            /* Skip to data offset */
            fseek(f, extra_len + comment_len, SEEK_CUR);
        }
    }
    
    fclose(f);
    return 0;
}

/* ============ METADATA PARSING ============ */

static int sbomx_parse_library_metadata(LibraryInfo *lib, const char *file_path) {
    if (!lib || !file_path) return -1;
    
    /* Try to extract version from filename */
    char name[256];
    strncpy(name, file_path, sizeof(name) - 1);
    
    /* Remove path prefix */
    const char *last_slash = strrchr(name, '/');
    if (last_slash) {
        strncpy(name, last_slash + 1, sizeof(name) - 1);
    }
    
    /* Extract version components */
    size_t nlen = strlen(name);
    while (nlen > 0 && (isdigit((unsigned char)name[nlen-1]) || 
                       name[nlen-1] == '.' || name[nlen-1] == '_')) {
        name[--nlen] = '\0';
    }
    
    /* Copy version */
    strncpy(lib->version, name, sizeof(lib->version) - 1);
    
    /* Try to identify platform from filename patterns */
    if (strstr(file_path, "arm64") || strstr(file_path, "aarch64")) {
        strcpy(lib->arch, "arm64");
    } else if (strstr(file_path, "x86_64") || strstr(file_path, "amd64")) {
        strcpy(lib->arch, "x86_64");
    } else if (strstr(file_path, "i386") || strstr(file_path, "ia32")) {
        strcpy(lib->arch, "i386");
    } else {
        strcpy(lib->arch, "generic");
    }
    
    /* Try to identify platform from path */
    if (strstr(file_path, "android") || strstr(file_path, "apk")) {
        strcpy(lib->platform, "android");
    } else if (strstr(file_path, "ios") || strstr(file_path, "iphoneos")) {
        strcpy(lib->platform, "ios");
    } else if (strstr(file_path, "darwin")) {
        strcpy(lib->platform, "macos");
    } else {
        strcpy(lib->platform, "generic");
    }
    
    /* Try to extract license from filename */
    const char *license_patterns[] = {
        ".lic", ".license", "_lic", "_license",
        "MIT", "Apache", "BSD", "GPL", "LGPL", "MPL"
    };
    
    for (size_t i = 0; i < sizeof(license_patterns) / sizeof(license_patterns[0]); i++) {
        if (strstr(file_path, license_patterns[i])) {
            char lic_str[64];
            strncpy(lic_str, license_patterns[i], sizeof(lic_str) - 1);
            
            /* Convert to proper format */
            for (size_t j = 0; j < strlen(lic_str); j++) {
                lic_str[j] = toupper((unsigned char)lic_str[j]);
            }
            
            strncpy(lib->license, lic_str, sizeof(lib->license) - 1);
            break;
        }
    }
    
    return 0;
}

/* ============ VULNERABILITY MATCHING ============ */

/* Known vulnerability database (embedded for demo) */
static const Vulnerability known_vulns[] = {
    /* CVE-2023-12345: Example Android NDK vulnerability */
    {
        .name = "libandroid_runtime",
        .version = "1.0.0",
        .cve_count = 1,
        .cvss_score = 7.5,
        .severity = "HIGH",
        .description = "Stack buffer overflow in Android runtime library",
        .advisory_url = "https://android.googlesource.com/platform/libcore/+/refs/tags/android-14.0.0_r26"
    },
    
    /* CVE-2023-12346: Example OpenSSL vulnerability */
    {
        .name = "libssl",
        .version = "3.0.8",
        .cve_count = 1,
        .cvss_score = 8.1,
        .severity = "HIGH",
        .description = "TLS renegotiation DoS in OpenSSL implementation",
        .advisory_url = "https://www.openssl.org/news/secadv/2