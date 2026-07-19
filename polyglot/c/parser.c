#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_PATH 4096
#define MAX_COMPONENTS 1024
#define MAX_FILES 8192
#define MAX_LINE 4096
#define SDK_KNOWN_COUNT 50

/* Component structure for SBOM */
typedef struct {
    char name[256];
    char version[64];
    char file_path[MAX_PATH];
    uint32_t arch;
    int is_sdk;
} Component;

/* SDK database entry */
typedef struct {
    const char *bundle_id;
    const char *sdk_name;
    const char *min_version;
    const char *max_version;
    int priority;
} KnownSDK;

/* CycloneDX BOM structure */
typedef struct {
    char bom_ref[256];
    char spec_url[1024];
    char version[32];
    time_t timestamp;
    Component components[MAX_COMPONENTS];
    int component_count;
} BOM;

/* Known SDKs database */
static KnownSDK known_sdks[] = {
    {"com.apple.CoreFoundation", "CoreFoundation", "1.0", NULL, 1},
    {"com.apple.Foundation", "Foundation", "2.0", NULL, 1},
    {"com.apple.UIKit", "UIKit", "3.0", NULL, 1},
    {"com.apple.AppKit", "AppKit", "4.0", NULL, 1},
    {"com.google.android.gms", "Google Play Services", "12.0", NULL, 2},
    {"com.google.firebase", "Firebase SDK", "9.0", NULL, 2},
    {NULL, NULL, NULL, NULL, 0}
};

/* Parse Mach-O header to extract info */
static int parse_mach_o(const char *path, Component *comp) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    
    uint32_t magic;
    fread(&magic, 4, 1, fp);
    fclose(fp);
    
    comp->arch = (magic == 0xfeedface) ? 0x0008 : 0x0009; /* ARM vs x86 */
    strncpy(comp->name, "Mach-O Binary", sizeof(comp->name));
    strncpy(comp->version, "1.0", sizeof(comp->version));
    strncpy(comp->file_path, path, MAX_PATH);
    
    return 0;
}

/* Parse ELF header to extract info */
static int parse_elf(const char *path, Component *comp) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    
    unsigned char e_ident[16];
    fread(e_ident, 1, 16, fp);
    fclose(fp);
    
    comp->arch = (e_ident[4] == 0x3E) ? 0x0008 : 0x0009; /* ARM vs x86 */
    strncpy(comp->name, "ELF Binary", sizeof(comp->name));
    strncpy(comp->version, "1.0", sizeof(comp->version));
    strncpy(comp->file_path, path, MAX_PATH);
    
    return 0;
}

/* Parse JSON plist for bundle identifier */
static int parse_plist(const char *path, Component *comp) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    char line[MAX_LINE];
    while (fgets(line, MAX_LINE, fp)) {
        if (strstr(line, "<key>CFBundleIdentifier</key>") ||
            strstr(line, "<string>")) {
            char *ptr = strchr(line, '<');
            if (!ptr) continue;
            
            /* Extract string value */
            while (*ptr && !isalnum(*ptr)) ptr++;
            if (!*ptr) continue;
            
            char val[256];
            int i = 0;
            while (*ptr && *ptr != '<' && i < 255) {
                val[i++] = *ptr++;
            }
            val[i] = '\0';
            
            if (strlen(val) > 0) {
                strncpy(comp->name, "Bundle", sizeof(comp->name));
                strncpy(comp->version, "1.0", sizeof(comp->version));
                strncpy(comp->file_path, path, MAX_PATH);
                return 0;
            }
        }
    }
    
    fclose(fp);
    return -1;
}

/* Parse Android manifest for package name */
static int parse_android_manifest(const char *path, Component *comp) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    char line[MAX_LINE];
    while (fgets(line, MAX_LINE, fp)) {
        if (strstr(line, "<package") && strstr(line, "name=")) {
            char *ptr = strchr(line, 'n');
            if (!ptr) continue;
            
            ptr += 6; /* skip "name=\"" */
            while (*ptr == '"') ptr++;
            
            char val[256];
            int i = 0;
            while (*ptr && *ptr != '"' && i < 255) {
                val[i++] = *ptr++;
            }
            val[i] = '\0';
            
            if (strlen(val) > 0) {
                strncpy(comp->name, "Android App", sizeof(comp->name));
                strncpy(comp->version, "1.0", sizeof(comp->version));
                strncpy(comp->file_path, path, MAX_PATH);
                return 0;
            }
        }
    }
    
    fclose(fp);
    return -1;
}

/* Check if file is a known SDK */
static int check_known_sdk(const char *path) {
    for (int i = 0; known_sdks[i].bundle_id != NULL; i++) {
        if (strstr(path, known_sdks[i].bundle_id)) {
            return 1;
        }
    }
    return 0;
}

/* Parse a single file and extract component info */
static int parse_file(const char *path, Component *comp) {
    comp->file_path[0] = '\0';
    
    /* Check file extension for quick hints */
    const char *ext = strrchr(path, '.');
    if (!ext) return -1;
    
    /* Try different parsers based on extension and content */
    if (strstr(ext, ".plist") || strstr(ext, "Info")) {
        parse_plist(path, comp);
        return 0;
    }
    
    if (strstr(ext, ".xml") && strstr(path, "AndroidManifest")) {
        parse_android_manifest(path, comp);
        return 0;
    }
    
    /* Check for Mach-O or ELF */
    if (parse_mach_o(path, comp) == 0 || parse_elf(path, comp) == 0) {
        return 0;
    }
    
    /* Generic binary file */
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    
    uint32_t magic;
    fread(&magic, 4, 1, fp);
    fclose(fp);
    
    comp->arch = (magic == 0xfeedface || magic == 0x7f454c46) ? 0x0008 : 0x0009;
    strncpy(comp->name, "Binary", sizeof(comp->name));
    strncpy(comp->version, "1.0", sizeof(comp->version));
    
    return 0;
}

/* Parse directory recursively */
static int parse_directory(const char *dir_path, BOM *bom) {
    DIR *dp = opendir(dir_path);
    if (!dp) return -1;
    
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        
        char full_path[MAX_PATH];
        snprintf(full_path, MAX_PATH, "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                parse_directory(full_path, bom);
            } else if (S_ISREG(st.st_mode)) {
                Component comp = {0};
                if (parse_file(full_path, &comp) == 0) {
                    /* Check if this is a known SDK */
                    comp.is_sdk = check_known_sdk(full_path);
                    
                    /* Avoid duplicates */
                    int duplicate = 0;
                    for (int i = 0; i < bom->component_count && !duplicate; i++) {
                        if (strcmp(bom->components[i].file_path, full_path) == 0) {
                            duplicate = 1;
                        }
                    }
                    
                    if (!duplicate && bom->component_count < MAX_COMPONENTS) {
                        strcpy(bom->components[bom->component_count].name, comp.name);
                        strncpy(bom->components[bom->component_count].version, 
                                comp.version, sizeof(comp.version));
                        strncpy(bom->components[bom->component_count].file_path,
                                full_path, MAX_PATH);
                        bom->components[bom->component_count].arch = comp.arch;
                        bom->components[bom->component_count].is_sdk = comp.is_sdk;
                        bom->component_count++;
                    }
                }
            }
        }
    }
    
    closedir(dp);
    return 0;
}

/* Generate CycloneDX BOM JSON */
static void generate_cyclonedx(const BOM *bom, const char *output_path) {
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open output file\n");
        return;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    /* BOM header */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"$schema\": \"https://cyclonedx.org/schema/bom-1.4.json\",\n");
    fprintf(fp, "  \"bomFormat\": \"CycloneDX\",\n");
    fprintf(fp, "  \"specVersion\": \"1.4\",\n");
    fprintf(fp, "  \"version\": 1,\n");
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"timestamp\": \"%s\",\n", timestamp);
    fprintf(fp, "    \"tools\": {\n");
    fprintf(fp, "      \"component\": {\n");
    fprintf(fp, "        \"name\": \"sbomx\",\n");
    fprintf(fp, "        \"version\": \"1.0.0\"\n");
    fprintf(fp, "      }\n");
    fprintf(fp, "    },\n");
    fprintf(fp, "    \"component\": {\n");
    fprintf(fp, "      \"name\": \"sbomx-app\",\n");
    fprintf(fp, "      \"version\": \"1.0.0\"\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "  },\n");
    
    /* Components array */
    fprintf(fp, "  \"components\": [\n");
    
    for (int i = 0; i < bom->component_count; i++) {
        Component *c = &bom->components[i];
        
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"type\": \"%s\",\n", c->is_sdk ? "library" : "application");
        fprintf(fp, "      \"name\": \"%s\",\n", c->name);
        fprintf(fp, "      \"version\": \"%s\",\n", c->version);
        fprintf(fp, "      \"description\": \"Extracted from mobile app bundle\",\n");
        
        /* Add file hash placeholder */
        fprintf(fp, "      \"hashes\": {\n");
        fprintf(fp, "        \"SHA-256\": \"<TO_BE_CALCULATED>\"\n");
        fprintf(fp, "      },\n");
        
        /* Add file path reference */
        fprintf(fp, "      \"file\": \"%s\",\n", c->file_path);
        
        /* Add license placeholder */
        fprintf(fp, "      \"licenses\": [\n");
        fprintf(fp, "        {\n");
        fprintf(fp, "          \"name\": \"<TO_BE_DETERMINED>\",\n");
        fprintf(fp, "          \"url\": \"https://cyclonedx.org/license/unknown\"\n");
        fprintf(fp, "        }\n");
        fprintf(fp, "      ],\n");
        
        /* Add external references */
        fprintf(fp, "      \"externalReferences\": [\n");
        fprintf(fp, "        {\n");
        fprintf(fp, "          \"type\": \"distribution\",\n");
        fprintf(fp, "          \"url\": \"https://github.com/sbomx/parser\"\n");
        fprintf(fp, "        }\n");
        fprintf(fp, "      ]\n");
        
        fprintf(fp, "    }%s\n", (i < bom->component_count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"dependencies\": [\n");
    fprintf(fp, "    {\n");
    fprintf(fp, "      \"ref\": \"sbomx-app\",\n");
    fprintf(fp, "      \"dependsOn\": []\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
}

/* Calculate SHA-256 hash of a file */
static void calculate_sha256(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    
    unsigned char buffer[4096];
    int bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        /* Hash update would go here */
        /* For now, we'll use a placeholder */
    }
    
    fclose(fp);
}

/* Main entry point with demo */
int main(int argc, char *argv[]) {
    BOM bom = {0};
    const char *input_dir = ".";
    const char *output_file = "sbom.json";
    
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_dir = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--demo") == 0) {
            /* Demo mode with sample data */
            printf("=== SBOMX Parser Demo ===\n\n");
            
            /* Simulate parsing a demo directory structure */
            Component demo_components[] = {
                {"com.apple.CoreFoundation", "1.0", "/usr/lib/libCoreFoundation.dylib", 0x0008, 1},
                {"com.google.android.gms", "12.0", "/data/app/armeabi-v7a/libgms.so", 0x0009, 1},
                {"Mach-O Binary", "1.0", "/app/Frameworks/UIKit.framework/UIKit", 0x0008, 0}
            };
            
            bom.component_count = 3;
            for (int i = 0; i < 3; i++) {
                strcpy(bom.components[i].name, demo_components[i].name);
                strncpy(bom.components[i].version, demo_components[i].version, sizeof(demo_components[i].version));
                strncpy(bom.components[i].file_path, demo_components[i].file_path, MAX_PATH);
                bom.components[i].arch = demo_components[i].arch;
                bom.components[i].is_sdk = demo_components[i].