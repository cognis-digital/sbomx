require 'zip'
require 'json'
require 'fileutils'
require 'tempfile'
require 'open3'

module Sbomx
  module Core
    # Constants for common paths and file types
    NATIVE_LIBS = ['lib/arm64-v8a/', 'lib/armeabi-v7a/', 
                   'lib/x86_64/', 'lib/x86/', 'lib/mips64/',
                   'lib/mips/'].freeze
    
    JAR_EXTENSIONS = ['.jar', '.aar'].freeze
    NDK_LIBS = ['.so', '.dylib'].freeze

    # CycloneDX spec version (v1.5 is widely supported)
    CYCLONEDX_SPEC_VERSION = '1.5'.freeze
    CYCLONEDX_BOM_FORMAT = 'CycloneDX'.freeze

    class << self
      # Main entry point - unpacks APK/IPA and generates SBOM
      def generate_bom(apk_path, output_dir: nil)
        return {} unless apk_path && File.exist?(apk_path)
        
        output_dir ||= Tempfile.new('sbomx').path + '/extract'
        FileUtils.mkdir_p(output_dir)
        
        begin
          # Unpack the APK/IPA
          extract_archive(apk_path, output_dir)
          
          # Find and parse all components
          component_list = []
          
          # 1. Parse JAR files for dependencies
          jar_deps = find_and_parse_jars(output_dir)
          component_list.concat(jar_deps)
          
          # 2. Detect native libraries (for version tracking)
          native_libs = find_native_libraries(output_dir)
          native_libs.each do |lib|
            component_list << {
              name: "native-lib-#{File.basename(lib, '.*')}",
              type: 'library',
              group: 'android-native',
              version: File.basename(lib),
              purl: "pkg:native-#{File.basename(lib, '.*')}"
            }
          end
          
          # 3. Detect bundled SDKs/frameworks
          sdk_deps = find_sdk_dependencies(output_dir)
          component_list.concat(sdk_deps)
          
          # 4. Scan for known vulnerabilities
          vuln_report = match_vulnerabilities(component_list)
          
          # Build the CycloneDX BOM structure
          build_cyclonedx_bom(component_list, vuln_report)
        ensure
          FileUtils.rm_rf(output_dir) if File.directory?(output_dir)
        end
      end

      private

      def extract_archive(apk_path, output_dir)
        # APKs are ZIP files; IPAs have nested structure
        Zip::File.open(apk_path) do |zip|
          zip.each_entry do |entry|
            next if entry.directory?
            
            target = File.join(output_dir, entry.name)
            FileUtils.mkdir_p(File.dirname(target)) unless File.exist?(target)
            entry.get_contents.tap { |c| c.write_to_file(target) }
          end
        end
        
        # Also extract the main dex for class analysis if needed
        main_dex_path = File.join(output_dir, 'classes.dex')
        return unless File.exist?(main_dex_path)
        
        # Basic dex header parsing to get package name hint
        parse_dex_header(main_dex_path)
      end

      def find_and_parse_jars(directory)
        jar_files = []
        
        NATIVE_LIBS.each do |lib_dir|
          Dir.glob(File.join(directory, lib_dir, '**', JAR_EXTENSIONS)).each do |jar|
            jar_files << jar unless File.directory?(jar)
          end
        end
        
        # Also check root and common SDK locations
        ['classes.dex', 'classes.jar'].each do |file|
          path = File.join(directory, file)
          jar_files << path if File.exist?(path)
        end
        
        jar_files.map do |jar_path|
          parse_jar_dependencies(jar_path)
        end.compact
      end

      def parse_jar_dependencies(jar_path)
        return [] unless File.file?(jar_path) && JAR_EXTENSIONS.include??.?(File.extname(jar_path))
        
        # Extract MANIFEST.MF for dependencies
        manifest = extract_manifest(jar_path)
        return [] if !manifest || manifest.empty?
        
        # Parse Manifest attributes
        deps = {}
        
        manifest.each_line do |line|
          if line.match?(/^(Implementation-)?Class-Path:/i)
            next unless line.match?(/:\s*(.+)/)
            
            parts = line.split(':').map(&:strip).reject(&:empty?)
            dep_name, dep_path = parts[0], parts[1]
            
            # Extract version from filename if available
            version = File.basename(jar_path).match(/-([0-9.]+)\.?/)&.captures&.first || 'unknown'
            
            deps << {
              name: dep_name,
              group: 'android-sdk',
              version: version,
              type: 'library',
              purl: "pkg:jar/#{dep_name}-#{version}"
            }
          end
        end
        
        deps.uniq
      end

      def extract_manifest(jar_path)
        manifest_content = nil
        Zip::File.open(jar_path) do |zip|
          zip.each_entry do |entry|
            if entry.name == 'META-INF/MANIFEST.MF' || 
               (entry.name.start_with?('META-INF/') && entry.name.end_with?('.MF'))
              manifest_content = entry.get_contents.to_s
              break
            end
          end
        end
        
        manifest_content
      end

      def find_native_libraries(directory)
        NATIVE_LIBS.each do |lib_dir|
          Dir.glob(File.join(directory, lib_dir, '**', NDK_LIBS)).each do |lib|
            next if File.directory?(lib)
            
            # Extract architecture and version hints from filename
            arch = extract_architecture_from_path(lib)
            version = File.basename(lib).match(/-([0-9.]+)\.?/)&.captures&.first || 'unknown'
            
            { path: lib, arch: arch, version: version }
          end
        end.flatten.uniq
      end

      def extract_architecture_from_path(path)
        # Parse common architecture patterns from paths
        patterns = [
          /arm64-v8a/i,   # ARM 64-bit (modern Android)
          /armeabi-v7a/i, # ARM 32-bit
          /x86_64/i,      # x86-64
          /x86/i,         # x86
          /mips64/i,      # MIPS 64-bit
          /mips/i,        # MIPS 32-bit
          /universal/i    # Universal (all architectures)
        ]
        
        patterns.each do |pattern|
          return pattern.to_s if path.match?(pattern)
        end
        
        'unknown'
      end

      def find_sdk_dependencies(directory)
        sdk_paths = []
        
        # Common SDK locations in extracted APKs
        common_locations = [
          'classes.dex',
          'classes.jar',
          'lib/classes.jar',
          'android.jar',
          'framework.jar'
        ]
        
        common_locations.each do |location|
          path = File.join(directory, location)
          sdk_paths << path if File.exist?(path)
        end
        
        # Parse Android SDK dependencies from classes.dex
        sdk_deps = parse_android_sdk(path: sdk_paths.first)
        
        sdk_deps || []
      end

      def parse_android_sdk(path: nil)
        return [] unless path && File.file?(path)
        
        # Extract package name hint from dex header
        begin
          result = Open3.capture3("strings -n 1 #{path}")
          output = result[0].to_s.strip
          
          # Look for common Android package patterns
          if output.match?(/com\.android\./) || 
             output.match?(/android\.app\./) ||
             output.match?(/android\.content\./)
            
            # Found Android SDK - extract version info
            {
              name: 'android-sdk',
              type: 'framework',
              group: 'android',
              version: 'latest',
              purl: 'pkg:maven/android.sdk@latest'
            }
          else
            []
          end
        rescue StandardError
          []
        end
      end

      def match_vulnerabilities(components)
        # Stub implementation - in production this would query real databases
        
        vuln_db = {
          'com.android.support:appcompat-v7' => ['1.0.0', '25.3.1'],
          'androidx.core:core-ktx' => ['1.0.0', '1.9.0'],
          'org.jetbrains.kotlin:kotlin-stdlib' => ['1.0.0', '1.8.20']
        }
        
        # Check each component against known vulnerabilities
        components.map do |comp|
          next unless comp[:name] && vuln_db.key?(comp[:name])
          
          versions = vuln_db[comp[:name]]
          current_version = comp[:version] || 'unknown'
          
          if versions.include?(current_version)
            {
              component: comp,
              vulnerability: {
                id: "CVE-2023-XXXXX",
                severity: 'Medium',
                cvss_score: 5.4,
                affected_versions: versions,
                fixed_in: versions.last
              }
            }
          else
            nil
          end
        end.compact
      end

      def build_cyclonedx_bom(components, vulnerabilities)
        # Build the CycloneDX BOM structure
        bom = {
          'bomFormat' => CYCLONEDX_BOM_FORMAT,
          'specVersion' => CYCLONEDX_SPEC_VERSION,
          'metadata' => {
            'component' => {
              'name' => 'sbomx-analyzed-app',
              'type' => 'application',
              'version' => '1.0.0'
            },
            'timestamp' => Time.now.iso8601,
            'tools' => [
              {
                'name' => 'sbomx-core',
                'version' => '1.0.0'
              }
            ]
          },
          'components' => components.map do |comp|
            # Ensure all required fields are present
            safe_comp = comp.dup
            safe_comp[:type] ||= 'library'
            safe_comp[:group] ||= ''
            
            {
              'name' => safe_comp[:name],
              'type' => safe_comp[:type],
              'version' => safe_comp[:version] || 'unknown',
              'purl' => safe_comp[:purl] || "pkg:generic/#{safe_comp[:name]}"
            }
          end,
          'services' => [],
          'dependencies' => build_dependencies(components),
          'vulnerabilities' => vulnerabilities.map do |vuln|
            {
              'component' => vuln[:component],
              'advisories' => [
                {
                  'id' => vuln[:vulnerability][:id],
                  'severity' => vuln[:vulnerability][:severity],
                  'cvssScore' => vuln[:vulnerability][:cvss_score]
                }
              ]
            }
          end
        }
        
        # Remove empty arrays for cleaner output
        bom.reject { |k, v| v.nil? || (Array(v).empty?) }
      end

      def build_dependencies(components)
        # Build a simple dependency graph
        deps = {}
        
        components.each do |comp|
          name = comp[:name]
          next unless name && !deps.key?(name)
          
          deps[name] = []
          
          # Add self-dependency (component depends on itself for transitive resolution)
          deps[name] << { ref: name, type: 'requires' }
        end
        
        deps
      end

      def parse_dex_header(dex_path)
        return unless File.file?(dex_path)
        
        # Read first 12 bytes of dex header
        begin
          header = File.binread(dex_path, 12)
          
          if header[0] == 0x7D && header[1] == 0x00 && 
             header[2] == 0x00 && header[3] == 0x3C
            # Valid dex file - extract magic number and version
            { valid: true, magic: 'dex', version: "#{header[4].chr}#{header[5].chr}" }
          else
            { valid: false }
          end
        rescue StandardError
          { valid: false }
        end
      end
    end
  end
end

# === Runnable Demo / Entry Point ===

if __FILE__ == $0 || ARGV.include?('demo')
  puts "=== Sbomx Core Demo ==="
  
  # Create a sample APK structure for testing
  demo_dir = File.join(Dir.tmpdir, 'sbomx_demo_') + Time.now.to_i.to_s
  
  begin
    FileUtils.mkdir_p(demo_dir)
    
    # Create a fake APK with some content
    apk_path = File.join(demo_dir, 'test.apk')
    
    Zip::File.open(apk_path, Zip::File::CREATE) do |zip|
      # Add META-INF/MANIFEST.MF
      manifest = <<MANIFEST
Manifest-Version: 1.0
Implementation-Title: Test App
Implementation-Version: 1.0.0
Class-Path: . lib/classes.jar
MANIFEST
      
      zip.add_entry('META-INF/MANIFEST.MF', manifest)
      
      # Add a fake classes.dex with Android SDK content
      dex_content = "\x7D\x00\x00\x3C\x01\x00" + "com.example.testapp".bytes.pack('C*')
      zip.add_entry('classes.dex', dex_content)
      
      # Add some native libraries
      lib_dir = File.join(demo_dir, 'lib', 'arm64-v8a')
      FileUtils.mkdir_p(lib_dir)
      
      so_file = File.join(lib_dir, 'libfoo.so.1.2.3')
      File.write(so_file, "\x7F\x45\x4C\x02" + "foo".bytes.pack('C*')) # ELF header
      
      zip.add_entry('lib/arm64-v8a/libfoo.so', so_file)
    end
    
    puts "Created demo APK: #{apk_path}"
    
    # Run the core functionality
    result = Sbomx::Core.generate_bom(apk_path, output_dir: demo_dir)
    
    puts "\n=== Generated BOM ==="
    puts JSON.pretty_generate(result)
    
    puts "\n=== Summary ==="
    puts "Components found: #{result[:components]&.length || 0}"
    puts "Vulnerabilities found: #{result[:vulnerabilities]&.length || 0}"
    
  ensure
    # Cleanup demo files
    FileUtils.rm_rf(demo_dir) if File.directory?(demo_dir)
  end
end

# === Module Export for External Use ===

require_relative 'core' if defined?(Sbomx::Core) && !defined?(Sbomx::Core::VERSION)