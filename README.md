# Maven-Fortify Vulnerability Patcher

A CLI application that integrates Fortify vulnerability reports with Maven dependency trees to identify and suggest patches for vulnerable packages by updating higher-level dependencies.

## Overview

This tool helps developers quickly identify how to patch vulnerabilities in their Maven projects by:

1. Analyzing Fortify vulnerability reports
2. Mapping vulnerabilities to Maven dependency trees  
3. Finding the optimal level in the dependency hierarchy to apply updates
4. Suggesting specific version updates that resolve vulnerabilities

## Features

- **Intelligent Patch Resolution**: Finds the highest-level dependency update that resolves vulnerabilities
- **Multiple Input Formats**: Supports Fortify XML reports and Maven JSON dependency trees
- **Comprehensive Analysis**: Traces complete dependency paths from root to vulnerable packages
- **Multiple Output Formats**: Text, JSON, and CSV output formats
- **Safe Operation**: Backup and restore POM files during analysis
- **Maven Repository Integration**: Queries Maven Central for latest versions
- **Flexible Configuration**: Options for pre-releases, dry-run mode, and logging levels

## Installation

### From Source

```bash
git clone <repository-url>
cd maven-fortify-patcher
pip install -e .
```

### Using pip

```bash
pip install maven-fortify-patcher
```

## Prerequisites

- Python 3.8 or higher
- Maven 3.6+ installed and available in PATH
- Java 8+ (required by Maven)
- Internet connection (for Maven repository queries)

## Usage

### Basic Usage

```bash
maven-fortify-patcher --fortify-report report.xml --dependency-tree deps.json
```

### Generate Dependency Tree

First, generate the Maven dependency tree in JSON format:

```bash
mvn dependency:tree -DoutputType=json -DoutputFile=dependency-tree.json
```

### Generate Fortify Report

Export vulnerability data from Fortify as XML:

```bash
# Using Fortify ReportGenerator
ReportGenerator -format XML -source project.fpr -f vulnerability-report.xml

# Or from Fortify SSC
# Export scan results as XML from the web interface
```

### Command Line Options

```bash
maven-fortify-patcher [OPTIONS]

Required Arguments:
  --fortify-report PATH     Path to Fortify vulnerability report XML
  --dependency-tree PATH    Path to Maven dependency tree JSON

Optional Arguments:
  --pom-file PATH          Path to project POM file (default: pom.xml)
  --include-prereleases    Include pre-release versions in updates
  --dry-run               Analyze without making changes
  --output-format FORMAT  Output format: text|json|csv (default: text)
  --log-level LEVEL       Logging level: DEBUG|INFO|WARN|ERROR
  --help                  Show help message
```

### Examples

#### Basic Analysis
```bash
maven-fortify-patcher \
  --fortify-report fortify-scan.xml \
  --dependency-tree dependency-tree.json
```

#### Dry Run with JSON Output
```bash
maven-fortify-patcher \
  --fortify-report fortify-scan.xml \
  --dependency-tree dependency-tree.json \
  --dry-run \
  --output-format json > analysis-results.json
```

#### Include Pre-release Versions
```bash
maven-fortify-patcher \
  --fortify-report fortify-scan.xml \
  --dependency-tree dependency-tree.json \
  --include-prereleases \
  --log-level DEBUG
```

#### Generate CSV Report
```bash
maven-fortify-patcher \
  --fortify-report fortify-scan.xml \
  --dependency-tree dependency-tree.json \
  --output-format csv > vulnerability-analysis.csv
```

## Sample Output

### Text Format
```
MAVEN-FORTIFY VULNERABILITY ANALYSIS REPORT
==================================================

Analysis Date: 2025-09-10 19:03:00

SUMMARY:
- Total vulnerabilities analyzed: 3
- Patchable by dependency updates: 2
- No patches available: 1

DETAILED FINDINGS:

1. Vulnerability: org.apache.commons:commons-text:1.8
   Severity: HIGH
   Path: my-project:1.0.0 → spring-boot-starter-web:2.5.0 → commons-text:1.8

   SOLUTION: Update spring-boot-starter-web:2.5.0
   to version 2.7.2
   This will automatically update transitive dependencies.

2. Vulnerability: com.fasterxml.jackson.core:jackson-databind:2.12.1
   Severity: CRITICAL
   Path: my-project:1.0.0 → jackson-databind:2.12.1

   SOLUTION: Update com.fasterxml.jackson.core:jackson-databind:2.12.1
   to version 2.15.2
   This is a direct dependency update.
```

### JSON Format
```json
{
  "analysis_date": "2025-09-10T19:03:00",
  "summary": {
    "total_vulnerabilities": 3,
    "patchable": 2,
    "not_patchable": 1
  },
  "findings": [
    {
      "vulnerable_package": {
        "group_id": "org.apache.commons",
        "artifact_id": "commons-text",
        "version": "1.8",
        "cve_ids": ["CVE-2023-12345"],
        "severity": "HIGH"
      },
      "dependency_path": [
        "my-project:1.0.0",
        "org.springframework.boot:spring-boot-starter-web:2.5.0",
        "org.apache.commons:commons-text:1.8"
      ],
      "is_patchable": true,
      "suggested_update": {
        "dependency": "org.springframework.boot:spring-boot-starter-web:2.5.0",
        "new_version": "2.7.2",
        "update_level": 1
      }
    }
  ]
}
```

## Algorithm

The tool uses the following algorithm to resolve vulnerabilities:

1. **Parse Inputs**: Load and validate Fortify XML report and Maven JSON dependency tree
2. **Build Dependency Graph**: Create internal representation with parent-child relationships
3. **Map Vulnerabilities**: Find vulnerable packages in the dependency tree
4. **Trace Dependency Paths**: Identify complete paths from project root to vulnerable packages
5. **Test Updates**: For each vulnerability:
   - Start from the highest level dependency (closest to root)
   - Query Maven Central for latest version
   - Simulate the update to check if it resolves the vulnerability
   - Move down the dependency path if the update doesn't resolve the issue
6. **Generate Report**: Provide actionable recommendations

## Architecture

### Core Components

- **DependencyNode**: Represents nodes in the Maven dependency tree
- **VulnerablePackage**: Represents vulnerabilities from Fortify reports  
- **PatchSuggestion**: Represents suggested fixes for vulnerabilities
- **MavenRepository**: Handles queries to Maven repositories
- **DependencyTreeParser**: Parses Maven dependency tree JSON
- **FortifyReportParser**: Parses Fortify vulnerability XML reports
- **MavenProjectManager**: Manages Maven project operations
- **VulnerabilityPatcher**: Main orchestration class

### Data Flow

```
Fortify XML Report ──┐
                     ├──► VulnerabilityPatcher ──► PatchSuggestions ──► Report
Maven JSON Tree  ────┘
```

## Configuration

### Environment Variables

- `MAVEN_HOME`: Path to Maven installation (if not in PATH)
- `JAVA_HOME`: Path to Java installation

### Logging

The tool supports multiple logging levels:

- **DEBUG**: Detailed debugging information
- **INFO**: General progress information (default)  
- **WARN**: Warning messages
- **ERROR**: Error messages only

## Limitations

- **Fortify Report Format**: Currently supports XML format exports from Fortify
- **Maven Only**: Designed specifically for Maven projects
- **Network Dependency**: Requires internet connection to query Maven repositories
- **Version Comparison**: Uses simplified version comparison logic
- **POM Complexity**: May not handle complex POM configurations (profiles, properties, etc.)

## Troubleshooting

### Common Issues

1. **"Maven not found in PATH"**
   - Ensure Maven is installed and available in system PATH
   - Set MAVEN_HOME environment variable if needed

2. **"Failed to parse Fortify XML report"**
   - Verify the XML file is a valid Fortify export
   - Check that the file contains vulnerability data
   - Ensure proper XML format and encoding

3. **"No vulnerabilities found in dependency tree"**
   - Verify that vulnerable packages are actually dependencies of your project
   - Check that dependency tree JSON includes all scopes
   - Ensure versions match exactly between Fortify report and dependency tree

4. **"Network timeout querying Maven repository"**
   - Check internet connection
   - Verify corporate firewall settings
   - Configure Maven to use proxy if needed

### Debug Mode

Run with debug logging for detailed information:

```bash
maven-fortify-patcher \
  --fortify-report report.xml \
  --dependency-tree deps.json \
  --log-level DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

### Development Setup

```bash
git clone <repository-url>
cd maven-fortify-patcher
pip install -e ".[dev]"
pytest tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:

1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with:
   - Sample Fortify report (sanitized)
   - Sample dependency tree JSON
   - Error messages and logs
   - Environment information (OS, Python version, Maven version)

## Changelog

### v1.0.0
- Initial release
- Basic vulnerability analysis
- Maven repository integration
- Multiple output formats
- POM backup/restore functionality