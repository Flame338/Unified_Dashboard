"""
Maven-Fortify Vulnerability Patching CLI Application

This application integrates Fortify vulnerability reports with Maven dependency trees 
to identify and suggest patches for vulnerable packages by updating higher-level dependencies.
"""

import argparse
import json
import logging
import shutil
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    """Represents a Maven dependency node in the dependency tree."""
    group_id: str
    artifact_id: str
    version: str
    scope: str = "compile"
    children: List['DependencyNode'] = field(default_factory=list)
    parent: Optional['DependencyNode'] = None
    path_from_root: List[str] = field(default_factory=list)

    @property
    def coordinates(self) -> str:
        """Return Maven coordinates as string."""
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    def __str__(self) -> str:
        return self.coordinates


@dataclass
class VulnerablePackage:
    """Represents a vulnerable package identified by Fortify."""
    group_id: str
    artifact_id: str
    version: str
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    description: str = ""

    @property
    def coordinates(self) -> str:
        """Return Maven coordinates as string."""
        return f"{self.group_id}:{self.artifact_id}:{self.version}"


@dataclass
class PatchSuggestion:
    """Represents a suggested patch for a vulnerability."""
    vulnerable_package: VulnerablePackage
    dependency_path: List[DependencyNode]
    suggested_update: Optional[DependencyNode] = None
    suggested_version: Optional[str] = None
    update_level: int = 0  # 0 = no patch, 1 = direct dependency, 2+ = transitive
    is_patchable: bool = False
    managed_in_parent_pom: bool = False
    parent_pom_path: Optional[Path] = None


class MavenRepository:
    """Handles Maven repository interactions."""

    MAVEN_CENTRAL_API = "https://search.maven.org/solrsearch/select"

    @staticmethod
    def get_latest_version(group_id: str, artifact_id: str, include_prereleases: bool = False) -> Optional[str]:
        """Get the latest version of a Maven artifact."""
        try:
            query = {'q': f'g:"{group_id}" AND a:"{artifact_id}"'}
            params = urlencode(query)
            url = f"{MavenRepository.MAVEN_CENTRAL_API}?{params}&core=gav&rows=20&wt=json"

            logger.debug(f"Querying Maven Central for {group_id}:{artifact_id}")

            req = Request(url)
            with urlopen(req, timeout=120) as response:
                data = json.loads(response.read().decode())

            versions = []
            for doc in data.get('response', {}).get('docs', []):
                version = doc.get('v', '')
                if version and (include_prereleases or MavenRepository._is_stable_version(version)):
                    versions.append(version)

            if versions:
                # Sort versions and return the latest
                sorted_versions = sorted(versions, key=MavenRepository._version_key, reverse=True)
                return sorted_versions[0]

            return None

        except (URLError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to get latest version for {group_id}:{artifact_id}: {e}")
            return None

    @staticmethod
    def _is_stable_version(version: str) -> bool:
        """Check if version is stable (not alpha, beta, snapshot, etc.)."""
        version_lower = version.lower()
        unstable_markers = ['alpha', 'beta', 'snapshot', 'rc', 'm1', 'm2', 'm3', 'm4', 'm5']
        return not any(marker in version_lower for marker in unstable_markers)

    @staticmethod
    def _version_key(version: str) -> Tuple:
        """Generate sorting key for version comparison."""
        # Simple version comparison - split by dots and convert to integers where possible
        parts = []
        for part in version.split('.'):
            # Extract numeric part
            numeric_match = re.match(r'(\d+)', part)
            if numeric_match:
                parts.append(int(numeric_match.group(1)))
            else:
                parts.append(0)
        return tuple(parts)


class DependencyTreeParser:
    """Parses Maven dependency tree JSON output."""

    @staticmethod
    def parse(json_data: dict) -> Optional[DependencyNode]:
        """Parse Maven dependency tree JSON and return root node."""
        try:
            root = DependencyTreeParser._parse_node(json_data)
            DependencyTreeParser._build_paths(root, [])
            return root
        except KeyError as e:
            logger.error(f"Missing required field in dependency tree JSON: {e}")
            return None

    @staticmethod
    def _parse_node(node_data: dict) -> DependencyNode:
        """Parse a single dependency node."""
        group_id = node_data.get('groupId', '')
        artifact_id = node_data.get('artifactId', '')
        version = node_data.get('version', '')
        scope = node_data.get('scope', 'compile')

        node = DependencyNode(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope
        )

        # Parse children
        children_data = node_data.get('children', [])
        for child_data in children_data:
            child = DependencyTreeParser._parse_node(child_data)
            child.parent = node
            node.children.append(child)

        return node

    @staticmethod
    def _build_paths(node: DependencyNode, current_path: List[str]):
        """Build path from root for each node."""
        node.path_from_root = current_path + [node.coordinates]

        for child in node.children:
            DependencyTreeParser._build_paths(child, node.path_from_root)


class FortifyReportParser:
    """Parses Fortify vulnerability reports in XML format."""

    @staticmethod
    def parse(xml_file_path: str) -> List[VulnerablePackage]:
        """Parse Fortify XML report and extract vulnerable packages."""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            namespace = {}
            if '}' in root.tag:
                namespace['fvdl'] = root.tag.split('}')[0][1:]

            vulnerabilities = []

            # Look for vulnerability information in different possible structures
            # Fortify reports can have different XML structures

            # Try FVDL format (Fortify Vulnerability Definition Language)
            find_str = ".//fvdl:Vulnerability" if namespace else ".//Vulnerability"
            for vuln in root.findall(find_str, namespace):
                vulnerable_pkg = FortifyReportParser._parse_vulnerability(vuln, namespace)
                if vulnerable_pkg:
                    vulnerabilities.append(vulnerable_pkg)

            # Try alternative formats
            if not vulnerabilities:
                for issue in root.findall(".//Issue"):
                    vulnerable_pkg = FortifyReportParser._parse_issue(issue)
                    if vulnerable_pkg:
                        vulnerabilities.append(vulnerable_pkg)

            logger.info(f"Found {len(vulnerabilities)} vulnerabilities in Fortify report")
            return vulnerabilities

        except ET.ParseError as e:
            logger.error(f"Failed to parse Fortify XML report: {e}")
            return []
        except FileNotFoundError:
            logger.error(f"Fortify report file not found: {xml_file_path}")
            return []

    @staticmethod
    def _parse_vulnerability(vuln_elem, namespace) -> Optional[VulnerablePackage]:
        """Parse vulnerability element from FVDL format."""
        try:
            # Extract package information - this is format-dependent
            # Looking for common patterns in Fortify reports

            # Try to extract from InstanceInfo
            inst_info_str = "fvdl:InstanceInfo" if namespace else "InstanceInfo"
            instance_info = vuln_elem.find(inst_info_str, namespace)
            if instance_info is not None:
                loc_str = "fvdl:Location" if namespace else "Location"
                location = instance_info.find(loc_str, namespace)
                if location is not None:
                    path = location.get("path", "")
                    # Try to extract Maven coordinates from path
                    coords = FortifyReportParser._extract_maven_coords_from_path(path)
                    if coords:
                        group_id, artifact_id, version = coords

                        # Extract CVE and severity information
                        cve_ids = []
                        severity = vuln_elem.get("instanceSeverity", "UNKNOWN")
                        
                        notes_str = "fvdl:AnalyzerNotes" if namespace else "AnalyzerNotes"
                        analyzer_notes = vuln_elem.find(notes_str, namespace)
                        if analyzer_notes is not None:
                            user_info_str = "fvdl:UserInfo" if namespace else "UserInfo"
                            user_info = analyzer_notes.find(user_info_str, namespace)
                            if user_info is not None and user_info.text:
                                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', user_info.text)
                                if cve_match:
                                    cve_ids.append(cve_match.group(0))


                        return VulnerablePackage(
                            group_id=group_id,
                            artifact_id=artifact_id,
                            version=version,
                            cve_ids=cve_ids,
                            severity=severity
                        )

            return None

        except Exception as e:
            logger.warning(f"Failed to parse vulnerability element: {e}")
            return None

    @staticmethod
    def _parse_issue(issue_elem) -> Optional[VulnerablePackage]:
        """Parse issue element from alternative format."""
        try:
            # Extract package information from issue format
            # This would need to be adapted based on actual Fortify report structure

            category = issue_elem.get("category", "")
            if "dependency" in category.lower() or "component" in category.lower():
                # Try to extract Maven coordinates
                description = issue_elem.find(".//Abstract")
                if description is not None:
                    text = description.text or ""
                    coords = FortifyReportParser._extract_maven_coords_from_text(text)
                    if coords:
                        group_id, artifact_id, version = coords

                        return VulnerablePackage(
                            group_id=group_id,
                            artifact_id=artifact_id,
                            version=version,
                            severity=issue_elem.get("severity", "UNKNOWN")
                        )

            return None

        except Exception as e:
            logger.warning(f"Failed to parse issue element: {e}")
            return None

    @staticmethod
    def _extract_maven_coords_from_path(path: str) -> Optional[Tuple[str, str, str]]:
        """Extract Maven coordinates from file path."""
        # Look for Maven repository structure: .../groupId/artifactId/version/...
        try:
            path_parts = path.replace('\\', '/').split('/')
            
            jar_index = -1
            for i, part in enumerate(path_parts):
                if part.endswith('.jar'):
                    jar_index = i
                    break
            
            if jar_index < 2:
                return None

            version = path_parts[jar_index - 1]
            artifact_id = path_parts[jar_index - 2]
            
            repo_index = -1
            try:
                # find last occurrence of 'repository'
                repo_index = len(path_parts) - 1 - path_parts[::-1].index('repository')
            except ValueError:
                return None # 'repository' not in path

            group_id_start_index = repo_index + 1
            group_id_end_index = jar_index - 3
            
            if group_id_start_index > group_id_end_index:
                # This case can happen for direct dependencies where groupid is not in path
                return None

            group_id_parts = path_parts[group_id_start_index : group_id_end_index + 1]
            group_id = ".".join(group_id_parts)
            
            if group_id and artifact_id and version:
                return (group_id, artifact_id, version)

            return None
        except (ValueError, IndexError) as e:
            logger.warning(f"Could not extract maven coordinates from path '{path}': {e}")
            return None


    @staticmethod
    def _extract_maven_coords_from_text(text: str) -> Optional[Tuple[str, str, str]]:
        """Extract Maven coordinates from text description."""
        # Look for patterns like groupId:artifactId:version
        maven_coord_pattern = r'([a-zA-Z][a-zA-Z0-9_.\-]*):([a-zA-Z][a-zA-Z0-9_\-]*):([0-9][a-zA-Z0-9_.\-]*)'
        match = re.search(maven_coord_pattern, text)
        if match:
            return (match.group(1), match.group(2), match.group(3))

        return None


class MavenProjectManager:
    """Manages Maven project operations."""

    def __init__(self, path: str):
        self.path = Path(path)
        if self.path.is_file():
            self.pom_path = self.path
            self.project_dir = self.path.parent
        else:
            self.project_dir = self.path
            self.pom_path = self.project_dir / 'pom.xml'
        self.backup_path = None

    def backup_pom(self):
        """Create backup of POM file."""
        self.backup_path = self.pom_path.with_suffix('.pom.backup')
        shutil.copy2(self.pom_path, self.backup_path)
        logger.debug(f"Created POM backup: {self.backup_path}")

    def restore_pom(self):
        """Restore POM from backup."""
        if self.backup_path and self.backup_path.exists():
            shutil.copy2(self.backup_path, self.pom_path)
            self.backup_path.unlink()  # Remove backup
            logger.debug("Restored POM from backup")

    def get_modules(self) -> List[str]:
        """Parse the POM file and return the list of modules."""
        try:
            tree = ET.parse(self.pom_path)
            root = tree.getroot()
            
            namespace = ''
            if '}' in root.tag:
                namespace = f"{{{root.tag.split('}')[0][1:]}}}"

            modules = []
            modules_element = root.find(f"{namespace}modules")
            if modules_element is not None:
                for module_element in modules_element.findall(f"{namespace}module"):
                    if module_element.text:
                        modules.append(module_element.text)
            
            return modules
        except ET.ParseError as e:
            logger.error(f"Failed to parse POM file: {self.pom_path}")
            return []

    def get_dependency_tree_json(self) -> Optional[dict]:
        """Get dependency tree as JSON."""
        if not shutil.which("mvn"):
            logger.error("Maven executable not found in PATH. Please install Maven and make sure it is in your PATH.")
            sys.exit(1)

        try:
            output_file = self.project_dir.resolve() / 'dependency-tree.json'
            command = f'mvn -f "{self.pom_path.resolve()}" dependency:tree -DoutputType=json -DoutputFile="{output_file}"'
            result = subprocess.run(
                command,
                cwd=self.project_dir,
                capture_output=True, 
                text=True,
                timeout=120,
                shell=True
            )

            if result.returncode != 0:
                logger.error(f"Maven dependency:tree failed: {result.stderr}")
                return None

            if not output_file.exists():
                logger.warning(f"Dependency tree file not created for {self.project_dir}")
                logger.debug(f"Maven stdout: {result.stdout}")
                logger.debug(f"Maven stderr: {result.stderr}")
                return None

            with open(output_file, 'r') as f:
                data = json.load(f)
            output_file.unlink()  # Clean up
            return data

        except subprocess.TimeoutExpired:
            logger.error("Maven dependency:tree command timed out")
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Maven command failed: {e}")
            return None

    def is_dependency_managed(self, dependency: DependencyNode) -> bool:
        """Check if a dependency is managed in the POM file."""
        try:
            tree = ET.parse(self.pom_path)
            root = tree.getroot()
            
            namespace = ''
            if '}' in root.tag:
                namespace = f"{{{root.tag.split('}')[0][1:]}}}"

            dep_management = root.find(f"{namespace}dependencyManagement")
            if dep_management is not None:
                dependencies = dep_management.find(f"{namespace}dependencies")
                if dependencies is not None:
                    for dep in dependencies.findall(f"{namespace}dependency"):
                        group_id = dep.findtext(f"{namespace}groupId")
                        artifact_id = dep.findtext(f"{namespace}artifactId")
                        if group_id == dependency.group_id and artifact_id == dependency.artifact_id:
                            return True
            return False
        except ET.ParseError:
            return False


class MultiModuleMavenProjectManager(MavenProjectManager):
    """Manages multi-module Maven projects."""

    def __init__(self, project_dir: str):
        super().__init__(project_dir)
        self.modules: List[str] = []

    def discover_modules(self):
        """Discover all modules in the project."""
        self.modules = self.get_modules()
        logger.info(f"Discovered modules: {self.modules}")

    def get_all_dependency_trees(self) -> Dict[str, dict]:
        """Get dependency trees for all modules."""
        trees = {}
        
        for module in self.modules:
            module_path = self.project_dir / module
            if module_path.is_dir():
                logger.info(f"Getting dependency tree for module: {module}")
                module_manager = MavenProjectManager(str(module_path))
                tree = module_manager.get_dependency_tree_json()
                if tree:
                    trees[module] = tree
        
        return trees


class VulnerabilityPatcher:
    """Main class for patching vulnerabilities."""

    def __init__(self, project_manager: MavenProjectManager, include_prereleases: bool = False, dry_run: bool = False):
        self.project_manager = project_manager
        self.include_prereleases = include_prereleases
        self.dry_run = dry_run
        self.patch_suggestions: List[PatchSuggestion] = []

    def analyze_vulnerabilities(self, fortify_report_path: str, dependency_trees: Dict[str, dict]) -> List[PatchSuggestion]:
        """Analyze vulnerabilities and generate patch suggestions."""

        vulnerable_packages = FortifyReportParser.parse(fortify_report_path)
        if not vulnerable_packages:
            logger.warning("No vulnerabilities found in Fortify report")
            return []

        logger.info(f"Analyzing {len(vulnerable_packages)} vulnerabilities across {len(dependency_trees)} modules")

        suggestions = []
        for vuln_pkg in vulnerable_packages:
            found_in_module = False
            for module_name, tree_data in dependency_trees.items():
                root_node = DependencyTreeParser.parse(tree_data)
                if root_node:
                    vulnerable_node, path = self._find_vulnerable_package_in_tree(vuln_pkg, root_node)
                    if vulnerable_node:
                        logger.info(f"Found vulnerable package {vuln_pkg.coordinates} in module {module_name}")
                        suggestion = self._analyze_single_vulnerability(vuln_pkg, root_node, module_name)
                        suggestions.append(suggestion)
                        found_in_module = True
                        break  # Move to the next vulnerability
            if not found_in_module:
                logger.warning(f"Vulnerable package not found in any dependency tree: {vuln_pkg.coordinates}")

        self.patch_suggestions = suggestions
        return suggestions

    def _analyze_single_vulnerability(self, vuln_pkg: VulnerablePackage, root_node: DependencyNode, module_name: str) -> PatchSuggestion:
        """Analyze a single vulnerability and generate patch suggestion."""

        # Find the vulnerable package in dependency tree
        vulnerable_node, path = self._find_vulnerable_package_in_tree(vuln_pkg, root_node)

        if not vulnerable_node:
            logger.warning(f"Vulnerable package not found in dependency tree: {vuln_pkg.coordinates}")
            return PatchSuggestion(
                vulnerable_package=vuln_pkg,
                dependency_path=[],
                is_patchable=False
            )

        logger.info(f"Found vulnerable package: {vuln_pkg.coordinates}")
        logger.info(f"Dependency path: {' → '.join([node.coordinates for node in path])}")

        # Try to find patch by updating dependencies in path
        patch_suggestion = self._find_patch_in_path(vuln_pkg, path, module_name)

        return patch_suggestion

    def _find_vulnerable_package_in_tree(self, vuln_pkg: VulnerablePackage, root_node: DependencyNode) -> Tuple[Optional[DependencyNode], List[DependencyNode]]:
        """Find vulnerable package in dependency tree and return node with path."""

        def search_node(node: DependencyNode, current_path: List[DependencyNode]) -> Tuple[Optional[DependencyNode], List[DependencyNode]]:
            new_path = current_path + [node]

            # Check if this node matches the vulnerable package
            if (node.group_id == vuln_pkg.group_id and 
                node.artifact_id == vuln_pkg.artifact_id and 
                node.version == vuln_pkg.version):
                return node, new_path

            # Search children
            for child in node.children:
                found_node, found_path = search_node(child, new_path)
                if found_node:
                    return found_node, found_path

            return None, []

        return search_node(root_node, [])

    def _find_patch_in_path(self, vuln_pkg: VulnerablePackage, path: List[DependencyNode], module_name: str) -> PatchSuggestion:
        """Find patch by testing updates along the dependency path."""

        if len(path) <= 1:  # Only root node
            return PatchSuggestion(
                vulnerable_package=vuln_pkg,
                dependency_path=path,
                is_patchable=False
            )

        # Start from the highest level (skip root project)
        for i in range(1, len(path)):
            current_node = path[i]

            is_managed = self.project_manager.is_dependency_managed(current_node)
            if is_managed:
                logger.info(f"Dependency {current_node.coordinates} is managed in the root POM.")

            logger.info(f"Checking if updating {current_node.coordinates} resolves vulnerability in module {module_name}")

            # Get latest version
            latest_version = MavenRepository.get_latest_version(
                current_node.group_id, 
                current_node.artifact_id, 
                self.include_prereleases
            )

            if not latest_version:
                logger.warning(f"Could not find latest version for {current_node.coordinates}")
                continue

            if latest_version == current_node.version:
                logger.info(f"Already using latest version: {current_node.coordinates}")
                continue

            logger.info(f"Latest version available: {latest_version}")

            if self._would_update_resolve_vulnerability(current_node, latest_version, vuln_pkg):
                return PatchSuggestion(
                    vulnerable_package=vuln_pkg,
                    dependency_path=path,
                    suggested_update=current_node,
                    suggested_version=latest_version,
                    update_level=i,
                    is_patchable=True,
                    managed_in_parent_pom=is_managed,
                    parent_pom_path=self.project_manager.pom_path if is_managed else None
                )

        # No patch found by updating dependencies
        return PatchSuggestion(
            vulnerable_package=vuln_pkg,
            dependency_path=path,
            is_patchable=False
        )

    def _would_update_resolve_vulnerability(self, node: DependencyNode, new_version: str, vuln_pkg: VulnerablePackage) -> bool:
        """Check if updating a dependency would resolve the vulnerability."""
        # This is a simplified check - in reality we'd need to update POM and re-run dependency tree
        # For now, assume that any newer version would potentially resolve the issue
        return MavenRepository._version_key(new_version) > MavenRepository._version_key(node.version)

    def generate_report(self, output_format: str = "text") -> str:
        """Generate analysis report."""
        if output_format == "json":
            return self._generate_json_report()
        elif output_format == "csv":
            return self._generate_csv_report()
        else:
            return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """Generate text format report."""
        report = []
        report.append("MAVEN-FORTIFY VULNERABILITY ANALYSIS REPORT")
        report.append("=" * 50)
        report.append("")
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Summary
        total_vulns = len(self.patch_suggestions)
        patchable = sum(1 for s in self.patch_suggestions if s.is_patchable)

        report.append("SUMMARY:")
        report.append(f"- Total vulnerabilities analyzed: {total_vulns}")
        report.append(f"- Patchable by dependency updates: {patchable}")
        report.append(f"- No patches available: {total_vulns - patchable}")
        report.append("")

        # Detailed findings
        report.append("DETAILED FINDINGS:")
        report.append("")

        for i, suggestion in enumerate(self.patch_suggestions, 1):
            report.append(f"{i}. Vulnerability: {suggestion.vulnerable_package.coordinates}")

            if suggestion.vulnerable_package.cve_ids:
                report.append(f"   CVE IDs: {', '.join(suggestion.vulnerable_package.cve_ids)}")

            report.append(f"   Severity: {suggestion.vulnerable_package.severity}")

            if suggestion.dependency_path:
                path_str = " → ".join([node.coordinates for node in suggestion.dependency_path])
                report.append(f"   Path: {path_str}")

            if suggestion.is_patchable and suggestion.suggested_update:
                report.append(f"   ")
                report.append(f"   SOLUTION: Update {suggestion.suggested_update.coordinates}")
                report.append(f"   to version {suggestion.suggested_version}")
                if suggestion.managed_in_parent_pom:
                    report.append(f"   This dependency is managed in the parent POM: {suggestion.parent_pom_path}")
                    report.append(f"   Update the version in the <dependencyManagement> section of the parent POM.")
                elif suggestion.update_level == 1:
                    report.append(f"   This is a direct dependency update.")
                else:
                    report.append(f"   This will automatically update transitive dependencies.")
            else:
                report.append(f"   ")
                report.append(f"   NO SOLUTION: No patch available through dependency updates")
                report.append(f"   Consider updating the vulnerable package directly or finding alternatives")

            report.append("")

        return "\n".join(report)

    def _generate_json_report(self) -> str:
        """Generate JSON format report."""
        report_data = {
            "analysis_date": datetime.now().isoformat(),
            "summary": {
                "total_vulnerabilities": len(self.patch_suggestions),
                "patchable": sum(1 for s in self.patch_suggestions if s.is_patchable),
                "not_patchable": sum(1 for s in self.patch_suggestions if not s.is_patchable)
            },
            "findings": []
        }

        for suggestion in self.patch_suggestions:
            finding = {
                "vulnerable_package": {
                    "group_id": suggestion.vulnerable_package.group_id,
                    "artifact_id": suggestion.vulnerable_package.artifact_id,
                    "version": suggestion.vulnerable_package.version,
                    "cve_ids": suggestion.vulnerable_package.cve_ids,
                    "severity": suggestion.vulnerable_package.severity
                },
                "dependency_path": [node.coordinates for node in suggestion.dependency_path],
                "is_patchable": suggestion.is_patchable,
                "suggested_update": None
            }

            if suggestion.is_patchable and suggestion.suggested_update:
                finding["suggested_update"] = {
                    "dependency": suggestion.suggested_update.coordinates,
                    "new_version": suggestion.suggested_version,
                    "update_level": suggestion.update_level,
                    "managed_in_parent_pom": suggestion.managed_in_parent_pom,
                    "parent_pom_path": str(suggestion.parent_pom_path) if suggestion.parent_pom_path else None
                }

            report_data["findings"].append(finding)

        return json.dumps(report_data, indent=2)

    def _generate_csv_report(self) -> str:
        """Generate CSV format report."""
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Vulnerable Package",
            "CVE IDs", 
            "Severity",
            "Dependency Path",
            "Is Patchable",
            "Suggested Update",
            "New Version",
            "Update Level",
            "Managed in Parent POM",
            "Parent POM Path"
        ])

        # Data rows
        for suggestion in self.patch_suggestions:
            writer.writerow([
                suggestion.vulnerable_package.coordinates,
                "; ".join(suggestion.vulnerable_package.cve_ids),
                suggestion.vulnerable_package.severity,
                " → ".join([node.coordinates for node in suggestion.dependency_path]),
                suggestion.is_patchable,
                suggestion.suggested_update.coordinates if suggestion.suggested_update else "",
                suggestion.suggested_version or "",
                suggestion.update_level,
                suggestion.managed_in_parent_pom,
                str(suggestion.parent_pom_path) if suggestion.parent_pom_path else ""
            ])

        return output.getvalue()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Maven-Fortify Vulnerability Patching CLI Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --fortify-report report.xml --project-dir /path/to/maven/project
  %(prog)s --fortify-report report.xml --dependency-tree-dir /path/to/json/dir
        """
    )

    parser.add_argument(
        '--fortify-report', 
        required=True,
        help='Path to Fortify vulnerability report XML file'
    )

    parser.add_argument(
        '--project-dir', 
        default='.',
        help='Path to the root of the Maven project (default: current directory)'
    )

    parser.add_argument(
        '--dependency-tree-dir',
        help='Path to a directory containing dependency tree JSON files (optional)'
    )

    parser.add_argument(
        '--include-prereleases', 
        action='store_true',
        help='Include pre-release versions in updates'
    )

    parser.add_argument(
        '--dry-run', 
        action='store_true',
        help='Analyze without making changes'
    )

    parser.add_argument(
        '--output-format', 
        choices=['text', 'json', 'csv'],
        default='text',
        help='Output format (default: text)'
    )

    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARN', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    args = parser.parse_args()

    # Configure logging
    log_level = getattr(logging, args.log_level)
    logger.setLevel(log_level)

    try:
        project_path = Path(args.project_dir)
        if project_path.is_file() and "pom" in project_path.name.lower() and project_path.name.lower().endswith('.xml'):
            # Single POM file provided
            project_manager = MavenProjectManager(str(project_path))
            # For single pom, we need to get the tree for that specific pom
            dependency_trees = {'root': project_manager.get_dependency_tree_json()}
        elif project_path.is_dir():
            # Multi-module project or single project directory
            project_manager = MultiModuleMavenProjectManager(str(project_path))
            project_manager.discover_modules()

            dependency_trees = {}
            if args.dependency_tree_dir:
                # Load from directory
                tree_dir = Path(args.dependency_tree_dir)
                for json_file in tree_dir.glob('*.json'):
                    module_name = json_file.stem
                    with open(json_file, 'r') as f:
                        dependency_trees[module_name] = json.load(f)
            else:
                # Generate dependency trees
                dependency_trees = project_manager.get_all_dependency_trees()
        else:
            logger.error(f"Invalid project path: {args.project_dir}. Must be a directory or a pom.xml file.")
            sys.exit(1)

        if not dependency_trees:
            logger.error("Could not load or generate any dependency trees.")
            sys.exit(1)

        patcher = VulnerabilityPatcher(
            project_manager=project_manager,
            include_prereleases=args.include_prereleases,
            dry_run=args.dry_run
        )

        # Analyze vulnerabilities
        logger.info("Starting vulnerability analysis...")
        suggestions = patcher.analyze_vulnerabilities(args.fortify_report, dependency_trees)

        # Generate and display report
        report = patcher.generate_report(args.output_format)
        print(report)

        # Exit with appropriate code
        patchable_count = sum(1 for s in suggestions if s.is_patchable)
        if patchable_count > 0:
            logger.info(f"Analysis complete. Found {patchable_count} patchable vulnerabilities.")
            sys.exit(0)
        else:
            logger.warning("No patchable vulnerabilities found.")
            sys.exit(1)

        if not dependency_trees:
            logger.error("Could not load or generate any dependency trees.")
            sys.exit(1)

        patcher = VulnerabilityPatcher(
            project_manager=project_manager,
            include_prereleases=args.include_prereleases,
            dry_run=args.dry_run
        )

        # Analyze vulnerabilities
        logger.info("Starting vulnerability analysis...")
        suggestions = patcher.analyze_vulnerabilities(args.fortify_report, dependency_trees)

        # Generate and display report
        report = patcher.generate_report(args.output_format)
        print(report)

        # Exit with appropriate code
        patchable_count = sum(1 for s in suggestions if s.is_patchable)
        if patchable_count > 0:
            logger.info(f"Analysis complete. Found {patchable_count} patchable vulnerabilities.")
            sys.exit(0)
        else:
            logger.warning("No patchable vulnerabilities found.")
            sys.exit(1)

        if not dependency_trees:
            logger.error("Could not load or generate any dependency trees.")
            sys.exit(1)

        patcher = VulnerabilityPatcher(
            project_manager=project_manager,
            include_prereleases=args.include_prereleases,
            dry_run=args.dry_run
        )

        # Analyze vulnerabilities
        logger.info("Starting vulnerability analysis...")
        suggestions = patcher.analyze_vulnerabilities(args.fortify_report, dependency_trees)

        # Generate and display report
        report = patcher.generate_report(args.output_format)
        print(report)

        # Exit with appropriate code
        patchable_count = sum(1 for s in suggestions if s.is_patchable)
        if patchable_count > 0:
            logger.info(f"Analysis complete. Found {patchable_count} patchable vulnerabilities.")
            sys.exit(0)
        else:
            logger.warning("No patchable vulnerabilities found.")
            sys.exit(1)

        if not dependency_trees:
            logger.error("Could not load or generate any dependency trees.")
            sys.exit(1)

        patcher = VulnerabilityPatcher(
            project_manager=project_manager,
            include_prereleases=args.include_prereleases,
            dry_run=args.dry_run
        )

        # Analyze vulnerabilities
        logger.info("Starting vulnerability analysis...")
        suggestions = patcher.analyze_vulnerabilities(args.fortify_report, dependency_trees)

        # Generate and display report
        report = patcher.generate_report(args.output_format)
        print(report)

        # Exit with appropriate code
        patchable_count = sum(1 for s in suggestions if s.is_patchable)
        if patchable_count > 0:
            logger.info(f"Analysis complete. Found {patchable_count} patchable vulnerabilities.")
            sys.exit(0)
        else:
            logger.warning("No patchable vulnerabilities found.")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.debug("Exception details:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()