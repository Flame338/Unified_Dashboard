#!/usr/bin/env python3
"""
Test suite for Maven-Fortify Vulnerability Patcher
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the main modules (assuming they're in the same directory)
from maven_fortify_patcher import (
    DependencyNode,
    VulnerablePackage,
    PatchSuggestion,
    DependencyTreeParser,
    FortifyReportParser,
    MavenRepository,
    VulnerabilityPatcher
)


class TestDependencyNode(unittest.TestCase):
    """Test DependencyNode functionality."""

    def test_dependency_node_creation(self):
        """Test creating a dependency node."""
        node = DependencyNode(
            group_id="com.example",
            artifact_id="test-lib", 
            version="1.0.0",
            scope="compile"
        )

        self.assertEqual(node.group_id, "com.example")
        self.assertEqual(node.artifact_id, "test-lib")
        self.assertEqual(node.version, "1.0.0")
        self.assertEqual(node.coordinates, "com.example:test-lib:1.0.0")

    def test_dependency_node_hierarchy(self):
        """Test parent-child relationships."""
        parent = DependencyNode("com.example", "parent", "1.0.0")
        child = DependencyNode("com.example", "child", "2.0.0")

        child.parent = parent
        parent.children.append(child)

        self.assertEqual(child.parent, parent)
        self.assertIn(child, parent.children)


class TestVulnerablePackage(unittest.TestCase):
    """Test VulnerablePackage functionality."""

    def test_vulnerable_package_creation(self):
        """Test creating a vulnerable package."""
        vuln = VulnerablePackage(
            group_id="org.apache.commons",
            artifact_id="commons-text",
            version="1.8",
            cve_ids=["CVE-2023-12345"],
            severity="HIGH"
        )

        self.assertEqual(vuln.coordinates, "org.apache.commons:commons-text:1.8")
        self.assertEqual(vuln.cve_ids, ["CVE-2023-12345"])
        self.assertEqual(vuln.severity, "HIGH")


class TestDependencyTreeParser(unittest.TestCase):
    """Test dependency tree parsing functionality."""

    def test_parse_simple_tree(self):
        """Test parsing a simple dependency tree."""
        sample_tree = {
            "groupId": "com.example",
            "artifactId": "test-project",
            "version": "1.0.0",
            "dependencies": [
                {
                    "groupId": "junit",
                    "artifactId": "junit",
                    "version": "4.13.2",
                    "scope": "test",
                    "dependencies": []
                }
            ]
        }

        root = DependencyTreeParser.parse(sample_tree)

        self.assertIsNotNone(root)
        self.assertEqual(root.group_id, "com.example")
        self.assertEqual(root.artifact_id, "test-project")
        self.assertEqual(len(root.children), 1)

        child = root.children[0]
        self.assertEqual(child.group_id, "junit")
        self.assertEqual(child.artifact_id, "junit")
        self.assertEqual(child.parent, root)

    def test_parse_nested_tree(self):
        """Test parsing a nested dependency tree."""
        nested_tree = {
            "groupId": "com.example",
            "artifactId": "root",
            "version": "1.0.0",
            "dependencies": [
                {
                    "groupId": "com.example",
                    "artifactId": "level1",
                    "version": "1.0.0",
                    "dependencies": [
                        {
                            "groupId": "com.example",
                            "artifactId": "level2",
                            "version": "1.0.0",
                            "dependencies": []
                        }
                    ]
                }
            ]
        }

        root = DependencyTreeParser.parse(nested_tree)

        self.assertIsNotNone(root)
        self.assertEqual(len(root.children), 1)

        level1 = root.children[0]
        self.assertEqual(len(level1.children), 1)

        level2 = level1.children[0]
        self.assertEqual(level2.artifact_id, "level2")
        self.assertEqual(level2.parent, level1)


class TestMavenRepository(unittest.TestCase):
    """Test Maven repository functionality."""

    @patch('urllib.request.urlopen')
    def test_get_latest_version(self, mock_urlopen):
        """Test getting latest version from Maven repository."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": {
                "docs": [
                    {"v": "1.10.0"},
                    {"v": "1.9.0"},
                    {"v": "1.8.0"}
                ]
            }
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        version = MavenRepository.get_latest_version("org.apache.commons", "commons-text")
        self.assertEqual(version, "1.10.0")

    def test_is_stable_version(self):
        """Test version stability detection."""
        self.assertTrue(MavenRepository._is_stable_version("1.0.0"))
        self.assertTrue(MavenRepository._is_stable_version("2.5.12"))
        self.assertFalse(MavenRepository._is_stable_version("1.0.0-SNAPSHOT"))
        self.assertFalse(MavenRepository._is_stable_version("2.0.0-alpha-1"))
        self.assertFalse(MavenRepository._is_stable_version("1.5.0-beta"))

    def test_version_key_comparison(self):
        """Test version comparison logic."""
        key1 = MavenRepository._version_key("1.0.0")
        key2 = MavenRepository._version_key("1.0.1")
        key3 = MavenRepository._version_key("2.0.0")

        self.assertLess(key1, key2)
        self.assertLess(key2, key3)
        self.assertLess(key1, key3)


class TestFortifyReportParser(unittest.TestCase):
    """Test Fortify report parsing functionality."""

    def test_extract_maven_coords_from_path(self):
        """Test extracting Maven coordinates from file paths."""
        path1 = "/home/.m2/repository/org/apache/commons/commons-text/1.8/commons-text-1.8.jar"
        coords1 = FortifyReportParser._extract_maven_coords_from_path(path1)

        self.assertIsNotNone(coords1)
        self.assertEqual(coords1[0], "org.apache.commons")  # group_id
        self.assertEqual(coords1[1], "commons-text")         # artifact_id
        self.assertEqual(coords1[2], "1.8")                  # version

    def test_extract_maven_coords_from_text(self):
        """Test extracting Maven coordinates from text."""
        text = "Vulnerability found in org.apache.commons:commons-text:1.8"
        coords = FortifyReportParser._extract_maven_coords_from_text(text)

        self.assertIsNotNone(coords)
        self.assertEqual(coords[0], "org.apache.commons")
        self.assertEqual(coords[1], "commons-text")
        self.assertEqual(coords[2], "1.8")


class TestVulnerabilityPatcher(unittest.TestCase):
    """Test main vulnerability patcher functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_pom = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        self.temp_pom.write('<project></project>')
        self.temp_pom.close()

        self.patcher = VulnerabilityPatcher(
            pom_path=self.temp_pom.name,
            include_prereleases=False,
            dry_run=True
        )

    def tearDown(self):
        """Clean up test fixtures."""
        Path(self.temp_pom.name).unlink(missing_ok=True)

    def test_find_vulnerable_package_in_tree(self):
        """Test finding vulnerable packages in dependency tree."""
        # Create test tree
        root = DependencyNode("com.example", "root", "1.0.0")
        child = DependencyNode("org.apache.commons", "commons-text", "1.8")
        child.parent = root
        root.children.append(child)

        # Create vulnerable package
        vuln_pkg = VulnerablePackage("org.apache.commons", "commons-text", "1.8")

        # Test finding the package
        found_node, path = self.patcher._find_vulnerable_package_in_tree(vuln_pkg, root)

        self.assertIsNotNone(found_node)
        self.assertEqual(found_node, child)
        self.assertEqual(len(path), 2)  # root + child
        self.assertEqual(path[0], root)
        self.assertEqual(path[1], child)

    def test_generate_text_report(self):
        """Test generating text format report."""
        # Create sample patch suggestion
        vuln_pkg = VulnerablePackage(
            group_id="org.apache.commons",
            artifact_id="commons-text", 
            version="1.8",
            severity="HIGH"
        )

        suggestion = PatchSuggestion(
            vulnerable_package=vuln_pkg,
            dependency_path=[],
            is_patchable=True
        )

        self.patcher.patch_suggestions = [suggestion]
        report = self.patcher._generate_text_report()

        self.assertIn("VULNERABILITY ANALYSIS REPORT", report)
        self.assertIn("Total vulnerabilities analyzed: 1", report)
        self.assertIn("commons-text", report)

    def test_generate_json_report(self):
        """Test generating JSON format report."""
        vuln_pkg = VulnerablePackage(
            group_id="org.apache.commons",
            artifact_id="commons-text",
            version="1.8"
        )

        suggestion = PatchSuggestion(
            vulnerable_package=vuln_pkg,
            dependency_path=[],
            is_patchable=False
        )

        self.patcher.patch_suggestions = [suggestion]
        report = self.patcher._generate_json_report()

        # Verify it's valid JSON
        data = json.loads(report)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)


class TestIntegration(unittest.TestCase):
    """Integration tests using sample data."""

    def test_end_to_end_analysis(self):
        """Test complete analysis workflow with sample data."""
        # This would require the sample files created above
        sample_tree_path = "sample-dependency-tree.json"
        sample_fortify_path = "sample-fortify-report.xml" 

        if not (Path(sample_tree_path).exists() and Path(sample_fortify_path).exists()):
            self.skipTest("Sample data files not available")

        # Load sample data
        with open(sample_tree_path, 'r') as f:
            tree_data = json.load(f)

        # Create patcher (using temporary POM)
        temp_pom = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        temp_pom.write('<project></project>')
        temp_pom.close()

        try:
            patcher = VulnerabilityPatcher(
                pom_path=temp_pom.name,
                dry_run=True
            )

            # Run analysis
            suggestions = patcher.analyze_vulnerabilities(sample_fortify_path, tree_data)

            # Verify results
            self.assertIsInstance(suggestions, list)

            # Generate reports
            text_report = patcher.generate_report("text")
            json_report = patcher.generate_report("json")
            csv_report = patcher.generate_report("csv")

            self.assertIsInstance(text_report, str)
            self.assertIsInstance(json_report, str)
            self.assertIsInstance(csv_report, str)

            # Verify JSON is valid
            json.loads(json_report)

        finally:
            Path(temp_pom.name).unlink(missing_ok=True)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)