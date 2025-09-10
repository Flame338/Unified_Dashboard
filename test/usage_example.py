#!/usr/bin/env python3
"""
Example usage of Maven-Fortify Vulnerability Patcher
"""

import json
import subprocess
import sys
from pathlib import Path

def run_example():
    """Run example analysis with sample data."""

    print("Maven-Fortify Vulnerability Patcher - Example Usage")
    print("=" * 55)
    print()

    # Check if sample files exist
    sample_files = [
        "sample-dependency-tree.json",
        "sample-fortify-report.xml", 
        "sample-pom.xml"
    ]

    missing_files = [f for f in sample_files if not Path(f).exists()]
    if missing_files:
        print(f"Missing sample files: {missing_files}")
        print("Please run the test data creation script first.")
        return 1

    print("Running analysis with sample data...")
    print()

    # Run the tool with sample data
    try:
        result = subprocess.run([
            sys.executable, "maven_fortify_patcher.py",
            "--fortify-report", "sample-fortify-report.xml",
            "--dependency-tree", "sample-dependency-tree.json", 
            "--pom-file", "sample-pom.xml",
            "--dry-run",
            "--log-level", "INFO"
        ], capture_output=True, text=True, timeout=60)

        print("STDOUT:")
        print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        print(f"Exit code: {result.returncode}")

    except subprocess.TimeoutExpired:
        print("Analysis timed out")
        return 1
    except subprocess.CalledProcessError as e:
        print(f"Analysis failed: {e}")
        return 1

    print()
    print("Example completed!")
    print()
    print("Try other output formats:")
    print("  python maven_fortify_patcher.py \\")
    print("    --fortify-report sample-fortify-report.xml \\")
    print("    --dependency-tree sample-dependency-tree.json \\")
    print("    --output-format json")
    print()
    print("  python maven_fortify_patcher.py \\")
    print("    --fortify-report sample-fortify-report.xml \\")
    print("    --dependency-tree sample-dependency-tree.json \\")
    print("    --output-format csv")

    return 0

if __name__ == "__main__":
    sys.exit(run_example())