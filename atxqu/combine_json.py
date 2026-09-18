#!/usr/bin/env python3
"""
Combine all .json files in a directory into one JSON array.

Usage:
    python3 combine_json.py [directory]

If no directory is given, it uses the current working directory.
"""

import json
import glob
import os
import sys

def combine_json(directory="."):
    json_files = glob.glob(os.path.join(directory, "*.json"))
    if not json_files:
        print(f"No .json files found in {directory}")
        return

    combined = []
    for filepath in sorted(json_files):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                combined.append(data)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")

    output_file = "combined_transactions.json"
    with open(output_file, 'w') as f:
        json.dump(combined, f, indent=2)

    print(f"Combined {len(combined)} files into {output_file}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        combine_json(sys.argv[1])
    else:
        combine_json()