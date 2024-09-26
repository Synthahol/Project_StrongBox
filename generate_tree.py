# generate_tree.py
import argparse
import fnmatch
import logging
import os
import sys
from pathlib import Path

# Configure logging (optional, for debugging)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def generate_directory_tree(
    root_dir: Path, output_file, exclude_dirs=None, exclude_files=None, prefix=""
):
    """
    Recursively generates a directory tree and writes it to a file.

    :param root_dir: The root directory as a Path object.
    :param output_file: The file object to write the tree structure.
    :param exclude_dirs: Set of directory patterns to exclude.
    :param exclude_files: Set of file patterns to exclude.
    :param prefix: String prefix for formatting.
    """
    if exclude_dirs is None:
        exclude_dirs = set()
    if exclude_files is None:
        exclude_files = set()

    # Get all entries in the directory, sorted with directories first
    entries = sorted(root_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))

    # Filter out excluded directories and files
    filtered_entries = []
    for entry in entries:
        # Check if the entry should be excluded
        if entry.is_dir():
            if any(fnmatch.fnmatch(entry.name, pattern) for pattern in exclude_dirs):
                logging.debug(f"Excluded directory: {entry}")
                continue
        else:
            if any(fnmatch.fnmatch(entry.name, pattern) for pattern in exclude_files):
                logging.debug(f"Excluded file: {entry}")
                continue
        filtered_entries.append(entry)

    entries_count = len(filtered_entries)
    for index, entry in enumerate(filtered_entries):
        connector = "├── " if index < entries_count - 1 else "└── "
        if entry.is_symlink():
            try:
                link_target = os.readlink(entry)
                line = f"{prefix}{connector}{entry.name} -> {link_target}\n"
                logging.debug(f"Symbolic link: {entry} -> {link_target}")
            except OSError:
                line = f"{prefix}{connector}{entry.name} -> [Invalid Link]\n"
                logging.warning(f"Invalid symbolic link: {entry}")
        elif entry.is_file():
            line = f"{prefix}{connector}{entry.name}\n"
            logging.debug(f"File: {entry}")
        else:
            line = f"{prefix}{connector}{entry.name}\n"
            logging.debug(f"Directory: {entry}")
        output_file.write(line)

        if entry.is_dir() and not entry.is_symlink():
            # Determine the extension for the next level
            extension = "│   " if index < entries_count - 1 else "    "
            generate_directory_tree(
                entry, output_file, exclude_dirs, exclude_files, prefix + extension
            )


def main():
    parser = argparse.ArgumentParser(
        description="Generate directory tree with exclusions."
    )
    parser.add_argument(
        "root_dir",
        nargs="?",
        default=".",
        help="Root directory to start the tree (default: current directory).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="directory_structure.txt",
        help="Output text file (default: directory_structure.txt).",
    )
    parser.add_argument(
        "-ed",
        "--exclude_dirs",
        nargs="*",
        default=[],
        help="Directory patterns to exclude (supports wildcards).",
    )
    parser.add_argument(
        "-ef",
        "--exclude_files",
        nargs="*",
        default=[],
        help="File patterns to exclude (supports wildcards).",
    )

    args = parser.parse_args()

    root_path = Path(args.root_dir).resolve()
    output_path = Path(args.output).resolve()

    if not root_path.exists():
        print(f"Error: The directory {root_path} does not exist.")
        sys.exit(1)

    # Define default exclusions
    default_exclude_dirs = {".git", ".ruff_cache", "__pycache__"}
    default_exclude_files = {"*.pyc"}

    # Combine default exclusions with user-specified exclusions
    combined_exclude_dirs = default_exclude_dirs.union(set(args.exclude_dirs))
    combined_exclude_files = default_exclude_files.union(set(args.exclude_files))

    logging.info(f"Generating directory tree for: {root_path}")
    logging.info(f"Excluding directories: {combined_exclude_dirs}")
    logging.info(f"Excluding files: {combined_exclude_files}")

    with output_path.open("w", encoding="utf-8") as f:
        f.write(f"{root_path.name}\n")
        generate_directory_tree(
            root_path, f, combined_exclude_dirs, combined_exclude_files
        )

    print(f"Directory structure saved to {output_path}")


if __name__ == "__main__":
    main()
