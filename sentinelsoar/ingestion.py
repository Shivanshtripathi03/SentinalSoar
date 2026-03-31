"""
Log Ingestion Module — tails log files from the shared /logs directory.
Yields new raw log lines as they appear, tracking file offsets.
"""

import os
import time
import glob


class LogIngester:
    """Tails multiple log files, yielding new lines as they appear."""

    def __init__(self, log_dir="/logs"):
        self.log_dir = log_dir
        self.offsets = {}  # filepath -> last-read byte offset

    def _discover_files(self):
        """Find all .log files in the log directory."""
        return glob.glob(os.path.join(self.log_dir, "*.log"))

    def _source_type(self, filepath):
        """Derive source type from filename."""
        basename = os.path.basename(filepath).replace(".log", "")
        return basename  # 'web', 'auth', 'db'

    def poll(self):
        """
        Read new lines from all log files since last offset.
        Returns a list of (source_type, raw_line) tuples.
        """
        new_lines = []
        for filepath in self._discover_files():
            source = self._source_type(filepath)
            try:
                with open(filepath, "r") as f:
                    # Seek to last known offset
                    offset = self.offsets.get(filepath, 0)
                    f.seek(offset)
                    for line in f:
                        stripped = line.strip()
                        if stripped:
                            new_lines.append((source, stripped))
                    # Update offset
                    self.offsets[filepath] = f.tell()
            except FileNotFoundError:
                continue
            except Exception as e:
                print(f"[ingestion] Error reading {filepath}: {e}")
        return new_lines
