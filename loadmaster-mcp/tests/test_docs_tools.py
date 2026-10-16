import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from loadmaster_mcp import server


class SampleScriptToolTests(unittest.TestCase):
    def test_reads_script_within_sample_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scripts_dir = Path(temp_dir) / "scripts"
            scripts_dir.mkdir()
            (scripts_dir / "example.sh").write_text("#!/bin/sh\nprintf ok\n")

            with patch.object(server, "SCRIPTS_DIR", scripts_dir):
                result = server.get_sample_script("example.sh")

        self.assertEqual(result, "#!/bin/sh\nprintf ok\n")

    def test_rejects_path_outside_sample_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir()
            (root / "private.txt").write_text("private content")

            with patch.object(server, "SCRIPTS_DIR", scripts_dir):
                result = server.get_sample_script("../private.txt")

        self.assertIn("outside the sample scripts directory", result)
        self.assertNotIn("private content", result)

    def test_rejects_symlink_to_file_outside_sample_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir()
            private_file = root / "private.txt"
            private_file.write_text("private content")
            (scripts_dir / "linked.txt").symlink_to(private_file)

            with patch.object(server, "SCRIPTS_DIR", scripts_dir):
                result = server.get_sample_script("linked.txt")

        self.assertIn("outside the sample scripts directory", result)
        self.assertNotIn("private content", result)


if __name__ == "__main__":
    unittest.main()
