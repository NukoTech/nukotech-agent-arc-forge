from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class InstallerContractTests(unittest.TestCase):
    def test_installer_is_offline_and_marker_scoped(self) -> None:
        root = Path(__file__).resolve().parents[1]
        install = root / "installer" / "install.sh"
        uninstall = root / "installer" / "uninstall.sh"
        self.assertTrue(install.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(uninstall.stat().st_mode & stat.S_IXUSR)
        install_text = install.read_text(encoding="utf-8")
        uninstall_text = uninstall.read_text(encoding="utf-8")
        self.assertIn("--no-index", install_text)
        self.assertIn("--find-links", install_text)
        self.assertNotIn("sudo", install_text)
        self.assertNotIn("rm -rf", uninstall_text)
        self.assertIn("ownership.py", install_text)
        self.assertIn("ownership.py", uninstall_text)

    def test_prefix_canonicalization_refuses_broad_traversal_and_symlink_paths(self) -> None:
        root = Path(__file__).resolve().parents[1]
        helper = root / "installer" / "ownership.py"
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            target = temporary_root / "target"
            target.mkdir()
            link = temporary_root / "linked"
            link.symlink_to(target, target_is_directory=True)
            refused = [Path("/"), Path.home(), temporary_root / "safe" / ".." / "escape", link / "install"]
            for prefix in refused:
                result = subprocess.run(
                    [sys.executable, str(helper), "canonicalize", str(prefix)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, prefix)


if __name__ == "__main__":
    unittest.main()
