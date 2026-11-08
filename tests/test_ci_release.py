# Exercise release validation against temporary, real Git repositories.
# Annotated tags, ancestry and version changes use Git's actual object model.
# Asset tests build real tar archives and verify exact-package/checksum policy.
# No hosted service, signing certificate or production repository is modified.
# These checks run through Makefile.ci before release workflow publication.
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release.sh"
RELEASE_TAG_ENV = "RELEASE_TAG"
RELEASE_COMMIT_ENV = "RELEASE_COMMIT"


class ReleaseValidation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet", "-b", "main")
        self.git("config", "user.name", "Release Test Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / "release.sh")
        shutil.copy2(SCRIPT.parent.parent / "Makefile.ci", self.root / "Makefile.ci")
        (self.root / "configure.ac").write_text("AC_INIT(TCPFLOW, 1.7.0, test@example.invalid)\n")
        (self.root / "CMakeLists.txt").write_text("project(tcpflow VERSION 1.7.0 LANGUAGES CXX C)\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Synthetic release fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/remotes/origin/main", self.commit)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, text=True, capture_output=True)

    def run_check(self, *args, succeeds=True):
        result = subprocess.run(["bash", str(SCRIPT), *args], cwd=self.root, text=True, capture_output=True)
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_annotated_version_tag_on_main_passes(self):
        self.git("tag", "-a", "v1.7.0", "-m", "Synthetic tag")
        self.assertIn(self.commit, self.run_check("preflight", "v1.7.0", self.commit).stdout)

    def test_lightweight_tag_and_wrong_event_commit_fail(self):
        self.git("tag", "v1.7.0")
        self.run_check("preflight", "v1.7.0", self.commit, succeeds=False)
        self.git("tag", "-d", "v1.7.0")
        self.git("tag", "-a", "v1.7.0", "-m", "Synthetic tag")
        self.run_check("preflight", "v1.7.0", "0" * 40, succeeds=False)

    def test_unmerged_commit_and_version_mismatch_fail(self):
        self.git("commit", "--quiet", "--allow-empty", "-m", "Unmerged fixture")
        tip = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", "-a", "v1.7.0", "-m", "Synthetic tag")
        self.run_check("preflight", "v1.7.0", tip, succeeds=False)
        self.git("update-ref", "refs/remotes/origin/main", tip)
        (self.root / "CMakeLists.txt").write_text("project(tcpflow VERSION 1.6.2 LANGUAGES CXX C)\n")
        self.run_check("preflight", "v1.7.0", tip, succeeds=False)

    def make_assets(self):
        assets = self.root / "dist"
        assets.mkdir()
        with tarfile.open(assets / "tcpflow-1.7.0.tar.gz", "w:gz") as archive:
            data = b"#!/bin/sh\n"
            entry = tarfile.TarInfo("tcpflow-1.7.0/configure")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        for name in ("tcpflow64.exe", "tcpflow_1.7.0_amd64.snap", "tcpflow_1.7.0_arm64.snap"):
            (assets / name).write_bytes(b"Synthetic asset: " + name.encode())
        return assets

    @unittest.skipUnless(shutil.which("sha256sum"), "GNU sha256sum is required for release assembly")
    def test_exact_assets_produce_checksums_of_final_bytes(self):
        assets = self.make_assets()
        self.run_check("assets", "v1.7.0", str(assets))
        lines = (assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((assets / name).read_bytes()).hexdigest())

    def test_missing_architecture_extra_and_empty_assets_fail(self):
        assets = self.make_assets()
        arm = assets / "tcpflow_1.7.0_arm64.snap"
        arm.unlink()
        self.run_check("assets", "v1.7.0", str(assets), succeeds=False)
        arm.write_bytes(b"arm")
        extra = assets / "unsigned.exe"
        extra.write_bytes(b"unreviewed")
        self.run_check("assets", "v1.7.0", str(assets), succeeds=False)
        extra.unlink()
        (assets / "tcpflow64.exe").write_bytes(b"")
        self.run_check("assets", "v1.7.0", str(assets), succeeds=False)

    def test_invalid_tag_cannot_be_interpreted_as_shell(self):
        self.run_check("preflight", "v1.7.0;touch forbidden", self.commit, succeeds=False)
        self.assertFalse((self.root / "forbidden").exists())

    def test_make_entry_points_do_not_execute_git_valid_tag_text(self):
        tag = "v`touch${IFS}forbidden`"
        self.git("check-ref-format", "refs/tags/" + tag)
        environment = os.environ | {RELEASE_TAG_ENV: tag, RELEASE_COMMIT_ENV: self.commit}
        for target in ("release-tag-check", "release-assets"):
            result = subprocess.run(["make", "-f", "Makefile.ci", target], cwd=self.root,
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((self.root / "forbidden").exists())


if __name__ == "__main__":
    unittest.main()
