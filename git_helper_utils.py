from typing import List, Dict, Optional, Tuple
import subprocess
import re
import tempfile
import os
import shutil

class GitHelper:
    def __init__(self, repo: str, depth_hint: Optional[int] = None, depth_cap: int = 5000):
        self.original = repo
        self.depth_hint = depth_hint
        self.depth_cap = depth_cap
        self.path: Optional[str] = None
        self.tmpdir: Optional[str] = None
        self.ensure_local()

    @staticmethod
    def run(cmd: List[str], cwd: Optional[str] = None) -> str:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"This command failed: {' '.join(cmd)}\n{p.stderr}")
        return p.stdout

    def is_url(self, s: str) -> bool:
        return bool(re.match(r'''^(https?://|git@)''', s))


    def ensure_local(self) -> None:
        if self.is_url(self.original):
            self.tmpdir = tempfile.mkdtemp(prefix="find_threats-")
            depth = None
            if self.depth_hint is not None:
                depth = min(self.depth_cap, max(4 * self.depth_hint, self.depth_hint + 1))
            cmd = ["git", "clone"]
            if depth:
                cmd += [f"--depth={depth}"]
            cmd += [self.original, self.tmpdir]
            self.run(cmd)
            self.path = self.tmpdir
        else:
            self.run(["git", "-C", self.original, "rev-parse", "--is-inside-work-tree"])
            self.path = self.original


    def list_last_commits(self, n: int) -> List[str]:
        out = self.run(["git", "-C", self.path, "log", f"-n{n}", "--pretty=%H"])
        commits = [l.strip() for l in out.splitlines() if l.strip()]
        if len(commits) < n and self.tmpdir:
            self.run(["git", "-C", self.path, "fetch", f"--deepen={min(2000, self.depth_cap)}", "origin",
                       "HEAD"])
            out = self.run(["git", "-C", self.path, "log", f"-n{n}", "--pretty=%H"])
            commits = [l.strip() for l in out.splitlines() if l.strip()]
        return commits


    def commit_message(self, commit: str) -> str:
        return self.run(["git", "-C", self.path, "log", "-1", "--pretty=%B", commit])


    def commit_parent(self, commit: str) -> Optional[str]:
        out = self.run(
            ["git", "-C", self.path, "rev-list", "--parents", "-n", "1", commit]).strip()
        parts = out.split()
        return parts[1] if len(parts) > 1 else None


    def diff_added(self, parent: Optional[str], commit: str) -> str:
        if parent:
            return self.run(["git", "-C", self.path, "diff", "-U0", parent, commit])
        else:
            empty = self.run(["git", "hash-object", "-t", "tree", "/dev/null"]).strip()
            return self.run(["git", "-C", self.path, "diff", "-U0", empty, commit])


    def cleanup(self) -> None:
        if self.tmpdir and os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)