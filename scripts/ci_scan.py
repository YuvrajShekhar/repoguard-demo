#!/usr/bin/env python3
"""RepoGuard CI scanner — synchronous pre-agent repository scan for GitHub Actions.

Design follows the deployability finding of Section 4.9.2: the synchronous CI path
runs Tier 0 (pattern rules) + Tier 1.5 (classifier) only, measured at ~339 ms/file.
The Tier 1.75 semantic layer is opt-in (--semantic) because its measured 17.9 s/file
at a 66% escalation rate precludes blocking pre-merge invocation.

Exit codes:
  0  no MALICIOUS verdict (SUSPICIOUS findings are annotated, not blocking)
  1  at least one MALICIOUS verdict
  2  scanner error (missing dependency, unreadable input)

Usage:
  python ci_scan.py --files-from changed.txt --report repoguard-report.json
  python ci_scan.py --all --report repoguard-report.json
  python ci_scan.py --all --semantic          # includes Tier 1.75; slow
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
import fnmatch

# ── Surfaces from the taxonomy of Section 3.1.1 ──────────────────────────────
STRICT_BASENAMES = {
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
    "copilot-instructions.md", ".clinerules", ".windsurfrules",
}
CI_PATH_MARKERS = (
    ".github/workflows/", ".gitlab-ci.yml", "bitbucket-pipelines.yml",
    ".circleci/", "azure-pipelines.yml",
)
DOC_SUFFIXES = {".md", ".markdown", ".rst", ".txt"}
CODE_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb",
    ".c", ".h", ".cpp", ".cs", ".php", ".sh",
}
MAX_BYTES = 1_000_000  # skip anything larger; not repository-instruction content


def classify_surface(path: str) -> str | None:
    """Return the taxonomy surface for a path, or None if out of scope."""
    p = path.replace("\\", "/")
    name = os.path.basename(p)
    if name in STRICT_BASENAMES:
        return "agent-instruction" if name != ".cursorrules" else ".cursorrules"
    if any(m in p for m in CI_PATH_MARKERS) and p.endswith((".yml", ".yaml")):
        return "ci-cd-yaml"
    suf = Path(p).suffix.lower()
    if name.lower().startswith("readme") and suf in DOC_SUFFIXES:
        return "readme"
    if suf in CODE_SUFFIXES:
        return "code-comments"
    return None


def iter_repo_files(root: Path):
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__",
                 "dist", "build", ".mypy_cache", ".pytest_cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            yield str(Path(dirpath, fn).relative_to(root))


def load_scanner(use_semantic: bool):
    """Import the pipeline. Returns (scan_callable, mode_label)."""
    try:
        from cloneguard.mini_semantic import MiniSemanticClassifier
    except ImportError as e:
        print(f"::error::CloneGuard classifier unavailable: {e}. "
              f"Install with: pip install 'cloneguard[mini]'", file=sys.stderr)
        sys.exit(2)

    classifier = MiniSemanticClassifier()

    if use_semantic:
        try:
            from repoguard.tier175 import scan_file
        except ImportError as e:
            print(f"::error::RepoGuard semantic layer unavailable: {e}", file=sys.stderr)
            sys.exit(2)

        def scan(path: str, content: str):
            return scan_file(path, content, classifier)

        return scan, "tier0+1.5+1.75"

    # Synchronous CI path: classifier only, no semantic escalation.
    from cloneguard.patterns import PatternEngine, ScanMode, Verdict as PatternVerdict

    engine = PatternEngine()

    def scan(path: str, content: str):
        mode = (ScanMode.STRICT
                if os.path.basename(path) in STRICT_BASENAMES
                else ScanMode.STANDARD)
        t0 = engine.scan(content, source_path=path, mode=mode)
        t0_verdict = getattr(t0, "verdict", None)
        if t0_verdict is not None and str(t0_verdict).upper().endswith("MALICIOUS"):
            return {"verdict": "MALICIOUS", "layer": "tier0",
                    "reason": getattr(t0, "reason", "pattern rule match")}
        r = classifier.classify(content, mode=mode)
        label = str(getattr(r, "label", getattr(r, "verdict", "SAFE"))).upper()
        label = label.rsplit(".", 1)[-1]
        return {"verdict": label,
                "layer": "tier1.5",
                "confidence": float(getattr(r, "confidence", 0.0) or 0.0),
                "reason": getattr(r, "reason", "") or ""}

    return scan, "tier0+1.5"


def normalise(result) -> dict:
    """Coerce either return shape into a flat dict."""
    if isinstance(result, dict):
        return result
    verdict = getattr(result, "verdict", None)
    verdict = str(getattr(verdict, "name", verdict) or "SAFE").upper().rsplit(".", 1)[-1]
    return {
        "verdict": verdict,
        "layer": "tier1.75" if getattr(result, "escalated", False) else "tier1.5",
        "escalated": bool(getattr(result, "escalated", False)),
        "escalation_reason": str(getattr(result, "escalation_reason", "") or ""),
        "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        "reason": str(getattr(result, "reason", "") or ""),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files-from", help="file containing newline-separated paths")
    ap.add_argument("--all", action="store_true", help="scan the whole repository")
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--report", default="repoguard-report.json")
    ap.add_argument("--semantic", action="store_true",
                    help="enable Tier 1.75 (slow; see Section 4.9.2)")
    ap.add_argument("--fail-on-suspicious", action="store_true")
    ap.add_argument("--exclude", nargs="*", default=[], help="glob patterns to exclude (e.g. 'scripts/*' 'src/repoguard/*')")
    a = ap.parse_args()

    root = Path(a.root).resolve()

    if a.files_from:
        raw = Path(a.files_from).read_text(encoding="utf-8").splitlines()
        candidates = [x.strip() for x in raw if x.strip()]
    elif a.all:
        candidates = list(iter_repo_files(root))
    else:
        print("::error::specify --files-from or --all", file=sys.stderr)
        return 2

    in_scope = [(p, s) for p in candidates if (s := classify_surface(p)) and not any(fnmatch.fnmatch(p.replace("\\", "/"), pat) for pat in a.exclude)]
    print(f"RepoGuard: {len(candidates)} changed file(s), "
          f"{len(in_scope)} on monitored surfaces")

    scan, mode_label = load_scanner(a.semantic)
    print(f"RepoGuard: scan mode {mode_label}")

    findings, scanned, t_start = [], 0, time.perf_counter()

    for rel, surface in in_scope:
        fp = root / rel
        try:
            if not fp.is_file() or fp.stat().st_size > MAX_BYTES:
                continue
            content = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not content.strip():
            continue

        t0 = time.perf_counter()
        res = normalise(scan(rel, content))
        res.update(path=rel, surface=surface,
                   latency_ms=round((time.perf_counter() - t0) * 1000, 1))
        scanned += 1
        if res["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            findings.append(res)

    elapsed = time.perf_counter() - t_start
    malicious = [f for f in findings if f["verdict"] == "MALICIOUS"]
    suspicious = [f for f in findings if f["verdict"] == "SUSPICIOUS"]

    # GitHub annotations — appear inline on the pull request diff.
    for f in malicious:
        print(f"::error file={f['path']},line=1::RepoGuard: prompt-injection "
              f"payload detected on {f['surface']} surface. {f.get('reason','')}")
    for f in suspicious:
        print(f"::warning file={f['path']},line=1::RepoGuard: suspicious content "
              f"on {f['surface']} surface — review before agent invocation. "
              f"{f.get('reason','')}")

    report = {
        "mode": mode_label,
        "files_considered": len(candidates),
        "files_in_scope": len(in_scope),
        "files_scanned": scanned,
        "malicious": len(malicious),
        "suspicious": len(suspicious),
        "total_seconds": round(elapsed, 3),
        "mean_latency_ms": round(elapsed / scanned * 1000, 1) if scanned else None,
        "findings": findings,
    }
    Path(a.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## RepoGuard scan\n\n")
            fh.write(f"Mode `{mode_label}` · {scanned} file(s) scanned on monitored "
                     f"surfaces · {elapsed:.2f}s total")
            if report["mean_latency_ms"]:
                fh.write(f" · {report['mean_latency_ms']:.0f} ms/file mean")
            fh.write("\n\n")
            if not findings:
                fh.write("No injection payloads detected.\n")
            else:
                fh.write("| Verdict | Surface | File |\n|---|---|---|\n")
                for f in malicious + suspicious:
                    fh.write(f"| {f['verdict']} | {f['surface']} | `{f['path']}` |\n")

    print(f"RepoGuard: {scanned} scanned in {elapsed:.2f}s "
          f"({report['mean_latency_ms']} ms/file) — "
          f"{len(malicious)} malicious, {len(suspicious)} suspicious")

    if malicious or (a.fail_on_suspicious and suspicious):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
