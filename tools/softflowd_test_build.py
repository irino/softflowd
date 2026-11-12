"""
Builds of the softflowd binaries (C stable / development, C++, Rust) for the compat suite.
"""

import atexit
import hashlib
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

import softflowd_test_helper as helper
from softflowd_test_helper import (
    PROJECT_ROOT,
    build_c,
    copy_binaries,
    print_cyan,
    print_red,
    print_yellow,
    run_command,
)


# ==============================================================================
# Build Functions
# ==============================================================================

# (short name, description, configure arguments, binary name suffix)
C_BUILD_VARIANTS = [
    ("default", "default", [], ""),
    ("legacy", "legacy (--enable-legacy)", ["--enable-legacy"], "-legacy"),
    ("static", "static (--enable-compat-export=static)", ["--enable-compat-export=static"], "-static"),
    ("direct", "direct-copies (--enable-direct-copies)", ["--enable-direct-copies"], "-direct"),
]


def build_c_variants(src_dir: str, output_dir: str, what: str, prefix: str,
                     variants: list) -> List[str]:
    """Build each variant in src_dir and copy the binaries into output_dir.

    Returns the flat list [softflowd, softflowctl, ...] in variants order.
    """
    paths: List[str] = []
    for n, (short, desc, args, suffix) in enumerate(variants):
        print(f"  -> Configuring and building {what} {desc}...")
        if not build_c(src_dir, args, autoreconf=(n == 0)):
            print_red(f"Failed to build {what} {short} C binaries.")
            sys.exit(1)
        daemon = os.path.join(output_dir, f"{prefix}softflowd{suffix}")
        ctl = os.path.join(output_dir, f"{prefix}softflowctl{suffix}")
        copy_binaries(src_dir, daemon, ctl)
        paths += [daemon, ctl]
    return paths


STABLE_BINARIES = ("stable-softflowd", "stable-softflowctl",
                   "stable-softflowd-legacy", "stable-softflowctl-legacy")


def stable_cache_key(commit_hash: str) -> str:
    """Resolve commit_hash to a full SHA so that a moved tag or branch does not
    hit a stale cache entry; fall back to the name as given."""
    res = subprocess.run(["git", "rev-parse", "--verify", f"{commit_hash}^{{commit}}"],
                         cwd=PROJECT_ROOT, capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else commit_hash


def build_c_stable(commit_hash: str, output_dir: str) -> Tuple[str, str, str, str]:
    """
    Check out C stable version into an isolated temp worktree and compile both
    standard and legacy variants.  The binaries are cached in CACHE_DIR per
    commit; a cached set is reused without building (or needing the commit).
    Returns: (stable-softflowd, stable-softflowctl, stable-softflowd-legacy, stable-softflowctl-legacy)
    """
    cache_entry = None
    if helper.CACHE_DIR:
        key = stable_cache_key(commit_hash)
        cache_entry = os.path.join(helper.CACHE_DIR, "stable", re.sub(r"[^A-Za-z0-9._-]", "_", key))
        cached = None if helper.REBUILD_STABLE else cached_binaries(cache_entry, STABLE_BINARIES,
                                                            output_dir)
        if cached:
            print_cyan(f"\n[Build] Using cached C stable binaries ({commit_hash}): {cache_entry}")
            return cached

    print_cyan(f"\n[Build] Compiling C stable version (Commit/Tag: {commit_hash})...")
    worktree_dir = os.path.join(helper.SUITE_TMP_DIR, "c_stable_worktree")

    run_command(["git", "worktree", "add", "-f", worktree_dir, commit_hash], cwd=PROJECT_ROOT)
    atexit.register(lambda: subprocess.run(["git", "worktree", "remove", "-f", worktree_dir], cwd=PROJECT_ROOT, stderr=subprocess.DEVNULL))

    # The stable tree predates --enable-compat-export: default and legacy only.
    paths = tuple(build_c_variants(worktree_dir, output_dir, "stable", "stable-",
                                   C_BUILD_VARIANTS[:2]))
    if cache_entry:
        store_binary_cache(cache_entry, paths, "stable")
    return paths


def cached_binaries(cache_entry: str, names: Sequence[str],
                    output_dir: str) -> Optional[Tuple[str, ...]]:
    """Copy the cached binaries into output_dir; None if the entry is not complete."""
    if not all(os.access(os.path.join(cache_entry, n), os.X_OK) for n in names):
        return None
    os.utime(cache_entry)  # most recently used, see prune_dev_cache()
    paths = []
    for n in names:
        dest = os.path.join(output_dir, n)
        shutil.copy2(os.path.join(cache_entry, n), dest)
        paths.append(dest)
    return tuple(paths)


def store_binary_cache(cache_entry: str, paths: Sequence[str], what: str) -> None:
    """Store the built binaries in the cache; a failure only costs a rebuild next time.

    The binaries that the entry already holds (same key, so same sources) are kept: a run
    that skips a variant does not drop it from the cache.
    """
    tmp = f"{cache_entry}.tmp.{os.getpid()}"
    try:
        os.makedirs(tmp)
        for path in paths:
            shutil.copy2(path, os.path.join(tmp, os.path.basename(path)))
        if os.path.isdir(cache_entry):
            for name in os.listdir(cache_entry):
                if not os.path.exists(os.path.join(tmp, name)):
                    shutil.copy2(os.path.join(cache_entry, name), os.path.join(tmp, name))
        # Rename into place only when complete so the cache never holds a partial set.
        if os.path.isdir(cache_entry):
            shutil.rmtree(cache_entry)
        os.rename(tmp, cache_entry)
        print(f"  -> Cached {what} binaries in {cache_entry}")
    except OSError as e:
        print_yellow(f"Warning: could not cache the {what} binaries: {e}")
        shutil.rmtree(tmp, ignore_errors=True)


# Number of development builds kept in the cache.
DEV_CACHE_KEEP = 5

# Paths (and *.md files) that do not influence the C binaries and are left out of
# the cache key.
DEV_KEY_EXCLUDE_DIRS = ("cpp", "rust", "tools", ".github")


def dev_cache_key() -> Tuple[str, bool]:
    """Hash everything the C build depends on: the contents of the tracked and
    the not-ignored untracked files (so uncommitted edits count, HEAD does not),
    the configure arguments, the compiler settings and the compiler version.

    Returns (hex digest, whether the tree differs from HEAD).
    """
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=PROJECT_ROOT, capture_output=True, check=True).stdout
    names = sorted(n for n in (b.decode() for b in out.split(b"\0") if b)
                   if n.split("/")[0] not in DEV_KEY_EXCLUDE_DIRS
                   and not n.endswith(".md"))
    h = hashlib.sha256()
    for name in names:
        h.update(name.encode() + b"\0")
        path = os.path.join(PROJECT_ROOT, name)
        if os.path.isfile(path):  # a tracked file deleted from the tree has no content
            with open(path, "rb") as f:
                h.update(hashlib.sha256(f.read()).digest())
    for _, _, args, _ in C_BUILD_VARIANTS:
        h.update(b"\0args\0" + " ".join(args).encode())
    for var in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS"):
        h.update(f"\0{var}={os.environ.get(var, '')}".encode())
    cc = subprocess.run([os.environ.get("CC") or "cc", "--version"],
                        capture_output=True, text=True)
    h.update(b"\0cc\0" + cc.stdout.encode())
    dirty = subprocess.run(["git", "status", "--porcelain", "--", ".",
                            *[f":(exclude){d}" for d in DEV_KEY_EXCLUDE_DIRS],
                            ":(exclude,glob)**/*.md", ":(exclude)*.md"],
                           cwd=PROJECT_ROOT, capture_output=True, text=True,
                           check=True).stdout.strip() != ""
    return h.hexdigest(), dirty


def prune_dev_cache(dev_cache_dir: str, keep: int = DEV_CACHE_KEEP) -> None:
    """Remove all but the `keep` most recently used development builds."""
    try:
        entries = [os.path.join(dev_cache_dir, n) for n in os.listdir(dev_cache_dir)
                   if ".tmp." not in n]
        entries.sort(key=os.path.getmtime, reverse=True)
        for old in entries[keep:]:
            shutil.rmtree(old, ignore_errors=True)
    except OSError:
        pass


def dev_variants(skip: Sequence[str] = ()) -> list:
    """The entries of C_BUILD_VARIANTS that build_c_dev() builds: all but those named in skip."""
    return [v for v in C_BUILD_VARIANTS if v[0] not in skip]


def build_c_dev(output_dir: str, skip: Sequence[str] = ()) -> Tuple[str, ...]:
    """
    Compile C development version (current working source tree including uncommitted/current changes)
    in the configurations of C_BUILD_VARIANTS, except those whose short name is in skip
    (the default one cannot be skipped):
      default (softflowd / softflowctl), legacy (softflowd-legacy / softflowctl-legacy),
      static compat export (softflowd-static / ...), direct copies (softflowd-direct / ...)
    Returns [softflowd, softflowctl, ...] in the order of dev_variants(skip).
    The binaries are cached in CACHE_DIR under a hash of the build inputs, so
    an unchanged tree is not compiled again.
    """
    variants = dev_variants(skip)
    names = tuple(f"{b}{suffix}" for _, _, _, suffix in variants
                  for b in ("softflowd", "softflowctl"))
    cache_entry = None
    if helper.CACHE_DIR:
        try:
            key, dirty = dev_cache_key()
        except (OSError, subprocess.CalledProcessError) as e:
            print_yellow(f"Warning: cannot compute the development build cache key ({e}); "
                         "building without the cache")
        else:
            dev_cache_dir = os.path.join(helper.CACHE_DIR, "dev")
            cache_entry = os.path.join(dev_cache_dir, key[:16])
            state = "uncommitted changes" if dirty else "same as HEAD"
            cached = None if helper.REBUILD_DEV else cached_binaries(cache_entry, names,
                                                              output_dir)
            if cached:
                print_cyan(f"\n[Build] Using cached C development binaries "
                           f"(key {key[:12]}, {state}): {cache_entry}")
                return cached
            print_cyan(f"\n[Build] Compiling C development version (current source tree; "
                       f"key {key[:12]}, {state})...")
    if cache_entry is None:
        print_cyan("\n[Build] Compiling C development version (current source tree)...")
    paths = tuple(build_c_variants(PROJECT_ROOT, output_dir, "C development", "",
                                   variants))
    if cache_entry:
        store_binary_cache(cache_entry, paths, "development")
        prune_dev_cache(os.path.dirname(cache_entry))
    return paths


def build_cpp(output_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Compile C++ version in cpp/build using cmake."""
    print_cyan("\n[Build] Compiling C++ binaries (cpp/)...")
    cpp_dir = os.path.join(PROJECT_ROOT, "cpp")
    build_dir = os.path.join(cpp_dir, "build")
    os.makedirs(build_dir, exist_ok=True)

    res = run_command(["cmake", ".."], cwd=build_dir)
    if res.returncode != 0:
        print_yellow("Warning: cmake configuration failed for C++ version.")
        return None, None

    res = run_command(["make", "-j"], cwd=build_dir)
    if res.returncode != 0:
        print_yellow("Warning: make failed for C++ version.")
        return None, None

    cpp_daemon = os.path.join(build_dir, "softflowd+")
    cpp_ctl = os.path.join(build_dir, "softflowctl+")

    dest_daemon = os.path.join(output_dir, "softflowd+")
    dest_ctl = os.path.join(output_dir, "softflowctl+")

    if os.path.exists(cpp_daemon):
        shutil.copy2(cpp_daemon, dest_daemon)
    else:
        dest_daemon = None

    if os.path.exists(cpp_ctl):
        shutil.copy2(cpp_ctl, dest_ctl)
    else:
        dest_ctl = None

    return dest_daemon, dest_ctl


def build_rust(output_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Compile Rust version in rust/ using cargo build."""
    print_cyan("\n[Build] Compiling Rust binaries (rust/)...")
    rust_dir = os.path.join(PROJECT_ROOT, "rust")
    if not os.path.exists(rust_dir):
        return None, None

    res = run_command(["cargo", "build", "--release"], cwd=rust_dir)
    if res.returncode != 0:
        print_yellow("Warning: cargo build --release failed for Rust version.")
        return None, None

    rust_daemon = os.path.join(rust_dir, "target", "release", "rsoftflowd")
    rust_ctl = os.path.join(rust_dir, "target", "release", "rsoftflowctl")

    dest_daemon = os.path.join(output_dir, "rsoftflowd")
    dest_ctl = os.path.join(output_dir, "rsoftctl")

    if os.path.exists(rust_daemon):
        shutil.copy2(rust_daemon, dest_daemon)
    else:
        dest_daemon = None

    if os.path.exists(rust_ctl):
        shutil.copy2(rust_ctl, dest_ctl)
    else:
        dest_ctl = None

    return dest_daemon, dest_ctl
