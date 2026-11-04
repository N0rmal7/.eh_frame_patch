# -*- coding: utf-8 -*-
"""Build the release archive for eh_frame_patch.

Produces two artefacts next to this script's parent directory:

  dist/eh_frame_patch-1.0.0.zip              full package (source + docs + tests + samples)
  dist/eh_frame_patch-1.0.0-ida-only.zip     only what has to be copied into IDA

Usage::

    python packaging/build_release.py

The script is deterministic (fixed timestamps, sorted entries) so archives can
be compared byte for byte between builds.
"""

from __future__ import annotations

import os
import sys
import zipfile

VERSION = "1.0.1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")

#: everything under these stays out of the archives
EXCLUDE_DIRS = {"evidence","__pycache__", "dist", ".git", ".idea", "out"}
EXCLUDE_EXT = {".pyc", ".pyo", ".log", ".i64", ".id0", ".id1", ".id2", ".nam", ".til"}

#: files that must be copied into IDA's plugins directory
IDA_ONLY = [
    "plugins/eh_frame_patch.py",
    "plugins/ehp/__init__.py",
    "plugins/ehp/asm_engine.py",
    "plugins/ehp/disasm_preview.py",
    "plugins/ehp/elf_image.py",
    "plugins/ehp/plan.py",
]


def walk(base, only=None, strip_prefix=""):
    """Yield relative paths to package, sorted, filtered.

    ``strip_prefix`` removes a leading directory from the archive names so the
    IDA-only archive can be extracted straight into the plugins directory.
    """
    if only is not None:
        for rel in only:
            full = os.path.join(base, rel)
            if os.path.isfile(full):
                arc = rel
                if strip_prefix and arc.startswith(strip_prefix):
                    arc = arc[len(strip_prefix):]
                yield rel, arc
        return
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in EXCLUDE_EXT:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            arc = rel
            if strip_prefix and arc.startswith(strip_prefix):
                arc = arc[len(strip_prefix):]
            yield rel, arc


def write_zip(path, base, pairs, prefix):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, arc in pairs:
            full = os.path.join(base, rel)
            name = "%s/%s" % (prefix, arc) if prefix else arc
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if rel.startswith("samples/") and "/src/" not in rel else 0o644) << 16
            with open(full, "rb") as fh:
                zf.writestr(info, fh.read())
    return path


def main():
    os.makedirs(DIST, exist_ok=True)
    prefix = "eh_frame_patch-%s" % VERSION

    full = write_zip(
        os.path.join(DIST, "%s.zip" % prefix),
        ROOT,
        list(walk(ROOT)),
        prefix,
    )
    # ida-only: drop the leading "plugins/" so the archive can be extracted
    # directly into <IDA plugins dir> (resulting in plugins\ehp\, plugins\*.py)
    ida = write_zip(
        os.path.join(DIST, "%s-ida-only.zip" % prefix),
        ROOT,
        list(walk(ROOT, only=IDA_ONLY, strip_prefix="plugins/")),
        "",
    )

    for path in (full, ida):
        size = os.path.getsize(path)
        with zipfile.ZipFile(path) as zf:
            count = len(zf.namelist())
        print("%-52s %6d file(s)  %7.1f KiB" % (os.path.basename(path), count, size / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
