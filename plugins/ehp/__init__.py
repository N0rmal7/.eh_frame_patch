"""ehp - core logic for the eh_frame_patch IDA plugin.

This package deliberately does **not** import any IDA module, so that the
assembly / planning / ELF-export logic can be unit tested outside of IDA with a
plain CPython interpreter.  The IDA glue lives in ``eh_frame_patch.py``.

Modules
-------
asm_engine       Keystone wrapper: labels, comments, IDA symbol resolution and
                 precise "which source line failed" diagnostics.
plan             Budget / segment / cross-segment checks and NOP padding.
elf_image        Minimal, dependency free ELF32/ELF64 reader + patched-copy
                 writer (used by the "export executable copy" feature).
disasm_preview   Optional Capstone powered preview of assembled bytes.
"""

from __future__ import annotations

__all__ = ["asm_engine", "plan", "elf_image", "disasm_preview"]

__version__ = "1.0.1"
