# -*- coding: utf-8 -*-
"""eh_frame_patch -- Keypatch companion for IDA Pro 9.0.

Keypatch refuses to assemble into segments IDA does not consider code, which
makes the classic AWDP-pwn trick ("put the fix in .eh_frame, jmp to it from the
bug site") impossible.  This plugin provides an equivalent editor that works on
*any* mapped address: data segments, .eh_frame, undefined bytes.

Scope of v1
-----------
* x86 / x86-64, Intel syntax, Keystone engine (same engine Keypatch uses).
* Standalone: it does not import, patch or otherwise touch keypatch.py, so both
  plugins can be installed side by side.
* Patches go through IDA's patching API so they end up in the .idb and in the
  produced binary; the patched region is re-analysed as instructions *only* if
  the user asks for it, and never for the whole segment.
* An extra export writes a *copy* of the input ELF with PF_X set on the
  PT_LOAD that holds .eh_frame (the "make it really executable" step).

Hotkeys
-------
Ctrl-Alt-J         open the patcher on the current address / selection
Ctrl-Alt-Shift-J   export an executable copy (ELF only)
"""

from __future__ import annotations

import os
import sys
import traceback

import idaapi
import idc
import ida_bytes
import ida_segment
import ida_ua
import ida_auto
import ida_kernwin
import ida_loader
import ida_name
import ida_lines
import ida_ida
import ida_nalt
import ida_dbg
import ida_funcs
import idautils

PLUGIN_VERSION = "1.0.0"

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from ehp import (  # noqa: E402
    aligned_heads,
    asm_engine,
    disasm_preview,
    elf_image,
    plan as plan_mod,
    unwind_cave,
    unwind_probe,
)
from ehp.plan import Check, SegPerm, Segment  # noqa: E402

ACTION_PATCH = "eh_frame_patch:patch"
ACTION_EXPORT = "eh_frame_patch:export"
ACTION_INFO = "eh_frame_patch:info"
ACTION_UNDO = "eh_frame_patch:undo"
ACTION_PREVIEW = "eh_frame_patch:preview"
ACTION_STUB = "eh_frame_patch:stub"
ACTION_MARK_EXEC = "eh_frame_patch:markexec"

MAX_ADDR_LEN = 40
MAX_ASM_LEN = 8192

#: history of applied patches for the "Undo last patch" action.
_patch_history = []

#: every (address, length) this plugin has written in this session, used so the
#: export only contains *our* patches.  A whole-database diff is not usable:
#: IDA resolves PLT/GOT pointers while loading, so large parts of .got differ
#: from the file without anyone having patched them.
_written_ranges = []


# ---------------------------------------------------------------------------
# IDA memory adapter
# ---------------------------------------------------------------------------
def _seg_name(seg):
    try:
        return ida_segment.get_segm_name(seg) or ""
    except Exception:
        return ""


def _seg_class(seg):
    try:
        return ida_segment.get_segm_class(seg) or ""
    except Exception:
        return ""


def _seg_is_code(seg):
    try:
        return ida_segment.get_segm_class(seg) == "CODE"
    except Exception:
        return False


class IdaMemory(object):
    """Implements the memory map protocol expected by :mod:`ehp.plan`."""

    def is_mapped(self, ea):
        try:
            return bool(ida_bytes.is_mapped(ea))
        except Exception:
            return False

    def segment_at(self, ea):
        if not self.is_mapped(ea):
            return None
        try:
            seg = ida_segment.getseg(ea)
        except Exception:
            seg = None
        if seg is None:
            return None
        return Segment(
            _seg_name(seg),
            int(seg.start_ea),
            int(seg.end_ea),
            int(seg.perm),
            _seg_is_code(seg),
            _seg_class(seg),
        )

    def read(self, ea, size):
        if size <= 0:
            return b""
        try:
            data = ida_bytes.get_bytes(ea, size)
        except Exception:
            data = None
        if data is None:
            return b""
        return data

    def resolve_symbol(self, name):
        """Turn an IDA name into an address for Keystone."""
        try:
            ea = idc.get_name_ea_simple(name)
        except Exception:
            ea = idc.BADADDR
        if ea is None or ea == idc.BADADDR:
            return None
        return int(ea)

    def bits(self):
        try:
            return 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit() else 16)
        except Exception:
            try:
                return 64 if idaapi.get_inf_structure().is_64bit() else 32
            except Exception:
                return 64


MEM = IdaMemory()


def _current_bits():
    return MEM.bits()


def _is_supported_arch():
    try:
        proc = ida_ida.inf_get_procname() or ""
    except Exception:
        try:
            proc = idaapi.get_inf_structure().procname
        except Exception:
            proc = ""
    return proc.lower() in ("metapc", "80386p", "80386r", "80486p", "80486r",
                            "80586p", "80586r", "80686p", "p2", "p3", "p4",
                            "x86", "x64")


# ---------------------------------------------------------------------------
# formatting helpers
# ---------------------------------------------------------------------------
def hexbytes(data, limit=None):
    if data is None:
        return ""
    blob = data if limit is None else data[:limit]
    text = " ".join("%02X" % b for b in bytearray(blob))
    if limit is not None and len(data) > limit:
        text += " ..."
    return text


def fmt_addr(ea):
    try:
        return "0x%X" % int(ea)
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# patch application
# ---------------------------------------------------------------------------
class ApplyResult(object):
    def __init__(self):
        self.ok = False
        self.message = ""
        self.orig = b""
        self.written = b""
        self.ea = 0
        self.reanalyzed = False


def apply_patch(plan, reanalyze=True):
    """Write ``plan.padded`` at ``plan.ea`` through IDA's patching API."""
    res = ApplyResult()
    res.ea = plan.ea
    if not plan.ok:
        res.message = "plan contains errors; nothing written"
        return res
    if ida_dbg.is_debugger_on():
        res.message = "stop the debugger before applying database/file patches"
        return res
    blob = plan.padded or plan.code
    if not blob:
        res.message = "nothing to write"
        return res

    # Refuse to write outside the database.
    if not MEM.is_mapped(plan.ea) or not MEM.is_mapped(plan.ea + len(blob) - 1):
        res.message = "target range is not mapped"
        return res

    orig = MEM.read(plan.ea, len(blob))
    if len(orig) != len(blob):
        res.message = "cannot read the original bytes at 0x%X" % plan.ea
        return res
    if orig != plan.orig_bytes:
        res.message = "bytes changed since preview; preview again before patching"
        return res
    if not all(MEM.is_mapped(addr) for addr in range(plan.ea, plan.ea + len(blob))):
        res.message = "patch range contains unmapped bytes"
        return res
    res.orig = orig

    try:
        ida_bytes.patch_bytes(plan.ea, bytes(blob))
        if MEM.read(plan.ea, len(blob)) != bytes(blob):
            raise RuntimeError("patch read-back mismatch")
    except Exception as exc:
        res.message = "patch failed: %s" % exc
        try:
            ida_bytes.patch_bytes(plan.ea, orig)
            if MEM.read(plan.ea, len(orig)) != orig:
                raise RuntimeError("rollback read-back mismatch")
            res.message += "; original bytes restored"
        except Exception as rollback_error:
            res.message += "; ROLLBACK FAILED: %s; inspect database bytes" % rollback_error
        return res

    res.written = bytes(blob)
    res.ok = True
    res.message = "patched %d byte(s) at 0x%X" % (len(blob), plan.ea)

    _patch_history.append(
        {
            "ea": plan.ea,
            "orig": orig,
            "new": bytes(blob),
            "source": plan.source,
            "imagebase": ida_nalt.get_imagebase(),
        }
    )
    _written_ranges.append((plan.ea, len(blob)))
    if reanalyze:
        try:
            res.reanalyzed = reanalyze_region(plan.ea, len(blob), plan.bits)
        except Exception as exc:
            res.message += "; bytes saved, code conversion failed: %s" % exc
    return res


def reanalyze_region(ea, size, bits=64):
    """Turn the patched bytes into instructions, without touching the rest.

    Deliberately narrow: only ``[ea, ea+size)`` is converted.  A whole-segment
    "make code" would destroy the surrounding .eh_frame data.
    """
    end = ea + size
    # del_items deletes entire items. Do not destroy a surrounding structure.
    for addr in (ea, end - 1):
        flags = ida_bytes.get_full_flags(addr)
        if not ida_bytes.is_unknown(flags):
            if ida_bytes.get_item_head(addr) < ea or ida_bytes.get_item_end(addr) > end:
                return False
    cur = ea
    while cur < end:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, cur)
        if length <= 0 or cur + length > end:
            return False
        cur += length
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
        return False
    cur = ea
    while cur < end:
        got = ida_ua.create_insn(cur)
        if not got or cur + got > end:
            return False
        cur += got
    ida_kernwin.refresh_idaview_anyway()
    return cur == end


# ---------------------------------------------------------------------------
# preview rendering
# ---------------------------------------------------------------------------
def render_preview(plan, show_orig=True):
    """Build the text shown in the preview pane."""
    out = []
    seg = plan.segment
    if seg is not None:
        out.append(
            "target    : %s  (%s-%s, perm=%s%s)"
            % (
                fmt_addr(plan.ea),
                fmt_addr(seg.start),
                fmt_addr(seg.end),
                SegPerm.text(seg.perm),
                ", CODE" if seg.is_code else "",
            )
        )
    else:
        out.append("target    : %s (unmapped)" % fmt_addr(plan.ea))
    out.append(
        "budget    : %d byte(s)   used: %d   padding: %d"
        % (plan.budget, plan.size, plan.pad_len)
    )
    out.append("entry     : %s" % fmt_addr(plan.entry))
    if plan.return_ea is not None:
        out.append("return to : %s" % fmt_addr(plan.return_ea))
    else:
        out.append("return to : (not set)")

    if plan.padded:
        out.append("")
        out.append("machine code (%d bytes):" % len(plan.padded))
        out.extend(_wrap_hex(plan.padded[:512]))
        if len(plan.padded) > 512:
            out.append("  ... preview limited to first 512 bytes")

    if plan.code:
        text = disasm_preview.format_disassembly(plan.code[:512], plan.ea, plan.bits)
        out.append("")
        if text:
            out.append("disassembly:")
            out.extend("  " + line for line in text.split("\n"))
        elif plan.pieces:
            out.append("disassembly:")
            for off, length, line in plan.pieces:
                out.append(
                    "  %016X  %-20s  %s"
                    % (plan.ea + off, hexbytes(plan.code[off : off + length]), line.strip())
                )

    if show_orig and plan.orig_bytes:
        out.append("")
        out.append("original bytes being overwritten (%d):" % len(plan.orig_bytes))
        out.extend(_wrap_hex(plan.orig_bytes[:512]))
        prev = disasm_preview.format_disassembly(plan.orig_bytes[:512], plan.ea, plan.bits)
        if prev:
            out.append("original disassembly:")
            out.extend("  " + line for line in prev.split("\n"))

    out.append("")
    if plan.asm is not None and getattr(plan.asm, "empty", False):
        out.append("nothing to assemble yet.")
        out.append("")
        out.append("Suggested UAF fix (edit the two addresses to match this binary):")
        for line in (
            "  mov eax, dword ptr [rbp-4]       ; index kept by the vulnerable function",
            "  cdqe",
            "  lea rdx, [<&array>]              ; write the ABSOLUTE address",
            "  mov qword ptr [rdx + rax*8], 0   ; array[idx] = NULL  <-- the fix",
            "  jmp <resume>                     ; back to the original epilogue",
        ):
            out.append(line)
        out.append("")
        out.append("  Clearing a register is NOT enough: clear the slot that holds")
        out.append("  the dangling pointer. Never overwrite a shared leave/ret.")
        out.append("")
    out.append("checks:")
    for chk in plan.checks:
        tag = {Check.OK: "ok   ", Check.WARN: "warn ", Check.ERROR: "ERROR"}[chk.level]
        out.append("  [%s] %s" % (tag, chk.text))
    return "\n".join(out)


def _wrap_hex(blob, per_line=16):
    lines = []
    for i in range(0, len(blob), per_line):
        lines.append("  " + " ".join("%02X" % b for b in bytearray(blob[i : i + per_line])))
    return lines


# ---------------------------------------------------------------------------
# preview window
# ---------------------------------------------------------------------------
class PreviewViewer(ida_kernwin.simplecustviewer_t):
    """Read-only, dockable preview of the pending patch.

    A second ``MultiLineTextControl`` inside the editor form makes IDA 9.0
    compute a bogus window height (observed: 52390 px), so the preview lives in
    its own viewer widget instead.  It also lets the user keep the preview open
    next to the disassembly while editing.
    """

    def __init__(self):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self._created = False
        self._title = "eh_frame_patch preview"

    def ensure(self):
        if not self._created:
            try:
                self._created = bool(self.Create(self._title))
            except Exception:
                return False
        return self._created

    def set_text(self, text, errors=0):
        if not self.ensure():
            return False
        try:
            self.ClearLines()
            for line in (text or "").split("\n"):
                if line.startswith("  [ERROR]"):
                    self.AddLine(ida_lines.COLSTR(line, ida_lines.SCOLOR_ERROR))
                elif line.startswith("  [warn"):
                    self.AddLine(ida_lines.COLSTR(line, ida_lines.SCOLOR_AUTOCMT))
                elif line.startswith("  [ok"):
                    self.AddLine(ida_lines.COLSTR(line, ida_lines.SCOLOR_DATNAME))
                else:
                    self.AddLine(line)
            self.Refresh()
        except Exception:
            return False
        return True

    def OnClose(self):
        self._created = False

    def show(self):
        if self.ensure():
            try:
                self.Show()
            except Exception:
                pass

    def close(self):
        if self._created:
            try:
                self.Close()
            except Exception:
                pass
            self._created = False


#: the single preview window reused across invocations.
_PREVIEW = None


def preview_viewer():
    global _PREVIEW
    if _PREVIEW is None:
        _PREVIEW = PreviewViewer()
    return _PREVIEW


# ---------------------------------------------------------------------------
# main form
# ---------------------------------------------------------------------------
class PatchForm:
    """Qt editor: explicit inputs, visible preview, no native Form layout tricks."""

    def __init__(self, ea, budget=None, source="", return_ea=None):
        from PyQt5 import QtCore, QtGui, QtWidgets
        self.bits = _current_bits()
        self.mem = MEM
        self._plan = None
        self._accepted_reanalyze = False
        self._patch_done = False
        seg = self.mem.segment_at(ea)
        if budget is None:
            budget = min(32, seg.end - ea) if seg else 16
        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("eh_frame_patch v%s -- assemble anywhere (%d)" % (PLUGIN_VERSION, self.bits))
        self.dialog.resize(960, 680)
        layout = QtWidgets.QVBoxLayout(self.dialog)
        inputs = QtWidgets.QFormLayout()
        self.c_addr = QtWidgets.QLineEdit(fmt_addr(ea))
        self.c_budget = QtWidgets.QLineEdit(str(budget))
        self.c_ret = QtWidgets.QLineEdit("" if return_ea is None else fmt_addr(return_ea))
        self.c_ret.setPlaceholderText("Optional; documentation only, does not generate a jump")
        self.c_seg = QtWidgets.QLabel()
        inputs.addRow("Target VA (hex)", self.c_addr)
        inputs.addRow("Overwrite budget (decimal bytes)", self.c_budget)
        inputs.addRow("Declared return VA (hex)", self.c_ret)
        inputs.addRow("IDA segment", self.c_seg)
        layout.addLayout(inputs)
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.c_asm = QtWidgets.QPlainTextEdit(source)
        self.c_asm.setPlaceholderText("Intel syntax; one instruction per line; ; starts a comment")
        self.c_preview = QtWidgets.QPlainTextEdit()
        self.c_preview.setReadOnly(True)
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.c_asm.setFont(font)
        self.c_preview.setFont(font)
        self.c_preview.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        for title, editor in (("Assembly", self.c_asm), ("Preview / overwritten bytes / checks", self.c_preview)):
            pane = QtWidgets.QWidget()
            inner = QtWidgets.QVBoxLayout(pane)
            inner.setContentsMargins(0, 0, 0, 0)
            inner.addWidget(QtWidgets.QLabel(title))
            inner.addWidget(editor)
            split.addWidget(pane)
        split.setSizes([380, 580])
        layout.addWidget(split, 1)
        self.c_reanalyze = QtWidgets.QCheckBox("Convert patched range to code if item boundaries permit")
        self.c_reanalyze.setChecked(True)
        self.c_pad = QtWidgets.QCheckBox("NOP-pad to the full budget (overwrites every budget byte)")
        self.c_cross = QtWidgets.QCheckBox("Allow segment crossing (all bytes must remain mapped)")
        for box in (self.c_reanalyze, self.c_pad, self.c_cross):
            layout.addWidget(box)
        self.c_status = QtWidgets.QLabel()
        layout.addWidget(self.c_status)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        self.patch_button = buttons.button(QtWidgets.QDialogButtonBox.Ok)
        self.patch_button.setText("Patch")
        self.patch_button.setAutoDefault(False)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.dialog.reject)
        layout.addWidget(buttons)
        self._timer = QtCore.QTimer(self.dialog)
        self._timer.setSingleShot(True)
        self._timer.setInterval(180)
        self._timer.timeout.connect(self._refresh)
        for field in (self.c_addr, self.c_budget, self.c_ret):
            field.textChanged.connect(self._queue_refresh)
        self.c_asm.textChanged.connect(self._queue_refresh)
        for box in (self.c_reanalyze, self.c_pad, self.c_cross):
            box.toggled.connect(self._queue_refresh)
        self._refresh()

    def _queue_refresh(self, *_):
        self.patch_button.setEnabled(False)
        self.c_status.setText("Preview pending...")
        self._timer.start()

    def _opt_flags(self):
        return (self.c_reanalyze.isChecked(), self.c_pad.isChecked(), self.c_cross.isChecked())

    def _refresh(self):
        self._timer.stop()
        try:
            ea = int(self.c_addr.text().strip(), 16)
            budget = int(self.c_budget.text().strip(), 10)
            ret_text = self.c_ret.text().strip()
            ret = int(ret_text, 16) if ret_text else None
            source = self.c_asm.toPlainText()
            if ea < 0 or (ret is not None and ret < 0):
                raise ValueError("addresses must be nonnegative")
            if len(source) > MAX_ASM_LEN:
                raise ValueError("assembly input exceeds %d characters" % MAX_ASM_LEN)
            rean, pad, cross = self._opt_flags()
            self._plan = plan_mod.build_plan(self.mem, ea, source, bits=self.bits,
                budget=budget, resolve=self.mem.resolve_symbol, nop_pad=pad,
                allow_cross_segment=cross, return_ea=ret)
            self.c_preview.setPlainText(render_preview(self._plan))
            seg = self._plan.segment
            self.c_seg.setText("%s  %s..%s  %s" % (seg.name, fmt_addr(seg.start),
                fmt_addr(seg.end), SegPerm.text(seg.perm)) if seg else "unmapped")
            self.patch_button.setEnabled(self._plan.ok)
            self.c_status.setText("%d code bytes + %d NOP bytes; %d errors, %d warnings" % (
                self._plan.size, self._plan.pad_len, len(self._plan.errors), len(self._plan.warnings)))
        except (ValueError, OverflowError) as exc:
            self._plan = None
            self.patch_button.setEnabled(False)
            self.c_status.setText(str(exc))
            self.c_preview.setPlainText("Invalid input: %s" % exc)
        return self._plan

    def _accept(self):
        plan = self._refresh()
        if plan is None or not plan.ok:
            return
        if plan.warnings and ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
            "Apply %d bytes at 0x%X?\n\n%s" % (len(plan.padded), plan.ea, plan.summary())) != ida_kernwin.ASKBTN_YES:
            return
        self._accepted_reanalyze = self.c_reanalyze.isChecked()
        self.dialog.accept()

    def Execute(self):
        return self.dialog.exec_()

    def Free(self):
        self._timer.stop()
        self.dialog.deleteLater()

    def plan(self):
        return self._plan


def _seg_name_safe(seg):
    if seg is None:
        return "?"
    return seg.name or "?"


# ---------------------------------------------------------------------------
# export executable copy
# ---------------------------------------------------------------------------
def export_executable_copy(ea, patches=None):
    """Write a copy of the input file with PF_X on the .eh_frame PT_LOAD.

    *ea* only decides which PT_LOAD gets ``PF_X`` when no ``.eh_frame`` section
    exists; normally we target ``.eh_frame`` explicitly so the export works no
    matter where the cursor happens to be.
    """
    src = ida_nalt.get_input_file_path()
    if not src or not os.path.isfile(src):
        ida_kernwin.warning("eh_frame_patch: cannot locate the input file")
        return None
    try:
        img = elf_image.ElfImage.from_file(src)
    except elf_image.ElfError as exc:
        ida_kernwin.warning("eh_frame_patch: not an ELF file: %s" % exc)
        return None

    converted = []
    try:
        for patch_ea, blob in patches or []:
            for i, value in enumerate(blob):
                off = ida_loader.get_fileregion_offset(patch_ea + i)
                va = img.offset_to_vaddr(off)
                if off < 0 or va is None:
                    raise elf_image.ElfError("patch at 0x%X has no PT_LOAD file mapping" % (patch_ea + i))
                original = ida_bytes.get_original_byte(patch_ea + i)
                if img.data[off] not in (original, value):
                    raise elf_image.ElfError("input file differs from IDB original at offset 0x%X" % off)
                if converted and converted[-1][0] + len(converted[-1][1]) == va:
                    converted[-1][1].append(value)
                else:
                    converted.append((va, bytearray([value])))
    except elf_image.ElfError as exc:
        ida_kernwin.warning(str(exc))
        return None

    # Pick the address whose PT_LOAD should become executable: prefer the
    # .eh_frame section, fall back to the caller's address.
    target = img.offset_to_vaddr(ida_loader.get_fileregion_offset(ea))
    eh_sec = img.section(".eh_frame")
    if eh_sec is not None and img.load_at(eh_sec.addr) is not None:
        target = eh_sec.addr
    else:
        seg = MEM.segment_at(ea)
        if seg is not None and (target is None or img.load_at(target) is None):
            sec = img.section(seg.name)
            if sec is not None:
                target = sec.addr

    default_name = os.path.splitext(os.path.basename(src))[0] + "_exe"
    out = ida_kernwin.ask_str(
        os.path.join(os.path.dirname(src), default_name), 0, "Save executable copy as"
    )
    if not out:
        return None

    if os.path.exists(out):
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Replace existing export?\n%s" % out) != ida_kernwin.ASKBTN_YES:
            return None
    load = img.load_at(target) if target is not None else None
    if load is None:
        ida_kernwin.warning("No file-backed PT_LOAD found for the execution target")
        return None
    if not load.flags & elf_image.PF_X:
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
            "Add execute permission to entire PT_LOAD #%d (%s)?\nThis affects all sections in this load segment."
            % (load.index, load.perm_text)) != ida_kernwin.ASKBTN_YES:
            return None
    try:
        img2, applied = elf_image.clone_with_patches(
            src, out, [(va, bytes(blob)) for va, blob in converted], make_exec=target
        )
    except Exception:
        ida_kernwin.warning(
            "eh_frame_patch: export failed:\n%s" % traceback.format_exc()
        )
        return None

    load = img2.load_at(target)
    msg = ["Wrote %s" % out]
    if load is not None:
        msg.append(
            "PT_LOAD #%d is now %s (PF_X %s)"
            % (
                load.index,
                load.perm_text,
                "set" if load.flags & elf_image.PF_X else "clear",
            )
        )
    if applied:
        total = sum(n for _v, n in applied)
        msg.append(
            "applied %d change run(s), %d byte(s) total, from the database"
            % (len(applied), total)
        )
        for vaddr, size in applied[:12]:
            msg.append("  0x%X  %d byte(s)" % (vaddr, size))
        if len(applied) > 12:
            msg.append("  ... and %d more" % (len(applied) - 12))
    else:
        msg.append("no differences from the input file were found")
    msg.append("")
    msg.append("The original file was not modified.")
    ida_kernwin.info("\n".join(msg))
    return out


def collect_db_patches(ea, size):
    """Read the current bytes from the database so the export matches the idb."""
    data = MEM.read(ea, size)
    return [(ea, data)] if data else []


def collect_all_db_changes():
    """Enumerate explicit IDA patches, including Keypatch and reopened IDBs.

    Loader fixups are not inferred by a database/file diff. File offsets are
    translated during export so rebased IDBs remain supported.
    """
    changes = []
    def visit(ea, fpos, original, patched):
        if fpos < 0 or fpos >= (1 << 63):
            raise elf_image.ElfError("patched address 0x%X has no file offset" % ea)
        if changes and changes[-1][0] + len(changes[-1][1]) == ea:
            start, blob = changes[-1]
            changes[-1] = (start, blob + bytes([patched]))
        else:
            changes.append((ea, bytes([patched])))
        return 0
    rc = ida_bytes.visit_patched_bytes(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), visit)
    if rc:
        raise elf_image.ElfError("patch enumeration did not complete")
    return changes


def show_permission_report(ea):
    """Explain IDA-segment vs ELF-file permissions for *ea*."""
    src = ida_nalt.get_input_file_path()
    lines = []
    seg = MEM.segment_at(ea)
    if seg is None:
        lines.append("0x%X is not mapped in the database" % ea)
    else:
        lines.append(
            "IDA segment %s: %s-%s perm=%s%s"
            % (
                seg.name,
                fmt_addr(seg.start),
                fmt_addr(seg.end),
                SegPerm.text(seg.perm),
                " (class CODE)" if seg.is_code else "",
            )
        )
        lines.append(
            "IDA permissions only affect how the database is browsed and "
            "whether the disassembler treats bytes as code."
        )
    lines.append("")
    if src and os.path.isfile(src):
        try:
            img = elf_image.ElfImage.from_file(src)
        except Exception as exc:
            lines.append("cannot parse %s: %s" % (src, exc))
            img = None
        if img is not None:
            vaddr = img.offset_to_vaddr(ida_loader.get_fileregion_offset(ea))
            if vaddr is None:
                raise elf_image.ElfError("current address has no PT_LOAD file mapping")
            if img.load_at(vaddr) is None and seg is not None:
                sec = img.section(seg.name)
                if sec is not None:
                    vaddr = sec.addr
            lines.append("ELF view of %s:" % os.path.basename(src))
            lines.append("")
            lines.append(img.describe())
            lines.append("")
            lines.append(
                elf_image.format_permission_report(img, vaddr, seg.name if seg else "?")
            )
    else:
        lines.append("input file not available; ELF permissions cannot be checked")
    ida_kernwin.info("\n".join(lines))


# ---------------------------------------------------------------------------
# plugin entry points
# ---------------------------------------------------------------------------
def show_preview(ea=None):
    """Open (or refresh) the standalone preview window for *ea*.

    The preview is a separate read-only widget rather than a second
    MultiLineTextControl inside the editor form, because IDA 9.0 cannot lay out
    two of them in one form (see docs/IDA_NOTES.md).
    """
    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    seg = MEM.segment_at(ea)
    budget = min(32, seg.end - ea) if seg else 16
    plan = plan_mod.build_plan(
        MEM,
        ea,
        "",
        bits=_current_bits(),
        budget=budget,
        resolve=MEM.resolve_symbol,
    )
    plan.entry = ea
    pv = preview_viewer()
    pv.set_text(render_preview(plan))
    pv.show()
    return plan


def open_patcher(ea=None):
    if not _is_supported_arch():
        ida_kernwin.warning(
            "eh_frame_patch v1 only supports x86 / x86-64 databases"
        )
        return
    if not asm_engine.keystone_available():
        ida_kernwin.warning(
            "eh_frame_patch: the Keystone engine is missing.\n"
            "Install 'keystone-engine' into IDA's Python, see docs/INSTALL.md"
        )
        return

    if ea is None:
        ea = ida_kernwin.get_screen_ea()

    budget = None
    source = ""
    ret = None
    # If the user selected a range, treat it as the budget and as the place to
    # write (matching Keypatch's "Fill Range" behaviour).
    try:
        sel, a, b = ida_kernwin.read_range_selection(None)
        if sel and b > a:
            ea = a
            budget = b - a
    except Exception:
        pass

    source = _suggest_source(ea)
    try:
        form = PatchForm(ea, budget=budget, source=source, return_ea=ret)
    except Exception:
        ida_kernwin.warning("eh_frame_patch: form failed:\n%s" % traceback.format_exc())
        return

    try:
        ok = form.Execute()
        plan = form._plan
        reanalyze = getattr(form, "_accepted_reanalyze", False)
    finally:
        form.Free()
    if ok != 1 or plan is None or not plan.ok:
        return
    result = apply_patch(plan, reanalyze=reanalyze)
    if not result.ok:
        ida_kernwin.warning("eh_frame_patch: %s" % result.message)
        return
    ida_kernwin.info(
        "%s\n%s\n\noriginal: %s"
        % (
            result.message,
            "re-analysed as instructions" if result.reanalyzed else "bytes saved; code conversion not completed (existing items or instruction boundary)",
            hexbytes(result.orig, 32),
        )
    )
    try:
        ida_kernwin.jumpto(plan.ea)
    except Exception:
        pass


def _eh_frame_segment():
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s is not None and _seg_name(s) == ".eh_frame":
            return s
    return None


def _pc_is_live(pc, rng):
    """Is this FDE describing a function that still exists and can run?"""
    if rng == 0:
        return False
    try:
        seg = ida_segment.getseg(pc)
    except Exception:
        seg = None
    if seg is None:
        return False
    return bool(seg.perm & ida_segment.SEGPERM_EXEC)


def find_safe_areas(want=0):
    """Return ranked overwrite candidates inside .eh_frame.

    ``want`` is how many bytes the caller needs; merged (record-spanning)
    candidates are only produced when the per-record padding cannot satisfy it.
    """
    seg = _eh_frame_segment()
    if seg is None:
        return []
    start, end = int(seg.start_ea), int(seg.end_ea)
    data = MEM.read(start, end - start)
    if not data:
        return []
    cands = unwind_cave.find_candidates(data, start, is_pc_live=_pc_is_live)

    # Always offer merged spans when nothing cost-free is big enough: a
    # level-3 span of the right size is more useful than a level-2 candidate
    # that is too small, but keep the cheaper candidates in the list too so the
    # user can see the trade-off.
    cheap_enough = any(
        c.level <= unwind_cave.Candidate.PADDING and c.size >= want for c in cands
    )
    if want and not cheap_enough:
        cands = cands + unwind_cave.find_merged_padding(data, start, want=want)

    # Rank by *cost first*, then by whether it is big enough, then by size.
    # Without this, a huge level-3 span would shadow a small level-2 padding
    # that costs far less.
    cands.sort(
        key=lambda c: (c.level, 0 if c.size >= want else 1, -c.size)
    )
    return cands


def suggest_stub_address(want=32):
    """Best place for a stub: returns ``(ea, budget, candidate)`` or None.

    Preference order: the cheapest level that is big enough; if no level is big
    enough, the cheapest level overall (the editor will show the overflow and
    the user can shorten the stub).
    """
    cands = find_safe_areas(want)
    if not cands:
        return None
    for cand in cands:
        if cand.size >= want:
            return (cand.ea, cand.size, cand)
    return (cands[0].ea, cands[0].size, cands[0])


def _elf_image_of_input():
    """Load the input file as an ElfImage, or None."""
    try:
        path = ida_nalt.get_input_file_path()
    except Exception:
        path = None
    if not path or not os.path.isfile(path):
        return None
    try:
        return elf_image.ElfImage.from_file(path)
    except Exception:
        return None


def _aligned_heads(want=0):
    """16-byte aligned writable heads in .eh_frame, biggest room first."""
    seg = _eh_frame_segment()
    if seg is None:
        return []
    start, end = int(seg.start_ea), int(seg.end_ea)
    data = MEM.read(start, end - start)
    if not data:
        return []
    heads = aligned_heads.find_writable_heads(data, start)
    if want:
        heads = [h for h in heads if h.room >= want] or heads
    heads.sort(key=lambda h: -h.room)
    return heads


def goto_safe_place(want=32):
    """Pick an overwrite head in .eh_frame and open the editor there.

    Priority is "pass the checker", so the decision is driven by whether the
    program ever unwinds at run time:

    * **No unwinding** (pure C, only libc): destroying CIE/FDE entries is
      invisible at run time, so the largest 16-byte aligned head is offered.
    * **Unwinds** (C++, libgcc_s, backtrace...): a destroyed CIE means SIGSEGV
      on the first throw, so only the record padding (a few bytes) is offered
      and the risk is spelled out.

    ``want`` is how many bytes the caller needs.
    """
    img = _elf_image_of_input()
    verdict = unwind_probe.verdict_for_image(img) if img is not None else None

    heads = _aligned_heads(want)
    if not heads:
        ida_kernwin.warning(
            "eh_frame_patch: .eh_frame has no writable area.\n\n"
            "Either the section is missing, or every 16-byte aligned head "
            "leaves less room than requested."
        )
        return

    best = heads[0]
    unsafe = bool(verdict and verdict.uses_unwinding)

    if unsafe:
        # Unwinding is live: prefer the cheap record padding when it is big
        # enough, and make the cost explicit.
        cheap = [c for c in find_safe_areas(want)
                 if c.level <= unwind_cave.Candidate.PADDING]
        if cheap:
            pick = cheap[0]
            ida_kernwin.info(
                "eh_frame_patch: this program unwinds at run time\n"
                "(%s)\n\n"
                "Using %s at %#x -- %d byte(s), %s.\n"
                "Overwriting a whole CIE/FDE would crash on the first "
                "exception, so the padding was preferred."
                % (verdict.summary(), pick.level_name, pick.ea, pick.size, pick.note)
            )
            try:
                ida_kernwin.jumpto(pick.ea)
            except Exception:
                pass
            open_patcher(pick.ea, budget=pick.size)
            return

        ida_kernwin.warning(
            "eh_frame_patch: this program unwinds at run time (%s),\n"
            "but .eh_frame has no record padding large enough for %d byte(s).\n\n"
            "Writing into a live CIE/FDE will crash the program on the first\n"
            "exception or backtrace. Consider a .text code cave or the jump\n"
            "stub approach instead."
            % (verdict.summary(), want)
        )
        # fall through: still offer the big head, but the user was warned

    # Safe case (no run-time unwinding) or the user accepted the risk.
    detail = []
    if verdict is not None:
        detail.append(verdict.summary())
    detail.append(
        "%#x leaves %d byte(s) up to the ZERO terminator" % (best.ea, best.room)
    )
    if best.records:
        detail.append(
            "it covers %d record(s); harmless here because nothing unwinds"
            % len(best.records)
            if not unsafe
            else "it covers %d record(s), including live unwind data"
            % len(best.records)
        )
    try:
        ida_kernwin.jumpto(best.ea)
    except Exception:
        pass
    open_patcher(best.ea, budget=best.room)
    print("eh_frame_patch: " + " | ".join(detail))


def _guess_uaf_template(ea):
    """Build a *generic* "clear the dangling pointer" stub skeleton.

    This is deliberately **not** tailored to one binary.  The shape is the
    common one for heap-slot UAF fixes::

        # load the index the vulnerable function used
        # (the slot is found by analysis; if unsure, a placeholder is emitted)
        mov rax, <idx slot>
        # compute &array[idx] with a PC-relative lea so PIE keeps working
        lea rdx, [<&array>]
        # clear the pointer -- this is the actual fix
        # (clear the *slot*, not a register copy)
        mov <ptrwidth> ptr [rdx + rax*<elemsize>], 0
        jmp <resume>

    Everything the database can tell us is filled in; everything else is left
    as an obvious ``<placeholder>`` so the preview lists exactly what still has
    to be decided, instead of silently assembling a fix that only worked for
    one sample.
    """
    bits = _current_bits()
    ptr = "qword ptr" if bits == 64 else "dword ptr"
    acc = "rax" if bits == 64 else "eax"
    base = "rdx"
    scale = 8 if bits == 64 else 4

    arr = _find_addr_list()
    resume = _find_resume_hint()
    idx_slot = _find_index_slot(ea)

    arr_txt = ("0x%X" % arr) if arr is not None else "<&array>"
    resume_txt = ("0x%X" % resume) if resume is not None else "<resume>"
    idx_txt = idx_slot if idx_slot is not None else "<idx slot, e.g. rbp-4>"

    lines = []
    if idx_slot is None:
        lines.append("# TODO: replace <idx slot> with where the function kept the index")
        lines.append("#       e.g. 'mov eax, dword ptr [rbp-4]' for a stack slot")
    lines.append("mov %s, %s" % (acc, idx_txt))
    if bits == 64:
        lines.append("cdqe")
    if arr is None:
        lines.append("# TODO: replace <&array> with the ADDRESS of the pointer array")
        lines.append("#       (write an absolute address; Keystone emits RIP-relative)")
    lines.append("lea %s, [%s]" % (base, arr_txt))
    lines.append(
        "# the fix: clear the slot that holds the dangling pointer"
    )
    lines.append("mov %s [%s + %s*%d], 0" % (ptr, base, acc, scale))
    if resume is None:
        lines.append("# TODO: replace <resume> with the address to continue at")
        lines.append("#       (usually just past the instructions you overwrote)")
    lines.append("jmp %s" % resume_txt)
    return "\n".join(lines) + "\n"


def _find_index_slot(ea):
    """Guess how to reload the index register inside .eh_frame.

    Inside .eh_frame there is no local frame of our own, so the only reliable
    sources are:

    * a global counter/array index the function read (``mov eax, ds:xxxx``), or
    * the caller's frame, which we cannot analyse reliably from here.

    We therefore look at the *entry patch* applied earlier in this session: if
    it jumped out of a function, scan that function for a global-index load and
    suggest it.  When nothing convincing is found we return None and the
    template emits a placeholder, because guessing ``[rbp-4]`` is exactly the
    kind of sample-specific assumption that silently breaks other binaries.
    """
    try:
        from_entry = None
        for item in reversed(_patch_history):
            if item["ea"] and item.get("source"):
                from_entry = int(item["ea"])
                break
        if from_entry is None:
            return None
        f = ida_funcs.get_func(from_entry)
        if f is None:
            return None
        bits = _current_bits()
        acc = "rax" if bits == 64 else "eax"
        cur = int(f.start_ea)
        end = int(f.end_ea)
        seen = 0
        while cur < end and seen < 4000:
            seen += 1
            mnem = (idc.print_insn_mnem(cur) or "").lower()
            if mnem == "mov":
                # look for "mov eax, ds:xxxx" (a global index variable)
                op1 = (idc.print_operand(cur, 1) or "")
                if "ds:" in op1 or (op1.startswith("dword") and "[" in op1):
                    try:
                        addr = idc.get_operand_value(cur, 1)
                    except Exception:
                        addr = idc.BADADDR
                    if addr not in (None, idc.BADADDR) and addr > 0x1000:
                        return "dword ptr ds:0x%X" % addr
            nxt = idc.next_head(cur, end)
            if nxt in (None, idc.BADADDR) or nxt <= cur:
                break
            cur = int(nxt)
    except Exception:
        pass
    return None


def _find_addr_list():
    """Find the global pointer array the vulnerable function indexes into.

    Strategy, most trustworthy first:

    1. A named global (``addrList`` and friends) that IDA knows and that lives
       in a writable data segment.
    2. A sized global array whose element size matches the pointer width and
       that sits in writable data (``.data`` / ``.bss``).

    We deliberately do **not** invent an address: a wrong ``lea`` target turns a
    would-be fix into a write to an unrelated global, which is far worse than a
    visible placeholder.
    """
    bits = _current_bits()
    elem = 8 if bits == 64 else 4

    def _ok(ea):
        try:
            seg = ida_segment.getseg(ea)
        except Exception:
            seg = None
        return seg is not None and bool(seg.perm & ida_segment.SEGPERM_WRITE)

    for name in ("addrList", "ptrList", "heapList", "g_list", "ptrArr"):
        try:
            ea = idc.get_name_ea_simple(name)
        except Exception:
            ea = idc.BADADDR
        if ea not in (None, idc.BADADDR) and _ok(ea):
            return int(ea)

    # fall back: a sized array of pointers in writable data
    try:
        for ea, name, size in idautils.Names():
            if size and size % elem == 0 and size >= elem * 4:
                if _ok(ea) and name.startswith("arr"):
                    return int(ea)
    except Exception:
        pass
    return None


def _find_resume_hint():
    """Guess the address the stub should jump back to.

    Inside .eh_frame we are not inside a real function, so walking "this
    function" is useless.  The only trustworthy hint is the entry patch applied
    earlier in this session: the stub should resume right after the bytes that
    entry jump replaced.

    A segment base (the old fallback) is deliberately NOT used: it silently
    produced ``jmp 0x11C0`` which for an arbitrary binary is the middle of
    ``_start`` -- a plausible-looking but wrong address that is worse than an
    explicit placeholder.
    """
    for item in reversed(_patch_history):
        end = item["ea"] + len(item["new"])
        try:
            seg = ida_segment.getseg(end)
        except Exception:
            seg = None
        if seg is not None and seg.perm & ida_segment.SEGPERM_EXEC:
            return int(end)
    return None


def _suggest_source(ea):
    """Pre-fill the editor.

    Inside .eh_frame we hand the user a working UAF "clear the pointer" stub
    instead of a wall of comments: the placeholder-free version assembles
    immediately, and anything we could not infer stays visibly marked.
    """
    seg = MEM.segment_at(ea)
    if seg is not None and seg.name == ".eh_frame":
        return _guess_uaf_template(ea)
    # Fall back to the current instruction, like Keypatch does.
    try:
        line = idc.GetDisasm(ea)
    except Exception:
        line = ""
    if line:
        return asm_engine.strip_comment(ida_lines.tag_remove(line))
    return ""


def do_undo():
    if not _patch_history:
        ida_kernwin.info("eh_frame_patch: nothing to undo in this session")
        return
    item = _patch_history[-1]
    if item["imagebase"] != ida_nalt.get_imagebase():
        ida_kernwin.warning("Database was rebased after this patch; session undo refused")
        return
    if ida_dbg.is_debugger_on():
        ida_kernwin.warning("Stop the debugger before undoing a patch")
        return
    if MEM.read(item["ea"], len(item["new"])) != item["new"]:
        ida_kernwin.warning("Bytes changed since this patch; undo refused to preserve later edits")
        return
    try:
        ida_bytes.patch_bytes(item["ea"], item["orig"])
        if MEM.read(item["ea"], len(item["orig"])) != item["orig"]:
            raise RuntimeError("undo read-back mismatch")
        _patch_history.pop()
    except Exception:
        ida_kernwin.warning("eh_frame_patch: undo failed:\n%s" % traceback.format_exc())
        return
    try:
        ida_auto.plan_and_wait(item["ea"], item["ea"] + len(item["orig"]))
    except Exception:
        pass
    ida_kernwin.info(
        "reverted %d byte(s) at 0x%X" % (len(item["orig"]), item["ea"])
    )


# ---------------------------------------------------------------------------
# actions / menus
# ---------------------------------------------------------------------------
class _Action(idaapi.action_handler_t):
    def __init__(self, callback, label, tooltip="", shortcut=None):
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
        self.label = label
        self.tooltip = tooltip
        self.shortcut = shortcut

    def activate(self, ctx):
        try:
            self.callback()
        except Exception:
            ida_kernwin.warning("eh_frame_patch:\n%s" % traceback.format_exc())
        return 1

    def update(self, ctx):
        try:
            if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_HEXVIEW):
                return idaapi.AST_ENABLE_FOR_WIDGET
        except Exception:
            pass
        return idaapi.AST_ENABLE_ALWAYS


def _ea_from_ctx():
    ea = ida_kernwin.get_screen_ea()
    try:
        sel, a, b = ida_kernwin.read_range_selection(None)
        if sel and b > a:
            return a
    except Exception:
        pass
    return ea


def _set_ida_segment_exec(seg):
    """Add SEGPERM_EXEC to an IDA segment's permission bits.

    :returns: (old_perm, new_perm) or None on failure
    """
    try:
        ea = int(seg.start_ea)
        old = idc.get_segm_attr(ea, idc.SEGATTR_PERM)
        if old is None:
            return None
        new = int(old) | ida_segment.SEGPERM_EXEC
        if new == old:
            return (old, old)
        if not idc.set_segm_attr(ea, idc.SEGATTR_PERM, new):
            return None
        return (old, new)
    except Exception:
        traceback.print_exc()
        return None


def _mark_eh_frame_executable():
    """Make the whole .eh_frame segment executable.

    Two separate things have to change, and both are required:

    * **IDA segment permission** -- so the disassembler treats the bytes as
      code and ``.eh_frame`` shows ``R-X`` in the segments window.
    * **ELF ``p_flags`` PF_X** on the PT_LOAD that contains .eh_frame -- this is
      what the kernel actually honours. IDA's flag alone cannot make the CPU
      execute the bytes.

    The file edit happens in place, so a ``.bak`` copy is written first.
    """
    seg = _eh_frame_segment()
    if seg is None:
        ida_kernwin.warning("eh_frame_patch: this database has no .eh_frame segment")
        return

    try:
        path = ida_nalt.get_input_file_path()
    except Exception:
        path = None
    img = None
    sec = None
    load = None
    if path and os.path.isfile(path):
        try:
            img = elf_image.ElfImage.from_file(path)
            sec = img.section(".eh_frame")
            if sec is not None:
                load = img.load_at(sec.addr)
        except Exception:
            img = None

    ida_perm = int(getattr(seg, "perm", 0))
    ida_has_x = bool(ida_perm & ida_segment.SEGPERM_EXEC)
    elf_has_x = bool(load is not None and (load.flags & elf_image.PF_X))

    lines = [
        ".eh_frame segment : %#x-%#x" % (int(seg.start_ea), int(seg.end_ea)),
        "IDA permissions   : %s" % SegPerm.text(ida_perm),
    ]
    if load is not None:
        lines.append(
            "ELF PT_LOAD #%-3d  : %s  (%#x-%#x)"
            % (load.index, load.perm_text, load.vaddr, load.end_vaddr)
        )
    else:
        lines.append("ELF PT_LOAD       : (not found -- file not readable?)")
    lines.append("")

    if ida_has_x and (elf_has_x or load is None):
        lines.append("Already executable in IDA and in the file -- nothing to do.")
        ida_kernwin.info("\n".join(lines))
        return

    lines.append("This will:")
    if not ida_has_x:
        lines.append("  - mark the IDA segment executable (disassembler shows code)")
    if not elf_has_x and load is not None:
        lines.append(
            "  - set PF_X on PT_LOAD #%d in the file (the kernel needs this)"
            % load.index
        )
    lines.append("")
    if load is not None:
        lines.append(
            "Note: PF_X covers the whole PT_LOAD (%#x-%#x), not only .eh_frame."
            % (load.vaddr, load.end_vaddr)
        )
        lines.append("The input file is modified in place; a .bak is written first.")
    lines.append("")
    lines.append("Continue?")
    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "\n".join(lines)) != ida_kernwin.ASKBTN_YES:
        return

    report = []

    # ---- 1. IDA segment permission ------------------------------------
    if not ida_has_x:
        changed = _set_ida_segment_exec(seg)
        if changed is None:
            report.append("IDA segment: FAILED to change permissions")
        else:
            report.append(
                "IDA segment: %s -> %s"
                % (SegPerm.text(changed[0]), SegPerm.text(changed[1]))
            )
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
    else:
        report.append("IDA segment: already executable")

    # ---- 2. ELF p_flags ------------------------------------------------
    if img is None or load is None:
        report.append("ELF file   : skipped (input file not readable)")
    elif elf_has_x:
        report.append("ELF file   : PF_X already set")
    else:
        backup = path + ".bak"
        try:
            if not os.path.exists(backup):
                with open(path, "rb") as src_fh, open(backup, "wb") as dst_fh:
                    dst_fh.write(src_fh.read())
        except Exception:
            ida_kernwin.warning(
                "eh_frame_patch: cannot write the backup %s; ELF left untouched"
                % backup
            )
            ida_kernwin.info("\n".join(lines + [""] + report))
            return
        try:
            img.set_exec_flag(sec.addr, True)
            img.write(path, allow_in_place=True)
            check = elf_image.ElfImage.from_file(path)
            now = check.load_at(sec.addr)
            report.append(
                "ELF file   : PT_LOAD #%d is now %s (backup: %s)"
                % (load.index, now.perm_text if now else "?", backup)
            )
        except Exception:
            report.append(
                "ELF file   : FAILED\n%s" % traceback.format_exc()
            )

    for line in report:
        print("eh_frame_patch: " + line)
    ida_kernwin.info("\n".join(lines[:-1] + [""] + report))


def _export_from_db():
    ea = _ea_from_ctx()
    seg = MEM.segment_at(ea)
    if seg is None:
        ida_kernwin.warning("eh_frame_patch: no segment at 0x%X" % ea)
        return
    # Enumerate explicit patches across all segments: a UAF fix
    # has a stub in .eh_frame plus a jump inside .text, and both must land in
    # the exported copy.
    patches = collect_all_db_changes()
    export_executable_copy(ea, patches)


def goto_stub_area():
    """Jump to a safe overwrite area in .eh_frame and open the editor there."""
    goto_safe_place(32)


class _PopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        try:
            wtype = idaapi.get_widget_type(widget)
        except Exception:
            wtype = None
        if wtype not in (idaapi.BWN_DISASM, idaapi.BWN_HEXVIEW):
            return
        try:
            idaapi.attach_action_to_popup(widget, popup, ACTION_PATCH, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_STUB, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_PREVIEW, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_INFO, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_EXPORT, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MARK_EXEC, "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, "-", "eh_frame_patch/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_UNDO, "eh_frame_patch/")
        except Exception:
            pass


_ACTIONS = [
    (
        ACTION_PATCH,
        "Patch...",
        "Assemble into any mapped address, including .eh_frame",
        "Ctrl-Alt-J",
        lambda: open_patcher(None),
    ),
    (
        ACTION_STUB,
        "Goto safe area",
        "Jump to a writable head in .eh_frame and open the editor "
        "(uses the largest 16-byte aligned head when the program never "
        "unwinds, and record padding when it does)",
        "Ctrl-Alt-K",
        goto_stub_area,
    ),
    (
        ACTION_PREVIEW,
        "Preview",
        "Show the patch preview of the address under the cursor",
        None,
        lambda: show_preview(_ea_from_ctx()),
    ),
    (
        ACTION_INFO,
        "Permissions...",
        "Compare IDA segment permissions with the ELF PT_LOAD flags, and "
        "report whether the program unwinds at run time",
        None,
        lambda: show_permission_report(_ea_from_ctx()),
    ),
    (
        ACTION_EXPORT,
        "Export...",
        "Write a new ELF containing this session's patches",
        "Ctrl-Alt-Shift-J",
        _export_from_db,
    ),
    (
        ACTION_MARK_EXEC,
        "Add exec bit",
        "Set PF_X on the PT_LOAD that holds .eh_frame, so code placed there "
        "can actually run (writes the input file; a backup is offered)",
        "Ctrl-Alt-Shift-X",
        _mark_eh_frame_executable,
    ),
    (
        ACTION_UNDO,
        "Undo",
        "Restore the bytes saved by the last patch of this session",
        None,
        do_undo,
    ),
]


class _DatabaseHooks(idaapi.IDB_Hooks):
    def closebase(self):
        _patch_history.clear()
        _written_ranges.clear()
        if _PREVIEW is not None:
            _PREVIEW.close()
        return 0


class EhFramePatchPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Keypatch companion: assemble into data segments / .eh_frame"
    help = "eh_frame_patch %s -- see docs/USAGE.md" % PLUGIN_VERSION
    wanted_name = "eh_frame_patch"
    wanted_hotkey = ""

    def init(self):
        self._hooks = None
        self._db_hooks = None
        self._registered = []
        try:
            for name, label, tooltip, shortcut, cb in _ACTIONS:
                desc = idaapi.action_desc_t(
                    name,
                    label,
                    _Action(cb, label, tooltip, shortcut),
                    shortcut,
                    tooltip,
                    -1,
                )
                if idaapi.register_action(desc):
                    self._registered.append(name)
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Patch...", ACTION_PATCH, idaapi.SETMENU_APP
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Goto safe area",
                ACTION_STUB,
                idaapi.SETMENU_APP,
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Preview",
                ACTION_PREVIEW,
                idaapi.SETMENU_APP,
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Permissions...",
                ACTION_INFO,
                idaapi.SETMENU_APP,
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Export...",
                ACTION_EXPORT,
                idaapi.SETMENU_APP,
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Add exec bit",
                ACTION_MARK_EXEC,
                idaapi.SETMENU_APP,
            )
            idaapi.attach_action_to_menu(
                "Edit/eh_frame_patch/Undo",
                ACTION_UNDO,
                idaapi.SETMENU_APP,
            )
            self._hooks = _PopupHooks()
            self._hooks.hook()
            self._db_hooks = _DatabaseHooks()
            self._db_hooks.hook()
            print(
                "eh_frame_patch %s loaded (keystone=%s, capstone=%s)"
                % (
                    PLUGIN_VERSION,
                    asm_engine.keystone_available(),
                    disasm_preview.capstone_available(),
                )
            )
        except Exception:
            self.term()
            print("eh_frame_patch: init failed:\n%s" % traceback.format_exc())
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        open_patcher(None)

    def term(self):
        try:
            if self._hooks is not None:
                self._hooks.unhook()
            if self._db_hooks is not None:
                self._db_hooks.unhook()
        except Exception:
            pass
        for name in self._registered:
            try:
                idaapi.unregister_action(name)
            except Exception:
                pass
        self._registered = []
        if _PREVIEW is not None:
            _PREVIEW.close()
        _patch_history.clear()
        _written_ranges.clear()


def PLUGIN_ENTRY():
    return EhFramePatchPlugin()
