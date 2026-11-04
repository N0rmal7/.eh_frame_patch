"""Verify the *shipped* eh_frame_patch form renders, without any keystrokes.

Loads the plugin module itself, builds its real ``PatchForm`` and shows it for a
moment (Qt timer closes it).  This is the regression test for the layout that
IDA 9.0's renderer refuses:
"form: error at %/" / access violation while showing the form.

Run WITHOUT -A on an existing database::

    ida.exe -S"probe_plugin_form.py" samples/uaf_demo64.i64
"""

import os
import sys
import time
import traceback

import idaapi

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG = os.path.join(HERE, "probe_plugin_form.log")


def log(msg):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(str(msg) + "\n")
        fh.flush()


def main():
    import ida_segment

    for _ in range(240):
        try:
            if ida_segment.get_segm_qty() > 0:
                break
        except Exception:
            pass
        time.sleep(0.3)

    sys.path.insert(0, os.path.join(ROOT, "plugins"))
    log("=== probe_plugin_form ===")

    try:
        import eh_frame_patch as EHP
    except Exception:
        log("IMPORT FAIL\n" + traceback.format_exc())
        idaapi.qexit(1)
        return

    seg = ida_segment.get_segm_by_name(".eh_frame")
    ea = seg.start_ea if seg else 0x1000
    log("eh_frame=%s" % (hex(ea) if seg else "none"))

    from PyQt5.QtCore import QTimer
    from PyQt5.QtWidgets import QApplication

    state = {"fired": False}

    def close_all():
        state["fired"] = True
        app = QApplication.instance()
        if app is None:
            return -1
        for w in app.topLevelWidgets():
            try:
                if w.isVisible():
                    w.close()
            except Exception:
                pass
        return -1

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(close_all)
    timer.start(1500)

    rc = None
    exc = None
    t0 = time.time()
    try:
        form = EHP.PatchForm(ea, budget=32, source="nop\nnop")
        log("constructed; plan ok=%s" % getattr(form._plan, "ok", None))
        rc = form.Execute()
    except Exception:
        exc = traceback.format_exc()
    elapsed = time.time() - t0
    try:
        timer.stop()
    except Exception:
        pass

    if exc:
        log("FORM FAIL after %.2fs\n%s" % (elapsed, exc))
    elif state["fired"]:
        log("FORM OK (rendered, closed by timer) rc=%s %.2fs" % (rc, elapsed))
    else:
        log("FORM CLOSED EARLY rc=%s %.2fs -> renderer refused it" % (rc, elapsed))

    log("PROBE DONE")
    idaapi.qexit(0)


main()
