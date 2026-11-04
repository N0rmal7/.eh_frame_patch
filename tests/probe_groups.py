"""Find a form layout that renders three independent checkboxes in IDA 9.0.

Variant A (one shared group, single line) renders fine but shows only one
checkbox.  Variant E (three separate ChkGroupControls) crashed.  This probe
isolates the actual crash trigger with single-line changes, showing each
variant for ~1.2 s and closing it with a Qt timer.

Run WITHOUT -A on an existing database::

    ida.exe -S"probe_groups.py" samples/uaf_demo64.i64
"""

import os
import time
import traceback

import idaapi
import ida_kernwin

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "probe_groups.log")


def log(msg):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(str(msg) + "\n")
        fh.flush()


def run_variant(tag, formstr, controls, delay_ms=1200):
    from PyQt5.QtCore import QTimer
    from PyQt5.QtWidgets import QApplication

    state = {"fired": False}

    def close_all():
        state["fired"] = True
        app = QApplication.instance()
        if app is not None:
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
    timer.start(delay_ms)

    rc = None
    exc = None
    t0 = time.time()
    try:
        f = ida_kernwin.Form(formstr, controls)
        f.Compile()
        rc = f.Execute()
    except Exception:
        exc = traceback.format_exc().splitlines()[-1][:120]
    elapsed = time.time() - t0
    try:
        timer.stop()
    except Exception:
        pass

    if exc:
        log("%-38s EXC      %.2fs  %s" % (tag, elapsed, exc))
        return "EXC"
    if state["fired"]:
        log("%-38s OK       %.2fs  rc=%s" % (tag, elapsed, rc))
        return "OK"
    log("%-38s REFUSED  %.2fs  rc=%s" % (tag, elapsed, rc))
    return "REFUSED"


def main():
    import ida_segment

    for _ in range(240):
        try:
            if ida_segment.get_segm_qty() > 0:
                break
        except Exception:
            pass
        time.sleep(0.3)

    F = ida_kernwin.Form
    ml = F.MultiLineTextControl
    log("=== probe_groups ===")

    def base():
        return {
            "c_addr": F.NumericInput(value=0x20b0, swidth=40, tp=F.FT_ADDR),
            "c_asm": ml(text="; c\nnop"),
            "FormChangeCb": F.FormChangeCb(lambda fid: 1),
        }

    head = (
        "STARTITEM {id:c_asm}\n"
        "BUTTON YES* Patch\n"
        "BUTTON CANCEL Cancel\n"
        "PG variant\n"
        "{FormChangeCb}\n"
        "\n"
        "<~T~arget address :{c_addr}>\n"
        "\n"
        "<Assembly:{c_asm}>\n"
        "\n"
    )

    results = {}

    # 1. NO checkbox at all (control group)
    results["1 no checkbox"] = run_variant("1 no checkbox", head, base())

    # 2. one single-item group, single line
    c = base()
    c["g1"] = F.ChkGroupControl(("i1",), value=1)
    results["2 one group"] = run_variant(
        "2 one group", head + "<Re-analyse:{i1}>{g1}>\n", c
    )

    # 3. two single-item groups, single line each
    c = base()
    c["g1"] = F.ChkGroupControl(("i1",), value=1)
    c["g2"] = F.ChkGroupControl(("i2",), value=0)
    results["3 two groups"] = run_variant(
        "3 two groups",
        head + "<Re-analyse:{i1}>{g1}>\n<NOP-pad:{i2}>{g2}>\n",
        c,
    )

    # 4. three single-item groups, single line each
    c = base()
    c["g1"] = F.ChkGroupControl(("i1",), value=1)
    c["g2"] = F.ChkGroupControl(("i2",), value=0)
    c["g3"] = F.ChkGroupControl(("i3",), value=0)
    results["4 three groups"] = run_variant(
        "4 three groups",
        head + "<Re-analyse:{i1}>{g1}>\n<NOP-pad:{i2}>{g2}>\n<Allow cross:{i3}>{g3}>\n",
        c,
    )

    # 5. one group with three items, all referenced on ONE line (known good)
    c = base()
    c["g"] = F.ChkGroupControl(("i1", "i2", "i3"), value=1)
    results["5 1grp3items oneline"] = run_variant(
        "5 1grp3items oneline",
        head + "<Options:{i1}>{g}>\n",
        c,
    )

    # 6. one group with three items spread over three lines
    c = base()
    c["g"] = F.ChkGroupControl(("i1", "i2", "i3"), value=1)
    results["6 1grp3items 3lines"] = run_variant(
        "6 1grp3items 3lines",
        head + "<Re-analyse:{i1}>\n<NOP-pad:{i2}>\n<Allow cross:{i3}>\n",
        c,
    )

    log("SUMMARY " + " ".join("%s=%s" % (k, v) for k, v in sorted(results.items())))
    log("PROBE DONE")
    idaapi.qexit(0)


main()
