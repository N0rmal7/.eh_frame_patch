import os, sys, traceback, json
from pathlib import Path
import idaapi, ida_auto, ida_bytes, ida_segment, ida_loader, ida_kernwin, ida_nalt
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT/'evidence'
OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'plugins'))
results=[]
def check(name,cond):
    results.append({'test':name,'passed':bool(cond)})
    if not cond: raise AssertionError(name)
try:
    ida_auto.auto_wait()
    # The machine has v1 installed; isolate the unpacked core under test.
    for name in list(sys.modules):
        if name == 'ehp' or name.startswith('ehp.'):
            del sys.modules[name]
    import eh_frame_patch as E
    from ehp import plan, asm_engine, elf_image
    check('IDA 9.0',idaapi.get_kernel_version().startswith('9.0'))
    check('optimized version imported',E.PLUGIN_VERSION=='1.0.1')
    check('x86 architecture',E._is_supported_arch())
    check('Keystone available',asm_engine.keystone_available())
    db_hooks=E._DatabaseHooks()
    check('database lifecycle hook registers',db_hooks.hook())
    db_hooks.unhook()
    eh=ida_segment.get_segm_by_name('.eh_frame'); addr=eh.start_ea
    orig=ida_bytes.get_bytes(addr,16)
    check('live tail not suggested as cave',E.suggest_stub_address() is None)
    p=plan.build_plan(E.MEM,addr,'nop\nnop',budget=8,nop_pad=True)
    check('plan valid',p.ok)
    r=E.apply_patch(p,False); check('patch readback',r.ok and ida_bytes.get_bytes(addr,8)==b'\x90'*8)
    check('stale plan rejected',not E.apply_patch(p,False).ok)
    invalid=plan.build_plan(E.MEM,addr,'nop\nnop',budget=1)
    check('invalid plan rejected at API',not E.apply_patch(invalid,False).ok)
    # Undo failure retains history; foreign edit is never overwritten.
    ida_bytes.patch_byte(addr,0xCC)
    warn=ida_kernwin.warning; info=ida_kernwin.info
    ida_kernwin.warning=lambda *a: None; ida_kernwin.info=lambda *a: None
    E.do_undo(); check('conflicting undo refused',len(E._patch_history)==1 and ida_bytes.get_byte(addr)==0xCC)
    ida_bytes.patch_bytes(addr,b'\x90'*8); E.do_undo()
    check('successful undo verified',not E._patch_history and ida_bytes.get_bytes(addr,8)==orig[:8])
    # Inject partial writes into the actual IDA API boundary, then verify rollback.
    write_api=ida_bytes.patch_bytes
    attempts=[0]
    def fail_once(ea,blob):
        attempts[0]+=1
        if attempts[0]==1:
            write_api(ea,blob[:1])
            raise RuntimeError('injected partial write')
        write_api(ea,blob)
    p=plan.build_plan(E.MEM,addr,'nop\nnop',budget=8)
    ida_bytes.patch_bytes=fail_once
    try: failed=E.apply_patch(p,False)
    finally: ida_bytes.patch_bytes=write_api
    check('partial write reports failure',not failed.ok)
    check('partial write rolled back',ida_bytes.get_bytes(addr,8)==orig[:8] and not E._patch_history)
    p=plan.build_plan(E.MEM,addr,'nop',budget=1)
    check('undo failure setup',E.apply_patch(p,False).ok)
    def reject_write(*args): raise RuntimeError('injected undo failure')
    ida_bytes.patch_bytes=reject_write
    try: E.do_undo()
    finally: ida_bytes.patch_bytes=write_api
    check('failed undo retains history',len(E._patch_history)==1)
    E.do_undo()
    check('retry undo succeeds',not E._patch_history and ida_bytes.get_bytes(addr,8)==orig[:8])
    # Simulate Keypatch: writes outside plugin API; clear all session state.
    text=ida_segment.get_segm_by_name('.text'); taddr=text.start_ea
    t_orig=ida_bytes.get_byte(taddr); ida_bytes.patch_byte(taddr,t_orig ^ 1)
    E._written_ranges.clear()
    runs=E.collect_all_db_changes()
    check('foreign explicit patches collected',any(a<=taddr<a+len(b) for a,b in runs))
    # Force a nonzero imagebase and export through actual plugin entry point.
    ida_segment.rebase_program(0x100000,ida_segment.MSF_FIXONCE)
    ida_auto.auto_wait()
    ea=ida_segment.get_segm_by_name('.eh_frame').start_ea
    out=str(OUT/'rebased_export.elf')
    askstr=ida_kernwin.ask_str; askyn=ida_kernwin.ask_yn
    ida_kernwin.ask_str=lambda *a: out
    ida_kernwin.ask_yn=lambda *a: ida_kernwin.ASKBTN_YES
    exported=E.export_executable_copy(ea,E.collect_all_db_changes())
    check('rebased export succeeded',exported==out)
    img=elf_image.ElfImage.from_file(out)
    check('export contains foreign patch',img.read(taddr,1)==bytes([t_orig ^ 1]))
    check('PF_X set',img.is_executable(img.section('.eh_frame').addr))
    # Restore test-only mutation and rebase for the GUI probe.
    ida_bytes.patch_byte(taddr+0x100000,t_orig)
    ida_segment.rebase_program(-0x100000,ida_segment.MSF_FIXONCE)
    ida_auto.auto_wait()
    form=E.PatchForm(addr,budget=8,source='nop')
    check('form compiled',form._plan.ok)
    form.Free()
    ida_kernwin.ask_str=askstr; ida_kernwin.ask_yn=askyn
    ida_kernwin.warning=warn; ida_kernwin.info=info
    check('Keypatch coexists',any(n.startswith('Kp_MC_') for n in ida_kernwin.get_registered_actions()))
    ida_loader.save_database(str(OUT/'review.i64'),0)
except Exception:
    results.append({'exception':traceback.format_exc()})
finally:
    (OUT/'ida_review.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8')
    idaapi.qexit(0 if all(x.get('passed',False) for x in results) else 1)
