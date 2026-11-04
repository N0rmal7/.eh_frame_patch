import sys,json,traceback
from pathlib import Path
import idaapi,ida_auto,ida_segment,ida_kernwin
from PyQt5.QtCore import QTimer,QObject,QEvent
from PyQt5.QtWidgets import QApplication,QPushButton
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'evidence'
sys.path.insert(0,str(ROOT/'plugins'))
state={}
class PlaceWindows(QObject):
    def eventFilter(self,obj,event):
        if event.type()==QEvent.Show and hasattr(obj,'isWindow') and obj.isWindow():
            screens=QApplication.screens()
            if len(screens)>1:
                geo=screens[-1].availableGeometry(); obj.move(geo.x()+60,geo.y()+60)
            else:
                obj.move(-20000,-20000)
        return False
app=QApplication.instance(); placement=PlaceWindows(); app.installEventFilter(placement)
try:
    ida_auto.auto_wait()
    for name in list(sys.modules):
        if name=='ehp' or name.startswith('ehp.'): del sys.modules[name]
    import eh_frame_patch as E
    ea=ida_segment.get_segm_by_name('.eh_frame').start_ea
    form=E.PatchForm(ea,budget=8,source='nop')
    ida_kernwin.ask_yn=lambda *a: ida_kernwin.ASKBTN_YES
    def edit_and_accept():
        try:
            form.c_asm.setPlainText('nop\nnop\nret')
            form.c_budget.setText('6')
            form.c_reanalyze.setChecked(False)
            form.c_pad.setChecked(True)
            form._refresh()
            state['rendered']=True
            state['live_preview_size']=form._plan.size
            state['live_padding']=form._plan.pad_len
            for w in app.topLevelWidgets():
                if 'eh_frame_patch v1.0.1' in w.windowTitle():
                    state['screenshot']=w.grab().save(str(OUT/'form.png'))
                    state['geometry']=[w.width(),w.height()]
                    buttons=w.findChildren(QPushButton)
                    for button in buttons:
                        if button.text().replace('&','')=='Patch':
                            button.click(); return
            state['button_missing']=True; form.dialog.reject()
        except Exception:
            state['timer_error']=traceback.format_exc(); form.dialog.reject()
    timer=QTimer(); timer.setSingleShot(True); timer.timeout.connect(edit_and_accept); timer.start(1200)
    state['return_code']=form.Execute()
    state['accepted_source']=form._plan.source
    state['accepted_budget']=form._plan.budget
    state['accepted_reanalyze']=getattr(form,'_accepted_reanalyze',None)
    form.Free()
    state['passed']=(state.get('return_code')==1 and state.get('live_preview_size')==3
                     and state.get('live_padding')==3 and state.get('accepted_budget')==6
                     and state.get('accepted_reanalyze') is False and state.get('screenshot'))
except Exception:
    state['exception']=traceback.format_exc(); state['passed']=False
(OUT/'ida_form_review.json').write_text(json.dumps(state,indent=2),encoding='utf8')
idaapi.qexit(0 if state.get('passed') else 1)
