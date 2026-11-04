from pathlib import Path
import subprocess,json
root=Path(__file__).resolve().parent.parent
file=root/'tests/out/main.e2e'
results=[]
for name,payload in [('exit',b'4   '),('add',b'1   1280 0   4   '),('delete',b'1   1280 0   2   0   4   '),('double_delete',b'1   1280 0   2   0   2   0   4   ')]:
 r=subprocess.run([str(file)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)
 assert r.returncode==0,(name,r.returncode,r.stdout)
 if name=='double_delete': assert b'Invalid Index' in r.stdout and b'double free' not in r.stdout
 results.append({'case':name,'exit_code':r.returncode,'passed':True})
(root/'evidence/plugin_export_runtime.json').write_text(json.dumps(results,indent=2))
print('PLUGIN-EXPORT-RUNTIME-OK: 4 cases')
