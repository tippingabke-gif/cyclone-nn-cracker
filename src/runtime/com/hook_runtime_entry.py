"""Exact-path IFEO stdio adapter. No engine executable is redistributed."""
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import uuid

HASH='86aa52769517fe0547ab8e26be2a6f3f5f5ee0b2f482386c7fae1471831285f6'
MODEL_HASH='324d1fb215d5dacb1278da0820ce79b8cbadca2c0fce01f1d3c83bb04459709d'
RUNTIME_VERSION='v325'
root=Path(sys.executable).resolve().parent
resources=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))

def main():
    if len(sys.argv)!=3 or sys.argv[1]!='--ifeo':
        raise ValueError('Start CycloneUnlocker.exe, then load the original engine in the chess GUI.')
    engine=Path(sys.argv[2]).resolve(strict=True)
    state=json.loads((root/'active-session.json').read_text(encoding='utf-8-sig'))
    marker=root/('session-'+str(uuid.UUID(state['session']))+'.active')
    if not marker.is_file():raise ValueError('Unlocker session is inactive')
    if str(engine).casefold()!=state['engine'].casefold():
        raise ValueError('Engine path differs from the active session')
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];kernel.OpenProcess.restype=W.HANDLE
    kernel.GetProcessTimes.argtypes=[W.HANDLE,C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME)]
    kernel.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
    kernel.CloseHandle.argtypes=[W.HANDLE]
    supervisor=kernel.OpenProcess(0x101000,False,int(state['pid']))
    if not supervisor:raise ValueError('Unlocker is not running; reopen it first')
    created,ended,kernel_time,user_time=(W.FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(supervisor,C.byref(created),C.byref(ended),C.byref(kernel_time),C.byref(user_time)):
        kernel.CloseHandle(supervisor);raise C.WinError(C.get_last_error())
    stamp=(created.dwHighDateTime<<32)|created.dwLowDateTime
    if stamp!=int(state['startedFileTime']) or kernel.WaitForSingleObject(supervisor,0)!=258:
        kernel.CloseHandle(supervisor);raise ValueError('Unlocker session expired')
    network=subprocess.run([str(root/'CycloneNetwork.exe'),'verify',str(root/'CycloneHook.exe'),str(engine)],
        capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if network.returncode:raise ValueError('Offline rule verification failed: '+network.stderr.decode(errors='replace'))
    if hashlib.sha256(engine.read_bytes()).hexdigest()!=HASH:raise ValueError('Engine SHA256 does not match the supported version')
    model=engine.parent/'cyclone-eval.nnue'
    if not model.is_file() or hashlib.sha256(model.read_bytes()).hexdigest()!=MODEL_HASH:
        raise ValueError('Matching cyclone-eval.nnue is missing or changed; restore the original model beside the engine')
    output=root/'logs'/(datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    output.mkdir(parents=True)
    plan={'bridge':True,'mockDns':True,'bridgeLimitSeconds':7200,'repairThreadLimit':True,
        'repairHorseStepTable':True,'allowSyntheticSerialInput':True,
        'earlyFeatureGeometry':True,'repairFeatureMembership':True,'verifyFeatureTables':True,
        'perft':[{'depth':1,'expected':44}]}
    plan_path=output/'runtime-plan.json';plan_path.write_text(json.dumps(plan),encoding='utf-8')
    (output/'launch.json').write_text(json.dumps({'mode':'exact-path-ifeo','engine':str(engine),
        'sha256':HASH,'modelSha256':MODEL_HASH,'runtimeVersion':RUNTIME_VERSION,
        'controllerPid':state['pid'],'networkRulesVerified':True},indent=2),encoding='utf-8')
    os.environ.update(CYCLONE_RUNTIME='1',CYCLONE_RUNTIME_ROOT=str(output),CYCLONE_RUNTIME_RUN=str(engine.parent),
        CYCLONE_RUNTIME_OUTPUT=str(output),CYCLONE_RUNTIME_PLAN=str(plan_path),
        CYCLONE_RUNTIME_HELPER=str(resources/'guest_examine.py'),CYCLONE_CONTROLLER_HANDLE=str(int(supervisor)),
        CYCLONE_CONTROLLER_MARKER=str(marker))
    sys.argv=[str(resources/'guest_startup_files.py'),RUNTIME_VERSION,'fixture-response-zfgeometry']
    try:
        final=runpy.run_path(str(resources/'guest_startup_files.py'),run_name='__main__')
    finally:kernel.CloseHandle(supervisor)
    report=final.get('report',{})
    if report.get('status')=='controller-closed' and report.get('controllerStopGraceful') and report.get('bridgeInputThreadStopped'):
        return
    if report.get('status')!='bridge-process-exited' or report.get('naturalExitCode')!=0:
        raise RuntimeError('Engine ended: '+report.get('status','unknown'))

try:main()
except Exception as exc:
    print(str(exc),file=sys.stderr)
    sys.exit(1)


