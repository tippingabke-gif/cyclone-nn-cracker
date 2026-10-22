COM_CASE='entry0'
"""Guest-only, bounded input-boundary observation with hardware breakpoints."""
import ctypes as C
from ctypes import wintypes as W
from collections import deque
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import traceback
import capstone
import pefile
import socket

VERSION = sys.argv[1] if len(sys.argv) > 1 else 'v4'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'trace'
SYNTHETIC_INPUT = sys.argv[3] if len(sys.argv) > 3 else 'XT-INVALID-0000'
CASE_LABEL = sys.argv[4] if len(sys.argv) > 4 else None
if CASE_LABEL and not CASE_LABEL.replace('-', '').isalnum():
    raise ValueError('Invalid case label')
if not VERSION.replace('-', '').isalnum():
    raise ValueError('Invalid run version')
RUNTIME = os.environ.get('CYCLONE_RUNTIME') == '1'
ROOT = Path(os.environ.get('CYCLONE_RUNTIME_ROOT',r'C:\Lab\CycloneUltimate'))
RUN = Path(os.environ.get('CYCLONE_RUNTIME_RUN',str(ROOT / ('analysis-run-' + VERSION))))
OUT = Path(os.environ.get('CYCLONE_RUNTIME_OUTPUT',str(ROOT / 'evidence' / VERSION)))
if CASE_LABEL:
    OUT = OUT / CASE_LABEL
OUT.mkdir(exist_ok=True)
plan_path = Path(os.environ.get('CYCLONE_RUNTIME_PLAN',str(Path(r'C:\Lab') / ('cyclone-test-plan-' + VERSION + '.json'))))
TEST_PLAN = json.loads(plan_path.read_text(encoding='utf-8-sig')) if plan_path.exists() else None
BRIDGE = bool(TEST_PLAN and TEST_PLAN.get('bridge'))
if TEST_PLAN:
    assert MODE in ('fixture-response', 'fixture-response-zfgeometry', 'fixture-response-zfsearch')
    if TEST_PLAN.get('traceFeatureTableWriters'):
        assert TEST_PLAN['perft']==[] and not TEST_PLAN.get('search')
    else:
        assert 1 <= len(TEST_PLAN['perft']) <= 64
    for case in TEST_PLAN['perft']:
        assert 1 <= case['depth'] <= 4
        assert all(re.fullmatch(r'[a-i][0-9][a-i][0-9]', move) for move in case.get('moves', []))
        if case.get('fen'):assert re.fullmatch(r'[a-zA-Z0-9/ \-]+',case['fen'])
    (OUT / 'test-plan.json').write_text(json.dumps(TEST_PLAN, indent=2), encoding='utf-8')
spec = importlib.util.spec_from_file_location('helpers', os.environ.get('CYCLONE_RUNTIME_HELPER',r'C:\Lab\cyclone-ultimate-examine.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
K = h.K
for name, args, restype in [
    ('DebugActiveProcess', [W.DWORD], W.BOOL),
    ('DebugSetProcessKillOnExit', [W.BOOL], W.BOOL),
    ('WaitForDebugEvent', [C.c_void_p, W.DWORD], W.BOOL),
    ('ContinueDebugEvent', [W.DWORD, W.DWORD, W.DWORD], W.BOOL),
    ('OpenThread', [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
    ('GetThreadContext', [W.HANDLE, C.c_void_p], W.BOOL),
    ('SetThreadContext', [W.HANDLE, C.c_void_p], W.BOOL),
    ('SetThreadExecutionState', [W.DWORD], W.DWORD),
    ('VirtualAllocEx', [W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD], C.c_void_p),
    ('DebugActiveProcessStop', [W.DWORD], W.BOOL),
    ('CreateJobObjectW', [C.c_void_p,W.LPCWSTR], W.HANDLE),
    ('SetInformationJobObject', [W.HANDLE,C.c_int,C.c_void_p,W.DWORD], W.BOOL),
    ('AssignProcessToJobObject', [W.HANDLE,W.HANDLE], W.BOOL),
    ('WaitForSingleObject', [W.HANDLE,W.DWORD], W.DWORD),
    ('PeekNamedPipe', [W.HANDLE,C.c_void_p,W.DWORD,C.c_void_p,C.POINTER(W.DWORD),C.c_void_p], W.BOOL),
]:
    f = getattr(K, name)
    f.argtypes = args
    f.restype = restype

class THREAD(C.Structure):
    _fields_ = [('size', W.DWORD), ('usage', W.DWORD), ('tid', W.DWORD),
                ('pid', W.DWORD), ('priority', W.LONG), ('delta', W.LONG), ('flags', W.DWORD)]
for name in ('Thread32First', 'Thread32Next'):
    getattr(K, name).argtypes = [W.HANDLE, C.POINTER(THREAD)]
    getattr(K, name).restype = W.BOOL

REG = dict(zip(['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rip'], range(120, 249, 8)))
REG.update(dr0=72, dr1=80, dr2=88, dr3=96, dr6=104, dr7=112)
dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
dis.detail = True
report = {'started': time.time(), 'version': VERSION, 'codePatched': False,
          'mode': MODE, 'input': SYNTHETIC_INPUT, 'inputSent': False, 'events': [], 'snapshots': []}
stdout = bytearray()
stderr = bytearray()
proc = None
ph = None
bridge_job = None
bridge_input_thread = None
bridge_stop = threading.Event()
bridge_input_lock = threading.Lock()
readers = []
attached = False
pending = None
base = 0
main_tid = None
trace_count = 0
trace_limit = 180000 if MODE == 'last-character' else (40000 if MODE == 'post-parse' else 10000)
trace_active = False
breakpoint_mode = 'input-return'
seen_prompt = False
major_hits = 0
last_char_hits = 0
handles = []
network_exports = {}
network_slots = {}
network_names = ('connect', 'send', 'recv', 'gethostbyname')
FIELD_START_RVA = 0xed61d3  # v38/v39: first read of the next field, payload+64.
network_threads = set()
exit_exports = {}
runtime_exit = 0
request_states = {}
response_states = {}
RESPONSE_MODES = ('fixture-response','fixture-response-pattern','fixture-response-trace','fixture-response-zfbaseline','fixture-response-zfset','fixture-response-zfzero','fixture-response-zfuci','fixture-response-zfperft','fixture-response-zfgeometry','fixture-response-zfsearch','fixture-response-equal','fixture-response-body','fixture-response-bodytrace','fixture-response-bodybranch','fixture-response-bodyguard','fixture-response-mismatch','fixture-response-exitcalls','fixture-response-exittrace','fixture-response-exitreturn','fixture-response-flagprobe','fixture-response-slotwatch','fixture-response-sourcewatch','fixture-response-sourcefollow','fixture-response-sourcewindow','fixture-response-rcxchain','fixture-response-rcxsource')
body_guard = None
ZF_SELECT_MODES = ('fixture-response-zfbaseline', 'fixture-response-zfset', 'fixture-response-zfzero', 'fixture-response-zfuci', 'fixture-response-zfperft', 'fixture-response-zfgeometry', 'fixture-response-zfsearch')
body_guard_pending = set()
REQUEST_MODES = ('fixture-request', 'fixture-request-plain', 'fixture-request-origin', 'fixture-key-trace')
ORIGIN_MODES = ('fixture-request-origin', 'fixture-key-trace')
key_trace_file = None
key_trace_active = False
key_trace_tid = None
key_trace_paused = False
key_trace_resume = 0
key_trace_dr7_base = 0x44
pending_pushfq_repairs = {}
KEY_TRACE_START_RVA = 0x13c5e32
branch_trace_active = False
branch_trace_tid = None
branch_trace_resume = 0
branch_trace_state = None
BRANCH_TRACE_EVENT_LIMIT = 16384
BRANCH_TRACE_TAIL_LIMIT = 4096
BRANCH_TRACE_INSTRUCTION_LIMIT = 1000000

def save():
    report['stdout'] = stdout.decode('utf-8', errors='replace')
    report['stderr'] = stderr.decode('utf-8', errors='replace')
    temporary=OUT/'boundary-report.json.tmp'
    with temporary.open('w',encoding='utf-8') as output:
        output.write(json.dumps(report,ensure_ascii=False,indent=2))
        output.flush();os.fsync(output.fileno())
    temporary.replace(OUT/'boundary-report.json')

def consume(stream, dest):
    pending_line=bytearray()
    while True:
        data = stream.read1(4096)
        if not data:
            return
        dest.extend(data)
        if BRIDGE:
            if len(dest)>2*1024*1024:del dest[:len(dest)-2*1024*1024]
            pending_line.extend(data)
            while b'\n' in pending_line:
                line,_,tail=pending_line.partition(b'\n');pending_line[:]=tail
                if line.startswith(b'input serial number: '):line=line[len(b'input serial number: '):]
                if line.startswith((b'maximum threads support ',b'remaining days of service ')):continue
                output=sys.stdout.buffer if dest is stdout else sys.stderr.buffer
                output.write(line+b'\n');output.flush()

def forward_client_input():
    try:
        def lines():
            if not os.environ.get('CYCLONE_CONTROLLER_HANDLE'):
                yield from sys.stdin.buffer
                return
            import msvcrt
            fd=sys.stdin.fileno();pipe=msvcrt.get_osfhandle(fd);pending_line=bytearray()
            while not bridge_stop.is_set():
                available=W.DWORD()
                if not K.PeekNamedPipe(pipe,None,0,None,C.byref(available),None):
                    if C.get_last_error() in (109,232):
                        if pending_line:yield bytes(pending_line)
                        return
                    raise C.WinError(C.get_last_error())
                if not available.value:
                    bridge_stop.wait(.02);continue
                pending_line.extend(os.read(fd,min(available.value,4096)))
                if len(pending_line)>65536:raise ValueError('Engine input line exceeds 64 KiB')
                while b'\n' in pending_line:
                    line,_,tail=pending_line.partition(b'\n');pending_line[:]=tail
                    yield bytes(line)+b'\n'
        for line in lines():
            if bridge_stop.is_set():return
            if len(line)>65536:raise ValueError('Engine input line exceeds 64 KiB')
            report.setdefault('bridgeCommands',[]).append(line.decode('utf-8',errors='replace').rstrip())
            report['bridgeCommands']=report['bridgeCommands'][-200:]
            with bridge_input_lock:
                proc.stdin.write(line);proc.stdin.flush()
            if line.strip()==b'quit':return
        if not bridge_stop.is_set() and proc.poll() is None:
            with bridge_input_lock:
                proc.stdin.write(b'quit\n');proc.stdin.flush()
    except (BrokenPipeError,OSError):pass

def read(addr, size):
    if not addr or addr < 0x10000 or addr > 0x7fffffffffff:
        return b''
    buf = C.create_string_buffer(size)
    got = C.c_size_t()
    K.ReadProcessMemory(ph, addr, buf, size, C.byref(got))
    return buf.raw[:got.value]

def get_context(tid):
    th = K.OpenThread(0x1a, False, tid)
    if not th:
        raise C.WinError(C.get_last_error())
    raw = C.create_string_buffer(1248)
    ptr = (C.addressof(raw) + 15) & ~15
    C.c_uint32.from_address(ptr + 48).value = 0x10001f
    if not K.GetThreadContext(th, ptr):
        K.CloseHandle(th)
        raise C.WinError(C.get_last_error())
    return th, raw, ptr

def regs(ptr):
    result = {k: C.c_uint64.from_address(ptr + off).value for k, off in REG.items()}
    result['eflags'] = C.c_uint32.from_address(ptr + 68).value
    return result

def put64(ptr, name, value):
    C.c_uint64.from_address(ptr + REG[name]).value = value

def flags(ptr, enable=0, disable=0):
    ref = C.c_uint32.from_address(ptr + 68)
    ref.value = (ref.value | enable) & ~disable

def execution_breakpoint_hit(hardware, registers):
    dr7=registers['dr7']
    return any(
        hardware & (1 << slot)
        and dr7 & (3 << (slot * 2))
        and not ((dr7 >> (16 + slot * 4)) & 3)
        and registers['rip']==registers['dr'+str(slot)]
        for slot in range(4)
    )

def require_runtime_instruction(rva, expected_text, expected_size):
    instruction=next(dis.disasm(read(base+rva,15),base+rva,count=1),None)
    actual=(instruction.mnemonic+' '+instruction.op_str).strip() if instruction else None
    if not instruction or instruction.size!=expected_size or actual!=expected_text:
        raise RuntimeError(
            f'Instruction precondition changed at RVA {rva:#x}: '
            f'expected {expected_text!r}/{expected_size}, got {actual!r}/'
            f'{instruction.size if instruction else None}')
    return instruction

def apply_context(th, ptr):
    if not K.SetThreadContext(th, ptr):
        raise C.WinError(C.get_last_error())

def snapshot(tid, ptr, label):
    if RUNTIME:return
    r = regs(ptr)
    index = len(report['snapshots'])
    stem = f'{index:02d}-{label}'
    row = {'label': label, 'tid': tid, 'registers': {k: hex(v) for k, v in r.items()}}
    (OUT / (stem + '.context.bin')).write_bytes(C.string_at(ptr, 1232))
    mbi = h.MBI()
    if K.VirtualQueryEx(ph, r['rsp'], C.byref(mbi), C.sizeof(mbi)):
        size = min(0x20000, mbi.base + mbi.regionSize - r['rsp'])
        raw = read(r['rsp'], size)
        (OUT / (stem + '.stack.bin')).write_bytes(raw)
        row['stack'] = {'address': hex(r['rsp']), 'size': len(raw), 'file': stem + '.stack.bin', 'sha256': hashlib.sha256(raw).hexdigest()}
        row['stackQwords'] = [hex(x[0]) for x in struct.iter_unpack('<Q', raw[:min(0x280, len(raw) // 8 * 8)])]
    row['memory'] = {}
    for name in ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r14', 'r15'):
        raw = read(r[name], 96)
        row['memory'][name] = {'address': hex(r[name]), 'bytes': raw.hex(), 'ascii': ''.join(chr(x) if 32 <= x < 127 else '.' for x in raw)}
    row['code'] = [f'{i.address-base:x}: {i.mnemonic} {i.op_str}' for i in dis.disasm(read(r['rip'], 120), r['rip'])]
    if MODE == 'checkpoints':
        row['frameRegions'] = {hex(offset): read(r['rbp'] + offset, 128).hex()
                               for offset in (0, 0xb00, 0xb20)}
    row['previousInstructionCandidates'] = []
    if report.get('licensePayload'):
        payload_bytes=read(int(report['licensePayload']['address'],16),132)
        row['licensePayloadHex']=payload_bytes.hex()
    for back in range(1, 16):
        previous = next(dis.disasm(read(r['rip']-back, back), r['rip']-back, count=1), None)
        if previous and previous.size == back:
            row['previousInstructionCandidates'].append(f'{previous.address-base:x}: {previous.mnemonic} {previous.op_str}')
    report['snapshots'].append(row)
    save()
    return r

def arm_thread(tid):
    th, raw, ptr = get_context(tid)
    try:
        if MODE == 'network':
            for slot, name in enumerate(network_names):
                put64(ptr, 'dr'+str(slot), network_exports[name])
                network_slots[tid,slot] = {'name':name, 'phase':'enter'}
            put64(ptr, 'dr6', 0)
            put64(ptr, 'dr7', 0x55)
            apply_context(th, ptr)
            return
        put64(ptr, 'dr0', base + 0xadf94)
        put64(ptr, 'dr1', base + (0x13c59b2 if MODE == 'checkpoints' else 0xadf40))
        put64(ptr, 'dr2', base + (0x13c7606 if MODE == 'checkpoints' else 0xadfa0))
        put64(ptr, 'dr3', base + 0x111766)
        put64(ptr, 'dr6', 0)
        put64(ptr, 'dr7', 0x55 | (3 << 28))
        apply_context(th, ptr)
    finally:
        K.CloseHandle(th)

def network_event(tid, ptr, r, hardware):
    slot = next(i for i in range(4) if hardware & (1 << i))
    state = network_slots[tid,slot]
    name, phase = state['name'], state['phase']
    item = {'name':name,'phase':phase,'time':time.time(),'tid':tid,
            'instruction':hex(r['rip'])}
    if name in ('connect','send','recv'):
        if phase == 'enter': state['socket']=r['rcx']
        item['socket']=hex(state['socket'])
    if phase == 'enter':
        ret = struct.unpack('<Q',read(r['rsp'],8))[0]
        item['returnAddress'] = hex(ret)
        item['callerRva'] = hex(ret-base) if base <= ret < base+0x4000000 else None
        if name == 'connect':
            address=read(r['rdx'],min(r['r8'],128))
            item['sockaddrHex']=address.hex()
            if len(address)>=8 and address[:2]==b'\x02\x00':
                item['remoteAddress']=socket.inet_ntoa(address[4:8])
                item['remotePort']=struct.unpack('>H',address[2:4])[0]
        elif name in ('send','recv'):
            state['buffer']=r['rdx'];state['capacity']=r['r8'] & 0xffffffff
            item['requestedBytes']=state['capacity']
            if name=='send':
                data=read(r['rdx'],min(state['capacity'],65536))
                item['bufferHex']=data.hex()
                item['bufferText']=data.decode('utf-8',errors='replace')
        elif name=='gethostbyname':
            item['hostname']=read(r['rcx'],512).split(b'\0',1)[0].decode('ascii',errors='replace')
        elif name in exit_exports:
            item['exitCode']=r['rdx']&0xffffffff if name=='NtTerminateProcess' else r['rcx']&0xffffffff
            item['processHandle']=hex(r['rcx']) if name=='NtTerminateProcess' else None
        if TEST_PLAN and TEST_PLAN.get('mockDns') and name=='gethostbyname':
            allocation=K.VirtualAllocEx(ph,None,4096,0x3000,4)
            if not allocation:raise C.WinError(C.get_last_error())
            blob=bytearray(128)
            struct.pack_into('<QQhh4xQ',blob,0,allocation+80,allocation+48,2,4,allocation+56)
            struct.pack_into('<Q',blob,56,allocation+72);blob[72:76]=bytes((127,0,0,1));blob[80:90]=b'localhost\0'
            buffer=C.create_string_buffer(bytes(blob));written=C.c_size_t()
            if not K.WriteProcessMemory(ph,allocation,buffer,len(blob),C.byref(written)) or written.value!=len(blob):
                raise RuntimeError('Local hostent setup failed')
            put64(ptr,'rax',allocation);put64(ptr,'rip',ret);put64(ptr,'rsp',r['rsp']+8)
            item['simulation']={'apiExecuted':False,'address':'127.0.0.1'}
            report.setdefault('networkEvents',[]).append(item);report['dnsSimulation']=True
            return
        if MODE in RESPONSE_MODES and name in ('connect','send','recv'):
            value=0 if name=='connect' else min(r['r8']&0xffffffff,1040)
            if name=='recv':
                if value!=1040:raise RuntimeError('Unexpected response receive capacity')
                response_bytes=bytes(value) if MODE=='fixture-response' else bytes(16)+bytes(range(256))*4
                data=C.create_string_buffer(response_bytes);written=C.c_size_t()
                if not K.WriteProcessMemory(ph,r['rdx'],data,value,C.byref(written)) or written.value!=value:
                    raise RuntimeError('Synthetic response write failed')
                response_states[tid]={'address':r['rdx'],'capacity':value,'siteCounts':{},'observations':[]}
                report['syntheticResponse']={'address':hex(r['rdx']),'bytes':value,
                    'fill':'all-zero' if MODE=='fixture-response' else 'zero header plus repeated 0..255 body',
                    'inputHex':response_bytes.hex(),
                    'source':'Local diagnostic input, not server data or an accepted authorization',
                    'observations':response_states[tid]['observations']}
                put64(ptr,'dr0',r['rdx']+16);put64(ptr,'dr1',r['rdx']+1036)
                report['syntheticResponse']['watchOffsets']=[16,1036]
                put64(ptr,'dr2',base+0xe5770);put64(ptr,'dr3',exit_exports['RtlExitUserProcess'])
                put64(ptr,'dr7',0x55|(0xf<<16)|(0xf<<20))
                network_threads.discard(tid)
            else:
                put64(ptr,'dr'+str(slot),network_exports[name])
            item['simulation']={'apiExecuted':False,'returnValue':value}
            put64(ptr,'rax',value);put64(ptr,'rip',ret);put64(ptr,'rsp',r['rsp']+8)
            report.setdefault('networkEvents',[]).append(item)
            report['apiSimulation']=True
            snapshot(tid,ptr,'simulated-'+name+'-return')
            return
        state['phase']='return'
        put64(ptr,'dr'+str(slot),ret)
    else:
        item['returnValue']=hex(r['rax'])
        signed=C.c_int32(r['rax'] & 0xffffffff).value
        if name!='gethostbyname':item['signedReturn']=signed
        if name=='recv' and signed>0:
            data=read(state['buffer'],min(signed,state['capacity'],65536))
            item['bufferHex']=data.hex();item['bufferText']=data.decode('utf-8',errors='replace')
        state['phase']='enter'
        put64(ptr,'dr'+str(slot),(network_exports|exit_exports)[name])
        if name=='recv':
            # DNS and connect have completed. Reuse their slots to observe the
            # real termination path; do not alter recv's result or control flow.
            for exit_slot,exit_name in ((0,'RtlExitUserProcess'),(3,'NtTerminateProcess')):
                network_slots[tid,exit_slot]={'name':exit_name,'phase':'enter'}
                put64(ptr,'dr'+str(exit_slot),exit_exports[exit_name])
    report.setdefault('networkEvents',[]).append(item)
    snapshot(tid,ptr,'net-'+name+'-'+phase)
    if MODE in REQUEST_MODES and name=='connect' and phase=='return' and signed==0:
        address=r['rbp']+0x1b60
        request_states[tid]={'address':address,'scheduleAddress':r['rbp']+0xb40,
                            'rawKeyAddress':r['rbp']-0x50,'observations':[]}
        report['requestBuffer']={'predictedAddress':hex(address),'derivation':'v35 send RDX = connect-return RBP + 0x1b60',
            'scheduleAddress':hex(r['rbp']+0xb40),
            'observations':request_states[tid]['observations']}
        for index,offset in enumerate((12,76,124)):put64(ptr,'dr'+str(index),address+offset)
        put64(ptr,'dr3',network_exports['send'])
        put64(ptr,'dr7',0x55|(0xd<<16)|(0xd<<20)|(0xd<<24))
        if MODE=='fixture-request-plain':
            if read(base+0x13ca1cc,3)!=bytes.fromhex('418908'):
                raise RuntimeError('Observed AES store instruction bytes changed')
            put64(ptr,'dr0',base+0x13ca1cc)
            put64(ptr,'dr7',0x41)
        elif MODE in ORIGIN_MODES:
            # v47 independently confirmed this address contains the complete
            # encryption schedule at send; observe its first writes this run.
            for index,watch in enumerate((r['rbp']+0xb40,address+4,address+8)):
                if watch & 3:raise RuntimeError('Unaligned origin watch address')
                put64(ptr,'dr'+str(index),watch)
        network_threads.discard(tid)
        report['status']='watching-request-writes'

def thread_ids(pid):
    sh = K.CreateToolhelp32Snapshot(4, 0)
    if sh == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        e = THREAD()
        e.size = C.sizeof(e)
        ok = K.Thread32First(sh, C.byref(e))
        result = []
        while ok:
            if e.pid == pid:
                result.append(e.tid)
            ok = K.Thread32Next(sh, C.byref(e))
        return result
    finally:
        K.CloseHandle(sh)

# Startup-only observation: no serial input, no code/data patches.
report.update(input=None, mode=MODE, startupDebugger=True, fileEvents=[])
K.SuspendThread.argtypes=[W.HANDLE];K.SuspendThread.restype=W.DWORD
K.ResumeThread.argtypes=[W.HANDLE];K.ResumeThread.restype=W.DWORD
file_apis={}
file_slots={}
file_handles={}
file_names=('CreateFileW','CreateFileA','ReadFile')
nnue_slots={}
nnue_handles={}
nnue_hashers={}
nnue_hidden_model=None
eval_slots={}

def record_feature_tables(stage):
    if not TEST_PLAN or not TEST_PLAN.get('traceFeatureTableInitialization'):
        return
    table_specs=(('base',0x1f39d0,16*90*2),('threats',0x239600,16*90*90*16*2))
    observation={'stage':stage,'tables':{}}
    for name,address,size in table_specs:
        raw=read(base+address,size)
        assert len(raw)==size, 'Incomplete feature table snapshot'
        values=struct.unpack('<'+'H'*(size//2),raw)
        (OUT/('features-'+stage+'-'+name+'.bin')).write_bytes(raw)
        observation['tables'][name]={'rva':hex(address),'bytes':size,
            'sha256':hashlib.sha256(raw).hexdigest(),'nonzero':sum(value!=0 for value in values),
            'maximum':max(values),'prefixHex':raw[:64].hex()}
    report.setdefault('featureTableInitialization',[]).append(observation)
    membership={}
    for name,address in (('king',0x138278),('elephant',0x13f4c0),('advisor',0x1f4510)):
        pointer=int.from_bytes(read(base+address,8),'little')
        raw=read(pointer,90)
        assert len(raw)==90, 'Incomplete square membership source'
        membership[name]={'pointerRva':hex(address),'pointer':hex(pointer),'bytes':list(struct.unpack('<90b',raw))}
    observation['squareMembershipSources']=membership

def verify_feature_tables():
    if not TEST_PLAN or not TEST_PLAN.get('verifyFeatureTables'):
        return
    expected=(
        ('base',0x1f39d0,2880,'0c172b70b4a41300db8c752868f0a38cb1c9839b201edd24e9f5829cf8cc71f2'),
        ('threats',0x239600,4147200,'4cc1e843e63f5ce7d003d28af1c743660fe964215ef53da7e06c63a418b1cbc8'))
    result={'atRva':'0xe5770','passed':False,'tables':{}}
    report['featureTableVerification']=result
    for name,address,size,digest in expected:
        raw=read(base+address,size)
        actual=hashlib.sha256(raw).hexdigest()
        result['tables'][name]={'bytes':len(raw),'sha256':actual,'expectedSha256':digest}
        if len(raw)!=size or actual!=digest:
            raise RuntimeError('Feature dictionary validation failed: '+name)
    result['passed']=True

def repair_feature_membership():
    if not TEST_PLAN or not TEST_PLAN.get('repairFeatureMembership'):
        return
    king={rank*9+file for rank in (0,1,2,7,8,9) for file in (3,4,5)}
    lower_elephant={(2,0),(6,0),(0,2),(4,2),(8,2),(2,4),(6,4)}
    lower_advisor={(3,0),(5,0),(4,1),(3,2),(5,2)}
    elephant={rank*9+file for file,rank in lower_elephant}|{(9-rank)*9+file for file,rank in lower_elephant}
    advisor={rank*9+file for file,rank in lower_advisor}|{(9-rank)*9+file for file,rank in lower_advisor}
    require_runtime_instruction(0xbbdf0,'cmp byte ptr [rcx + rdx], 0',4)
    changes=[]
    for name,address,allowed in (('king',0x138278,king),('elephant',0x13f4c0,elephant),('advisor',0x1f4510,advisor)):
        pointer=int.from_bytes(read(base+address,8),'little')
        before=read(pointer,90);assert len(before)==90
        replacement=bytes(0 if square in allowed else 255 for square in range(90))
        buffer=C.create_string_buffer(replacement);written=C.c_size_t()
        if not K.WriteProcessMemory(ph,pointer,buffer,90,C.byref(written)) or written.value!=90:
            raise RuntimeError('Feature square-membership diagnostic write failed')
        assert read(pointer,90)==replacement
        changes.append({'name':name,'pointerRva':hex(address),'pointer':hex(pointer),
            'beforeHex':before.hex(),'afterHex':replacement.hex(),'allowedCount':len(allowed)})
    report['featureMembershipRepair']={'atRva':'0x95f6c','consumerRva':'0xbbd50',
        'scope':'Restore signed-byte square membership before native feature dictionary generation; diagnostic only',
        'changes':changes}

def arm_eval_thread(tid,ptr):
    for slot in range(4):put64(ptr,'dr'+str(slot),0)
    put64(ptr,'dr0',base+0xa5750);put64(ptr,'dr6',0);put64(ptr,'dr7',1)
    eval_slots[tid]={'phase':'enter','count':0}

def handle_eval(tid,ptr,r,hardware):
    state=eval_slots.get(tid)
    if state is None:return False
    if hardware&4 and state.get('phase')=='return' and TEST_PLAN.get('traceFeatureConstruction'):
        removed=int.from_bytes(read(r['rsp']+0x60,8),'little')
        added=r['rbp']&0xffffffff;threats=r['rdi']&0xffffffff
        assert 0<=removed<=32 and 0<=added<=32 and 0<=threats<=128
        def indices(offset,count):return list(struct.unpack('<'+'I'*count,read(r['rsp']+offset,count*4)))
        entry={'cacheVectorSha256':hashlib.sha256(read(r['r10'],2048)).hexdigest(),
            'removed':indices(0x3e8,removed),'added':indices(0xd0,added),'threats':indices(0x1e0,threats)}
        state['event'].setdefault('featureConstruction',[]).append(entry)
        if len(state['event']['featureConstruction'])>=2:
            put64(ptr,'dr2',0);put64(ptr,'dr7',r['dr7']&~0x10)
        return True
    if hardware&2 and state.get('phase')=='return' and TEST_PLAN.get('traceEvaluationStages'):
        if r['rip']==base+0xa57ed:
            stack_base=r['rbx'];index=int.from_bytes(read(stack_base+0x11d980,8),'little')
            accumulator=stack_base+index*0x1280-0x1280
            raw=read(accumulator,4096);psqt=read(accumulator+4096,64)
            assert len(raw)==4096 and len(psqt)==64
            state['event']['accumulator']={'stackIndex':index,'sha256':hashlib.sha256(raw).hexdigest(),
                'perspectiveSha256':[hashlib.sha256(raw[n:n+2048]).hexdigest() for n in (0,2048)],
                'psqt':list(struct.unpack('<16i',psqt))}
            if state['count']==0:
                (OUT/('root-accumulator-'+str(tid)+'.bin')).write_bytes(raw)
                state['event']['rootNetworkSha256']=hashlib.sha256(read(r['rsi'],0x540d480)).hexdigest()
            put64(ptr,'dr1',base+0xa5e39)
        elif r['rip']==base+0xa5e39:
            state['event']['rawTerms']={'termRcx':C.c_int32(r['rcx']&0xffffffff).value,
                'termR9':C.c_int32(r['r9']&0xffffffff).value,'r12AtStage':C.c_int32(r['r12']&0xffffffff).value}
            put64(ptr,'dr1',0);put64(ptr,'dr7',r['dr7']&~4)
        return True
    if not hardware&1:return False
    if state['phase']=='enter':
        position=r['rdx'];position_state=int.from_bytes(read(position+0x148,8),'little')
        side=int.from_bytes(read(position+0x144,1),'little')
        material_count=int.from_bytes(read(position_state+0x48,2),'little',signed=True)
        bucket_pointer=int.from_bytes(read(base+0x1fec40,8),'little')
        bucket_index=side+material_count*2
        bucket_raw=read(bucket_pointer+bucket_index,1)
        entry={'threadId':tid,'phase':'enter','sequence':state['count'],'networkPointer':hex(r['rcx']),
            'boardPrefixHex':read(position,90).hex(),'positionStateHex':read(position_state,96).hex(),
            'side':side,'materialCount':material_count,'bucketTablePointer':hex(bucket_pointer),
            'bucketIndex':bucket_index,'bucketValue':int.from_bytes(bucket_raw,'little',signed=True),
            'bucketTableHex':read(bucket_pointer,128).hex(),
            'optimism':int.from_bytes(read(r['rsp']+0x28,4),'little',signed=True),
            'networkBiasSha256':hashlib.sha256(read(r['rcx'],0x800)).hexdigest()}
        state['event']=entry
        report.setdefault('evaluationEvents',[]).append(entry)
        put64(ptr,'dr0',int.from_bytes(read(r['rsp'],8),'little'))
        state['phase']='return'
        if TEST_PLAN.get('traceEvaluationStages'):
            require_runtime_instruction(0xa57ed,'imul r10, qword ptr [rbx + 0x11d980], 0x1280',11)
            put64(ptr,'dr1',base+0xa57ed);put64(ptr,'dr7',5)
        if TEST_PLAN.get('traceFeatureConstruction') and state['count']==0:
            require_runtime_instruction(0xfc320,'mov r8d, dword ptr [rsp + 0x60]',5)
            put64(ptr,'dr2',base+0xfc320);put64(ptr,'dr7',0x15)
    else:
        state['event']['returnValue']=C.c_int32(r['rax']&0xffffffff).value
        state['event']['returnRva']=hex(r['rip']-base)
        put64(ptr,'dr1',0);put64(ptr,'dr2',0);put64(ptr,'dr7',1)
        state['count']+=1;state['phase']='enter'
        if state['count']>=4:
            put64(ptr,'dr0',0);put64(ptr,'dr7',0)
        else:put64(ptr,'dr0',base+0xa5750)
    return True

def arm_nnue_files(tid,ptr):
    report['nnueTrace']={'startRva':'0x95f6c','threadId':tid,'events':[],
        'files':{},'scope':'Observe native initialization through search; no file result substitution'}
    for slot,name in ((0,'CreateFileW'),(1,'ReadFile')):
        nnue_slots[tid,slot]={'name':name,'phase':'enter'}
        put64(ptr,'dr'+str(slot),file_apis[name])
    put64(ptr,'dr2',base+0xe5770)
    put64(ptr,'dr3',base+0xe1aed)
    put64(ptr,'dr7',0x55)

def handle_nnue_file(tid,ptr,r,hardware):
    matches=[slot for slot in (0,1) if hardware&(1<<slot) and (tid,slot) in nnue_slots]
    if not matches:return False
    slot=matches[0];state=nnue_slots[tid,slot];name=state['name']
    entry={'api':name,'phase':state['phase'],'time':time.time(),'threadId':tid}
    if name=='ModelParser':
        if state['phase']=='enter':
            stream=read(r['r8'],40)
            address=int.from_bytes(stream[:8],'little')
            offset=int.from_bytes(stream[16:24],'little')
            length=int.from_bytes(stream[24:32],'little')
            state.update(resultPointer=r['rcx'],networkPointer=r['rdx'],streamPointer=r['r8'])
            entry.update(rva=hex(r['rip']-base),streamLength=length,streamOffset=offset,
                streamHeader=read(address+offset,64).hex(),networkPointer=hex(r['rdx']))
            state['phase']='return';put64(ptr,'dr0',int.from_bytes(read(r['rsp'],8),'little'))
        else:
            result_bytes=read(state['resultPointer'],32)
            entry.update(resultHex=result_bytes.hex(),successFlag=result_bytes[24] if len(result_bytes)>24 else None,
                streamAfterHex=read(state['streamPointer'],40).hex(),returnRva=hex(r['rip']-base))
            if TEST_PLAN.get('nnueWeightFingerprint') and entry['successFlag']==1:
                entry['weightFingerprints']={}
                for label,offset,length in (('biases',0,0x800),('featureWeights',0x204c800,0x316f000),
                    ('allBeforeFilename',0,0x540d480)):
                    raw=read(state['networkPointer']+offset,length)
                    assert len(raw)==length
                    entry['weightFingerprints'][label]={'bytes':length,'sha256':hashlib.sha256(raw).hexdigest()}
            state['phase']='enter';put64(ptr,'dr0',base+0xfa130)
        report['nnueTrace'].setdefault('parserEvents',[]).append(entry)
        if len(report['nnueTrace']['parserEvents'])>12:raise RuntimeError('NNUE parser trace bound exceeded')
        return True
    if state['phase']=='enter':
        ret=int.from_bytes(read(r['rsp'],8),'little')
        entry['returnAddress']=hex(ret)
        if name=='CreateFileW':
            path=read(r['rcx'],2048).decode('utf-16-le',errors='replace').split('\0',1)[0]
            state.update(path=path,capture=path.lower().endswith('.nnue'))
            entry.update(path=path,access=hex(r['rdx']))
        else:
            path=nnue_handles.get(r['rcx'])
            state.update(path=path,capture=path is not None,buffer=r['rdx'],capacity=r['r8'],countPointer=r['r9'])
            entry.update(path=path,requestedBytes=r['r8'])
        state['phase']='return';put64(ptr,'dr'+str(slot),ret)
    else:
        path=state.get('path');entry.update(path=path,result=hex(r['rax']))
        if name=='CreateFileW' and state['capture'] and r['rax'] not in (0,0xffffffffffffffff):
            nnue_handles[r['rax']]=path
            nnue_hashers[path]=hashlib.sha256()
            report['nnueTrace']['files'][path]={'opened':True,'bytesRead':0,'readCalls':0}
        elif name=='ReadFile' and state['capture'] and r['rax']:
            count=int.from_bytes(read(state['countPointer'],4),'little')
            if count>state['capacity']:raise RuntimeError('NNUE read length exceeds requested capacity')
            data=read(state['buffer'],count)
            if len(data)!=count:raise RuntimeError('NNUE read buffer could not be fully observed')
            entry['actualBytes']=count
            nnue_hashers[path].update(data)
            file_report=report['nnueTrace']['files'][path]
            file_report['bytesRead']+=count;file_report['readCalls']+=1
            file_report['readStreamSha256']=nnue_hashers[path].hexdigest()
        state['phase']='enter';put64(ptr,'dr'+str(slot),file_apis[name])
        if name=='CreateFileW' and state['capture'] and r['rax'] not in (0,0xffffffffffffffff) and TEST_PLAN.get('nnueParserTrace'):
            require_runtime_instruction(0xfa130,'push r15',2)
            nnue_slots[tid,0]={'name':'ModelParser','phase':'enter'}
            put64(ptr,'dr0',base+0xfa130)
    if state.get('capture'):
        report['nnueTrace']['events'].append(entry)
        if len(report['nnueTrace']['events'])>65000:raise RuntimeError('NNUE trace event bound exceeded')
    return True

continue_address=0
nt_exports={}
soft_breakpoint=None
license_watch_active=False
single_step_aux=0
field_trace=None
external_pending=None
external_export_cache={}
for name,args,restype in [
    ('WriteProcessMemory',[W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],W.BOOL),
    ('VirtualProtectEx',[W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)],W.BOOL),
    ('FlushInstructionCache',[W.HANDLE,C.c_void_p,C.c_size_t],W.BOOL)]:
    getattr(K,name).argtypes=args;getattr(K,name).restype=restype

def write_debug_byte(address,data):
    old=W.DWORD();ignored=W.DWORD();written=C.c_size_t()
    if not K.VirtualProtectEx(ph,address,len(data),0x40,C.byref(old)):raise C.WinError(C.get_last_error())
    try:
        payload=C.create_string_buffer(data)
        if not K.WriteProcessMemory(ph,address,payload,len(data),C.byref(written)) or written.value!=len(data):
            raise C.WinError(C.get_last_error())
        if not K.FlushInstructionCache(ph,address,len(data)):raise C.WinError(C.get_last_error())
    finally:
        if not K.VirtualProtectEx(ph,address,len(data),old.value,C.byref(ignored)):
            raise C.WinError(C.get_last_error())

def arm_pushfq_repair(tid,r,instruction,trace_index,trace_kind):
    if instruction.mnemonic!='pushfq':return
    if tid in pending_pushfq_repairs:
        raise RuntimeError(f'Overlapping pushfq repair for thread {tid}')
    pending_pushfq_repairs[tid]={'sourceRva':hex(r['rip']-base),'resume':r['rip']+instruction.size,
        'stack':(r['rsp']-8)&0xffffffffffffffff,'traceIndex':trace_index,'traceKind':trace_kind}

def repair_pushed_trap_flag(tid,r):
    pending=pending_pushfq_repairs.pop(tid,None)
    if pending is None:return
    if r['rip']!=pending['resume'] or r['rsp']!=pending['stack']:
        raise RuntimeError(f"pushfq repair boundary mismatch for thread {tid}: "
            f"rip={r['rip']:#x}/{pending['resume']:#x}, rsp={r['rsp']:#x}/{pending['stack']:#x}")
    raw=read(r['rsp'],8)
    if len(raw)!=8:raise RuntimeError(f"Unable to read pushed RFLAGS at {r['rsp']:#x}")
    before=int.from_bytes(raw,'little');after=before&~0x100
    if after!=before:
        value=C.c_uint64(after);written=C.c_size_t()
        if not K.WriteProcessMemory(ph,r['rsp'],C.byref(value),8,C.byref(written)) or written.value!=8:
            raise C.WinError(C.get_last_error())
    report.setdefault('pushfqRepairs',[]).append({'tid':tid,'sourceRva':pending['sourceRva'],
        'resumeRva':hex(r['rip']-base),'stack':hex(r['rsp']),'before':hex(before),'after':hex(after),
        'traceIndex':pending['traceIndex'],'traceKind':pending['traceKind']})

def publish_branch_trace(reason=None):
    if branch_trace_state is None:return
    target=report['bodyBranchTrace']
    target['instructions']=branch_trace_state['instructions']
    target['interestingInstructions']=branch_trace_state['interestingInstructions']
    target['discardedEvents']=branch_trace_state['discardedEvents']
    target['tailDiscarded']=max(0,branch_trace_state['instructions']-len(branch_trace_state['tail']))
    target['events']=list(branch_trace_state['events'])
    target['tail']=list(branch_trace_state['tail'])
    target['elapsedSeconds']=round(time.monotonic()-branch_trace_state['started'],6)
    if branch_trace_state.get('pendingControl'):
        target['pendingControl']=branch_trace_state['pendingControl']
    if reason is not None:target['finishReason']=reason

def handle_com_selector(tid,ptr,r,hardware):
    global key_trace_active,key_trace_tid,key_trace_dr7_base,key_trace_file
    if tid not in response_states or not report.get('dataIntervention'):return False
    response=response_states[tid];state=report['comSelection']
    if hardware&1 and r['rip']==base+0xe1784:
        require_runtime_instruction(0xe177d,'mov rax, qword ptr [rip + 0x53afc]',7)
        require_runtime_instruction(0xe1784,'mov r9d, dword ptr [rax]',3)
        pointer=int.from_bytes(read(base+0x135280,8),'little')
        assert pointer==r['rax'],'Thread source pointer mismatch'
        before=read(pointer,4);assert len(before)==4
        value=os.cpu_count() or 1;assert 1<=value<=256
        data=C.create_string_buffer(struct.pack('<I',value));written=C.c_size_t()
        assert K.WriteProcessMemory(ph,pointer,data,4,C.byref(written)) and written.value==4
        assert int.from_bytes(read(pointer,4),'little')==value
        state['threadLimitRepair']={'siteRva':'0xe1784','slotRva':'0x135280','before':int.from_bytes(before,'little'),'after':value}
        put64(ptr,'dr0',0);put64(ptr,'dr7',0x50)
        return True
    if hardware&1:
        if not state.get('phase'):
            return_address=int.from_bytes(read(r['rsp'],8),'little')
            assert base<return_address<base+0x3000000
            state['copy']={'returnRva':hex(return_address-base),'returnAddress':return_address,'destination':r['rax'],'source':response['address']+24,'bytes':608}
            state['phase']='copy-return'
            put64(ptr,'dr0',return_address);put64(ptr,'dr7',0x55)
            return True
        if state['phase']=='copy-return':
            cp=state['copy'];assert r['rip']==cp['returnAddress'] and r['rax']==cp['destination']
            cp['sourceMatches']=read(cp['source'],608)==read(cp['destination'],608)
            assert cp['sourceMatches']
            cp['copiedHex']=read(cp['destination'],608).hex()
            cp['nextCode']=[{'rva':hex(i.address-base),'text':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()} for i in dis.disasm(read(r['rip'],96),r['rip'])]
            snapshot(tid,ptr,'com-response-copy-complete')
            state['phase']='body-watch'
            put64(ptr,'dr0',cp['destination']);put64(ptr,'dr7',0xb0055)
            return True
        if state['phase']=='forward-return':
            cp=state['copy'];forward=state['forwards'][-1]
            assert r['rip']==forward['returnAddress'] and r['rax']==forward['destination']
            forward['sourceMatches']=read(forward['source'],608)==read(forward['destination'],608)
            assert forward['sourceMatches']
            cp['destination']=forward['destination']
            state['phase']='aes-entry'
            put64(ptr,'dr0',base+0x139cf22);put64(ptr,'dr7',0x55)
            return True
        if state['phase']=='aes-entry':
            cp=state['copy']
            assert r['rip']==base+0x139cf22
            if r['rdx']!=cp['destination']:return True
            ret=int.from_bytes(read(r['rsp'],8),'little')
            assert base<ret<base+0x3000000
            state['innerTransform']={'entryRva':'0x139cf22','source':r['rdx'],'destination':r['r8'],'context':r['rcx'],'returnAddress':ret,'returnRva':hex(ret-base),'cipherFirstBlockHex':read(r['rdx'],16).hex()}
            snapshot(tid,ptr,'com-inner-transform-entry')
            state['phase']='aes-return'
            put64(ptr,'dr0',ret);put64(ptr,'dr7',0x55)
            return True
        if state['phase']=='aes-return':
            tf=state['innerTransform'];assert r['rip']==tf['returnAddress']
            tf['plainFirstBlockHex']=read(tf['destination'],16).hex()
            snapshot(tid,ptr,'com-inner-transform-first-return')
            state['phase']='plaintext-watch'
            put64(ptr,'dr0',tf['destination']);put64(ptr,'dr7',0xb0055)
            return True
        if state['phase']=='plaintext-watch':
            tf=state['innerTransform']
            tf['consumer']={'rva':hex(r['rip']-base),'registers':{k:hex(v) for k,v in r.items() if not k.startswith('dr')},'beforeCodeHex':read(r['rip']-24,40).hex(),'plainFirstBlockHex':read(tf['destination'],16).hex()}
            snapshot(tid,ptr,'com-inner-plaintext-consumer')
            assert r['rip']==base+0x12453d7 and r['r11']==int.from_bytes(read(tf['destination'],8),'little')
            target_value=0x150f87c2a170c87c
            if True:
                before=read(tf['destination'],8)
                data=C.c_uint64(target_value);written=C.c_size_t()
                assert K.WriteProcessMemory(ph,tf['destination'],C.byref(data),8,C.byref(written)) and written.value==8
                put64(ptr,'r11',target_value)
                assert read(tf['destination'],8)==target_value.to_bytes(8,'little')
                state['secondQwordIntervention']={'scope':'Candidate second-layer first-qword equality test; not valid authorization','beforeHex':before.hex(),'afterHex':target_value.to_bytes(8,'little').hex(),'registerUpdated':'r11'}
            state['transitionSlot']=r['rsp']+16
            state['phase']='post-plaintext-flag-watch'
            state['postPlaintextShifts']=[]
            put64(ptr,'dr0',tf['destination']+8);put64(ptr,'dr7',0xb0055)
            return True
        if state['phase']=='post-plaintext-flag-watch':
            tf=state['innerTransform']
            mod=next((m for m in modules if m['base']<=r['rip']<m['base']+m['size']),None)
            state['secondPlaintextAccess']={'rva':hex(r['rip']-base),'module':mod['name'] if mod else None,'registers':{k:hex(v) for k,v in r.items() if not k.startswith('dr')},'secondQwordHex':read(tf['destination']+8,8).hex(),'beforeCodeHex':read(r['rip']-24,40).hex()}
            snapshot(tid,ptr,'com-second-plaintext-qword-access')
            assert r['rip']==base+0x133da38 and r['rbp']==int.from_bytes(read(tf['destination']+8,8),'little')
            if COM_CASE!='observe':
                value=0x3837a3a + {'entry0':0,'entry1':1,'entry2':-1}[COM_CASE]
                before=read(tf['destination']+8,8)
                data=C.c_uint64(value);written=C.c_size_t()
                assert K.WriteProcessMemory(ph,tf['destination']+8,C.byref(data),8,C.byref(written)) and written.value==8
                put64(ptr,'rbp',value)
                assert read(tf['destination']+8,8)==value.to_bytes(8,'little')
                state['secondFieldIntervention']={'beforeHex':before.hex(),'afterHex':value.to_bytes(8,'little').hex(),'registerUpdated':'rbp'}
            state['phase']='second-field-condition-watch'
            state['secondFieldConditions']=[]
            put64(ptr,'dr0',base+0x117baf8);put64(ptr,'dr7',0x55)
            return True
        if state['phase']=='second-field-condition-watch':
            require_runtime_instruction(0x117baf8,'shr rbx, cl',3)
            state['secondFieldConditions'].append({'rdiRva':hex(r['rdi']-base),'value':hex(r['rbx']),'count':r['rcx']&63,'responseDelta':response['address']-r['rsp']})
            if len(state['secondFieldConditions'])==1:
                snapshot(tid,ptr,'com-two-header-fields-passed-loop')
                put64(ptr,'dr0',0);put64(ptr,'dr7',0x54)
            return True
        if state['phase']=='body-watch':
            cp=state['copy'];mod=next((m for m in modules if m['base']<=r['rip']<m['base']+m['size']),None)
            if mod and mod['name'].lower()=='ucrtbase.dll' and r['rdx']==cp['destination'] and r['r8']==608:
                ret=int.from_bytes(read(r['rsp'],8),'little')
                assert base<ret<base+0x3000000
                state.setdefault('forwards',[]).append({'source':cp['destination'],'destination':r['rax'],'returnAddress':ret,'returnRva':hex(ret-base),'moduleRva':hex(r['rip']-mod['base'])})
                assert len(state['forwards'])<=4
                state['phase']='forward-return'
                put64(ptr,'dr0',ret);put64(ptr,'dr7',0x55)
                return True
            raise RuntimeError('Unexpected COM response transfer path')
    if hardware&2 and r['rip']==base+0x951e0:
        report['comNativeReached']={'rva':'0x951e0'}
        snapshot(tid,ptr,'com-native-initializer')
        state['phase']='native-init'
        report['status']='com-native-initializing'
        state['milestones']=[{'rva':'0x951e0','time':time.time()}]
        put64(ptr,'dr0',0);put64(ptr,'dr1',base+0x9577a);put64(ptr,'dr2',base+0xe5770)
        put64(ptr,'dr3',exit_exports['RtlExitUserProcess']);put64(ptr,'dr7',0x54)
        return True
    if hardware&2 and r['rip']==base+0x9577a:
        i=require_runtime_instruction(0x9577a,'mov r8, qword ptr [rip + 0x5956cf]',7)
        require_runtime_instruction(0x95781,'movdqa xmm0, xmmword ptr [rip + 0x5956c7]',8)
        target=i.address+i.size+i.operands[1].mem.disp
        assert target==base+0x62ae50
        before=read(target,16);assert len(before)==16
        data=C.create_string_buffer(bytes(16));written=C.c_size_t()
        assert K.WriteProcessMemory(ph,target,data,16,C.byref(written)) and written.value==16
        assert read(target,16)==bytes(16)
        state['zeroVector']={'atRva':'0x9577a','targetRva':'0x62ae50','beforeSetBits':int.from_bytes(before,'little').bit_count(),'afterSetBits':0}
        require_runtime_instruction(0xb6bb2,'lea rax, [rip + 0x574247]',7)
        require_runtime_instruction(0xb6bc2,'mov rax, qword ptr [rip + 0x576fa7]',7)
        require_runtime_instruction(0xb6d21,'mov rax, qword ptr [rip + 0x5875c8]',7)
        require_runtime_instruction(0x97732,'movdqa xmm1, xmmword ptr [rip + 0x5936e6]',8)
        lower=(1<<45)-1;upper=lower<<45
        palace=sum(1<<(rank*9+file) for rank in (0,1,2,7,8,9) for file in (3,4,5))
        pawn=[(x,y) for y in (3,4) for x in (0,2,4,6,8)]+[(x,y) for y in range(5,10) for x in range(9)]
        elephant=[(2,0),(6,0),(0,2),(4,2),(8,2),(2,4),(6,4)]
        advisor=[(3,0),(5,0),(4,1),(3,2),(5,2)]
        geometry={0x62ae00:('lower-half',lower),0x62ae10:('upper-half',upper),0x62ae20:('both-palaces',palace),
            0x62ae30:('lower-pawn',sum(1<<(y*9+x) for x,y in pawn)),0x62ae40:('upper-pawn',sum(1<<((9-y)*9+x) for x,y in pawn)),
            0x62db70:('elephant-squares',sum(1<<(y*9+x) for x,y in elephant+[(x,9-y) for x,y in elephant])),
            0x63e2f0:('advisor-squares',sum(1<<(y*9+x) for x,y in advisor+[(x,9-y) for x,y in advisor]))}
        king={rank*9+file for rank in (0,1,2,7,8,9) for file in (3,4,5)}
        elephant_set={y*9+x for x,y in elephant}|{(9-y)*9+x for x,y in elephant}
        advisor_set={y*9+x for x,y in advisor}|{(9-y)*9+x for x,y in advisor}
        state['membershipRepair']=[]
        checks=(('king',0xb9a4b,0x135278,'mov rax, qword ptr [rip + 0x7b826]',king),
                ('elephant',0xb9a57,0x13c4c0,'mov rax, qword ptr [rip + 0x82a62]',elephant_set),
                ('advisor',0xb9a68,0x1f1510,'mov rax, qword ptr [rip + 0x137aa1]',advisor_set))
        for label,site,slot,text,allowed in checks:
            inst=require_runtime_instruction(site,text,7)
            assert inst.address+inst.size+inst.operands[1].mem.disp==base+slot, label+' slot mismatch'
            raw_pointer=read(base+slot,8);assert len(raw_pointer)==8,label+' unreadable slot'
            pointer=int.from_bytes(raw_pointer,'little');assert pointer>0,label+' null pointer'
            before=read(pointer,90);assert len(before)==90,label+' unreadable table'
            replacement=bytes(0 if square in allowed else 255 for square in range(90))
            buf=C.create_string_buffer(replacement);written=C.c_size_t()
            assert K.WriteProcessMemory(ph,pointer,buf,90,C.byref(written)) and written.value==90,label+' write failure'
            assert read(pointer,90)==replacement,label+' readback mismatch'
            state['membershipRepair'].append({'label':label,'siteRva':hex(site),'slotRva':hex(slot),
                'pointer':hex(pointer),'beforeSha256':hashlib.sha256(before).hexdigest(),
                'afterSha256':hashlib.sha256(replacement).hexdigest(),'allowedCount':len(allowed)})
        require_runtime_instruction(0x983bd,'mov rcx, qword ptr [rip + 0x16398c]',7)
        require_runtime_instruction(0xb5c3d,'mov rax, qword ptr [rip + 0x14610c]',7)
        require_runtime_instruction(0xb5c52,'add r11b, byte ptr [rax + rcx]',4)
        raw=read(base+0x1fbd50,8);assert len(raw)==8,'horse pointer unreadable'
        horse_pointer=int.from_bytes(raw,'little');before=read(horse_pointer,41)
        assert len(before)==41,'horse table unreadable'
        expected=bytearray(before);directions={-19:-9,-17:-9,-11:-1,-7:1,7:-1,11:1,17:9,19:9}
        changes=[]
        for delta,offset in directions.items():
            index=20+delta;value=bytes([offset&255]);buf=C.create_string_buffer(value);written=C.c_size_t()
            assert K.WriteProcessMemory(ph,horse_pointer+index,buf,1,C.byref(written)) and written.value==1,'horse write failed'
            expected[index]=offset&255
            changes.append({'difference':delta,'before':before[index],'afterSigned':offset})
        assert read(horse_pointer,41)==bytes(expected),'horse readback mismatch'
        state['horseRepair']={'pointerRva':'0x1fbd50','changes':changes,'otherBytesUnchanged':True}
        state['geometry']=[]
        for at,(meaning,value) in geometry.items():
            before=read(base+at,16);replacement=value.to_bytes(16,'little');buf=C.create_string_buffer(replacement)
            assert len(before)==16
            assert K.WriteProcessMemory(ph,base+at,buf,16,C.byref(written)) and written.value==16
            assert read(base+at,16)==replacement
            state['geometry'].append({'rva':hex(at),'meaning':meaning,'beforeSetBits':int.from_bytes(before,'little').bit_count(),'afterSetBits':value.bit_count()})
        state['milestones'].append({'rva':'0x9577a','time':time.time()})
        snapshot(tid,ptr,'com-zero-vector-corrected')
        put64(ptr,'dr0',base+0xe1784);put64(ptr,'dr1',0);put64(ptr,'dr7',0x51)
        return True
    if hardware&4 and r['rip']==base+0xe5770:
        state['milestones'].append({'rva':'0xe5770','time':time.time()})
        state['featureTables']={}
        for label,at,length in (('base',0x1f09d0,2880),('threats',0x236600,4147200)):
            raw_table=read(base+at,length);assert len(raw_table)==length
            values=struct.unpack('<'+'H'*(length//2),raw_table)
            state['featureTables'][label]={'rva':hex(at),'bytes':length,'sha256':hashlib.sha256(raw_table).hexdigest(),'maximum':max(values),'outOfRange':sum(v>= (689 if label=='base' else 50620) for v in values)}
        assert all(t['outOfRange']==0 for t in state['featureTables'].values()), 'Feature index still outside model bounds'
        snapshot(tid,ptr,'com-protocol-reached')
        state['phase']='protocol'
        put64(ptr,'dr0',0);put64(ptr,'dr1',0);put64(ptr,'dr2',0);put64(ptr,'dr7',0x40)
        expected_tables={'base':'0c172b70b4a41300db8c752868f0a38cb1c9839b201edd24e9f5829cf8cc71f2',
                         'threats':'4cc1e843e63f5ce7d003d28af1c743660fe964215ef53da7e06c63a418b1cbc8'}
        assert all(state['featureTables'][label]['sha256']==digest for label,digest in expected_tables.items()),'COM feature hash mismatch'
        assert state.get('threadLimitRepair'),'Thread source repair not reached'
        for other_tid in thread_ids(proc.pid):
            if other_tid==tid:
                for slot in range(4):put64(ptr,'dr'+str(slot),0)
                put64(ptr,'dr6',0);put64(ptr,'dr7',0)
            else:
                handle,raw,context=get_context(other_tid)
                try:
                    for slot in range(4):put64(context,'dr'+str(slot),0)
                    put64(context,'dr6',0);put64(context,'dr7',0);apply_context(handle,context)
                finally:K.CloseHandle(handle)
        report['featureTableVerification']={'passed':True,'tables':state['featureTables']}
        report['bridgeReady']=True;report['status']='bridge-ready'
        return True
    return False
def arm_files(tid,initial=False):
    th,raw,ptr=get_context(tid)
    try:
        if not initial:arm_network_context(tid,ptr)
        else:
            for slot in range(3):put64(ptr,'dr'+str(slot),0)
            put64(ptr,'dr3',continue_address);put64(ptr,'dr6',0);put64(ptr,'dr7',0x40)
        apply_context(th,ptr)
    finally:K.CloseHandle(th)

def arm_network_context(tid,ptr):
    for slot,name in enumerate(network_names):
        put64(ptr,'dr'+str(slot),network_exports[name])
        network_slots[tid,slot]={'name':name,'phase':'enter'}
    put64(ptr,'dr6',0);put64(ptr,'dr7',0x55)
    network_threads.add(tid)
    report['status']='observing-fixture-network'

def apply_case_repairs(uci_probe, case):
    if case.get('replayEvasionGeometry'):
        source_version=case['replayEvasionGeometry'];assert re.fullmatch(r'v[0-9]+',source_version)
        source_raw=(ROOT/'evidence'/source_version/'boundary-report.json').read_bytes()
        original=json.loads(source_raw)['zfSelector']['nativeProbe'][0]['extraGeometry']
        changes=[]
        for target in (0x630b78,0x631300):
            replacement=bytes.fromhex(original[hex(target)]);assert len(replacement)==16
            before=read(base+target,16);buffer=C.create_string_buffer(replacement);written=C.c_size_t()
            if not K.WriteProcessMemory(ph,base+target,buffer,16,C.byref(written)) or written.value!=16:
                raise RuntimeError('Evasion baseline replay failed')
            assert read(base+target,16)==replacement
            changes.append({'rva':hex(target),'beforeHex':before.hex(),'afterHex':replacement.hex()})
        report['evasionGeometryReplay']={'sourceVersion':source_version,'sourceReportSha256':hashlib.sha256(source_raw).hexdigest(),'changes':changes}
    if case.get('repairEvasionGeometry'):
        assert not report.get('evasionGeometryRepair')
        elephant=[(2,0),(6,0),(0,2),(4,2),(8,2),(2,4),(6,4)]
        advisor=[(3,0),(5,0),(4,1),(3,2),(5,2)]
        targets={0x630b78:('elephant-reachable-squares',elephant),0x631300:('advisor-reachable-squares',advisor)}
        changes=[]
        for target,(meaning,points) in targets.items():
            value=sum(1<<(y*9+x) for x,y in points+[(x,9-y) for x,y in points])
            replacement=value.to_bytes(16,'little');before=read(base+target,16)
            buffer=C.create_string_buffer(replacement);written=C.c_size_t()
            if not K.WriteProcessMemory(ph,base+target,buffer,16,C.byref(written)) or written.value!=16:
                raise RuntimeError('Evasion geometry write failed')
            assert read(base+target,16)==replacement
            changes.append({'rva':hex(target),'meaning':meaning,'beforeHex':before.hex(),'afterHex':replacement.hex(),'setBits':value.bit_count()})
        report['evasionGeometryRepair']={'afterCompletedCases':len(uci_probe['perftResults']),'changes':changes,
            'scope':'Two 128-bit geometric filter masks, changed only between completed perft commands'}
    if case.get('repairPawnGeometry'):
        assert not report.get('pawnGeometryRepair')
        points=[(x,y) for y in (3,4) for x in (0,2,4,6,8)]+[(x,y) for y in range(5,10) for x in range(9)]
        changes=[]
        for target,points_for_side in ((0x62de30,points),(0x62de40,[(x,9-y) for x,y in points])):
            value=sum(1<<(y*9+x) for x,y in points_for_side);replacement=value.to_bytes(16,'little')
            before=read(base+target,16);buffer=C.create_string_buffer(replacement);written=C.c_size_t()
            if not K.WriteProcessMemory(ph,base+target,buffer,16,C.byref(written)) or written.value!=16:
                raise RuntimeError('Pawn reachability write failed')
            assert read(base+target,16)==replacement
            changes.append({'rva':hex(target),'beforeHex':before.hex(),'afterHex':replacement.hex(),'setBits':value.bit_count()})
        report['pawnGeometryRepair']={'afterCompletedCases':len(uci_probe['perftResults']),'changes':changes,
            'scope':'Correct prior palace assumption: native piece code 1 is pawn; reachable squares per side'}
def send_perft_case(uci_probe, case):
    apply_case_repairs(uci_probe,case)
    position='position fen '+case['fen'] if case.get('fen') else 'position startpos'
    if case.get('moves'):position+=' moves '+' '.join(case['moves'])
    commands=[position]
    if case.get('diagnosticEval'):
        commands+=['eval','eval']
    commands+=['go perft '+str(case['depth'])]
    uci_probe['outputStart']=len(stdout)
    proc.stdin.write(('\n'.join(commands)+'\n').encode());proc.stdin.flush()
    uci_probe['commands']+=commands
    uci_probe['stage']='perft';uci_probe['perftStarted']=time.monotonic()
    uci_probe['perftDepth']=case['depth'];uci_probe['activeCase']=case

try:
    report['awakeRequest']=bool(K.SetThreadExecutionState(0x80000001))
    engine=RUN/'cyclone-nn-com.exe'
    report['engineSha256']=hashlib.sha256(engine.read_bytes()).hexdigest()
    if TEST_PLAN and TEST_PLAN.get('nnueFileTrace'):
        model=RUN/'cyclone-eval.nnue'
        report['nnueModel']={'path':str(model),'bytes':model.stat().st_size,
            'sha256':hashlib.sha256(model.read_bytes()).hexdigest()}
        if TEST_PLAN.get('nnueModelAbsent'):
            hidden=RUN/'cyclone-eval.nnue.diagnostic-backup'
            assert not RUNTIME and model.resolve().parent==RUN.resolve() and hidden.resolve().parent==RUN.resolve()
            assert not hidden.exists()
            model.rename(hidden);nnue_hidden_model=(model,hidden)
            report['nnueModel']['temporarilyAbsent']=True
    proc=subprocess.Popen([str(engine)],cwd=RUN,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW|2)
    attached=True;K.DebugSetProcessKillOnExit(True)
    if BRIDGE:
        bridge_job=K.CreateJobObjectW(None,None)
        if not bridge_job:raise C.WinError(C.get_last_error())
        job_limits=C.create_string_buffer(144)
        struct.pack_into('<I',job_limits,16,0x2000)
        if not K.SetInformationJobObject(bridge_job,9,job_limits,144) or not K.AssignProcessToJobObject(bridge_job,int(proc._handle)):
            raise C.WinError(C.get_last_error())
        report['bridgeKillOnCloseJob']=True
    readers=[threading.Thread(target=consume,args=(s,d),daemon=True) for s,d in [(proc.stdout,stdout),(proc.stderr,stderr)]]
    for t in readers:t.start()
    deadline=time.monotonic()+(65 if MODE in ('fixture-fields','fixture-key-trace','fixture-response-bodytrace','fixture-response-bodybranch','fixture-response-exittrace','fixture-response-slotwatch') else 45)
    if BRIDGE:
        bridge_seconds=TEST_PLAN.get('bridgeLimitSeconds',60)
        assert 30<=bridge_seconds<=7200
        deadline=time.monotonic()+bridge_seconds
        if RUNTIME:deadline=float('inf')
    initialized=False
    while time.monotonic()<deadline:
        if RUNTIME and os.environ.get('CYCLONE_CONTROLLER_HANDLE'):
            if K.WaitForSingleObject(int(os.environ['CYCLONE_CONTROLLER_HANDLE']),0)!=258 or not Path(os.environ['CYCLONE_CONTROLLER_MARKER']).is_file():
                bridge_stop.set()
                if report.get('bridgeDetached') and proc.poll() is None:
                    try:
                        with bridge_input_lock:
                            proc.stdin.write(b'stop\nquit\n');proc.stdin.flush()
                        report['controllerStopExit']=proc.wait(timeout=3)
                        report['controllerStopGraceful']=report['controllerStopExit']==0
                    except (OSError,subprocess.TimeoutExpired):report['controllerStopGraceful']=False
                report['status']='controller-closed';break
        if BRIDGE and report.get('bridgeDetached'):
            if proc.poll() is not None:
                report['naturalExitCode']=proc.returncode;report['status']='bridge-process-exited';break
            time.sleep(0.02)
            continue
        if report.get('uciProbe'):
            protocol_lines=stdout.decode('utf-8',errors='replace').splitlines()
            uci_probe=report['uciProbe']
            if uci_probe['stage']=='uci' and 'uciok' in protocol_lines:
                uci_probe['uciok']=True;uci_probe['uciokTime']=time.time()
                commands=[]
                if TEST_PLAN:
                    for option,value in TEST_PLAN.get('uciOptions',{}).items():
                        assert (option=='Threads' and 1<=value<=16) or (option=='Hash' and 16<=value<=256)
                        commands.append('setoption name '+option+' value '+str(value))
                commands.append('isready');proc.stdin.write(('\n'.join(commands)+'\n').encode());proc.stdin.flush()
                uci_probe['commands']+=commands;uci_probe['stage']='isready'
            if uci_probe['stage']=='isready' and 'readyok' in protocol_lines:
                uci_probe['readyok']=True;uci_probe['readyokTime']=time.time()
                if MODE in ('fixture-response-zfperft','fixture-response-zfgeometry','fixture-response-zfsearch'):
                    uci_probe['perftResults']=[]
                    send_perft_case(uci_probe,TEST_PLAN['perft'][0] if TEST_PLAN else {'depth':1,'expected':44})
                else:
                    uci_probe['stage']='complete';report['status']='synthetic-response-uci-ready'
                    break
            if uci_probe['stage']=='perft':
                current_output=bytes(stdout[uci_probe['outputStart']:]).decode('utf-8',errors='replace')
                perft_match=re.search(r'^Nodes searched:[ \t]*(\d+)[ \t]*\r?\n',current_output,re.MULTILINE)
                if perft_match:
                    case=uci_probe['activeCase'];depth=case['depth'];nodes=int(perft_match.group(1))
                    expected=case.get('expected')
                    divide={move:int(count) for move,count in re.findall(r'^([a-i][0-9][a-i][0-9]):[ \t]+(\d+)[ \t]*\r?$',current_output[:perft_match.end()],re.MULTILINE)}
                    uci_probe['perftResults'].append({'depth':depth,'moves':case.get('moves',[]),
                        'fen':case.get('fen'),'label':case.get('label'),'nodes':nodes,'expected':expected,
                        'matches':None if expected is None else nodes==expected,'divide':divide,
                        'divideSumMatches':sum(divide.values())==nodes,'output':current_output[:perft_match.end()]})
                    if case.get('referenceDivide'):
                        uci_probe['perftResults'][-1]['referenceDivideMatches']=(divide==case['referenceDivide'])
                    if TEST_PLAN:
                        completed=len(uci_probe['perftResults'])
                        if completed<len(TEST_PLAN['perft']):send_perft_case(uci_probe,TEST_PLAN['perft'][completed])
                        elif TEST_PLAN.get('search') and all(item['matches'] for item in uci_probe['perftResults'][-TEST_PLAN['search']['requireLastCases']:]):
                            command='go depth '+str(TEST_PLAN['search']['depth'])
                            proc.stdin.write(('position startpos\n'+command+'\n').encode());proc.stdin.flush()
                            uci_probe['commands']+=['position startpos',command]
                            uci_probe['stage']='search';uci_probe['searchStarted']=time.monotonic()
                            uci_probe['searchThreadIds']=thread_ids(proc.pid)
                        else:
                            uci_probe['stage']='complete';report['status']='synthetic-response-perft-suite-complete';break
                    elif MODE in ('fixture-response-zfgeometry','fixture-response-zfsearch') and nodes==expected and depth<3:
                        send_perft_case(uci_probe,{'depth':depth+1,'expected':{2:1920,3:79666}[depth+1]})
                    elif MODE=='fixture-response-zfsearch' and nodes==expected and depth==3:
                        proc.stdin.write(b'position startpos\ngo depth 4\n');proc.stdin.flush()
                        uci_probe['commands']+=['position startpos','go depth 4']
                        uci_probe['stage']='search';uci_probe['searchStarted']=time.monotonic()
                    else:
                        uci_probe['stage']='complete';report['status']='synthetic-response-perft-complete'
                        break
                if time.monotonic()-uci_probe['perftStarted']>10:
                    proc.stdin.write(b'stop\n');proc.stdin.flush();uci_probe['commands'].append('stop')
                    report['status']='synthetic-response-perft-timeout';break
            if uci_probe['stage']=='search':
                bestmove_match=re.search(r'^bestmove[ \t]+(\S+)(?:[ \t]+ponder[ \t]+(\S+))?[ \t]*\r?\n',stdout.decode('utf-8',errors='replace'),re.MULTILINE)
                if bestmove_match:
                    uci_probe['bestmove']=bestmove_match.group(1);uci_probe['ponder']=bestmove_match.group(2)
                    uci_probe['completedThreadIds']=thread_ids(proc.pid)
                    uci_probe['searchElapsed']=round(time.monotonic()-uci_probe['searchStarted'],3)
                    uci_probe['stage']='complete';report['status']='synthetic-response-bestmove'
                    break
                search_elapsed=time.monotonic()-uci_probe['searchStarted']
                if search_elapsed>10 and not uci_probe.get('stopSent'):
                    proc.stdin.write(b'stop\n');proc.stdin.flush();uci_probe['commands'].append('stop');uci_probe['stopSent']=True
                if search_elapsed>13:
                    report['status']='synthetic-response-search-timeout';break
        if b'input serial number' in stdout.lower():
            if TEST_PLAN and TEST_PLAN.get('allowSyntheticSerialInput'):
                if not report.get('runtimeSyntheticInputSent'):
                    proc.stdin.write(b'111111111222222222333\n');proc.stdin.flush()
                    report['runtimeSyntheticInputSent']=True
                    report['syntheticInputPurpose']='Local startup input; all subsequent network operations simulated and OS network blocking required'
                # The original prompt remains in the output buffer after input.
        if b'input serial number' in stdout.lower() and not report.get('runtimeSyntheticInputSent'):
            report['promptThreadDebugRegisters']=[]
            for task_tid in thread_ids(proc.pid):
                th=K.OpenThread(0x1a,False,task_tid)
                if not th:continue
                suspended=K.SuspendThread(th)
                try:
                    if suspended==0xffffffff:continue
                    check,buf,ptr=get_context(task_tid)
                    try:
                        state=regs(ptr)
                        report['promptThreadDebugRegisters'].append({'tid':task_tid,
                            'state':{n:hex(v) for n,v in state.items() if n.startswith('dr') or n=='rip'}})
                    finally:K.CloseHandle(check)
                finally:
                    if suspended!=0xffffffff:K.ResumeThread(th)
                    K.CloseHandle(th)
            report['status']='startup-and-prompt-captured'
            break
        event=C.create_string_buffer(176)
        if not K.WaitForDebugEvent(event,100):continue
        raw=event.raw;kind,pid,tid=struct.unpack_from('<III',raw)
        pending=(pid,tid);continuation=0x10002
        if kind==3:
            hf,hp,ht,base=struct.unpack_from('<QQQQ',raw,16)
            if hf:K.CloseHandle(hf)
            handles.extend([hp,ht]);ph=K.OpenProcess(0x438,False,pid)
            report['base']=hex(base)
        elif kind==2:
            handles.append(struct.unpack_from('<Q',raw,16)[0])
            if report.get('evaluationTraceInstalled'):
                eval_handle,eval_buffer,eval_ptr=get_context(tid)
                try:arm_eval_thread(tid,eval_ptr);apply_context(eval_handle,eval_ptr)
                finally:K.CloseHandle(eval_handle)
            elif initialized and not report.get('bridgeReady'):arm_files(tid,initial=True)
        elif kind==6:
            hf=struct.unpack_from('<Q',raw,16)[0]
            if hf:K.CloseHandle(hf)
        elif kind==5:
            report['naturalExitCode']=struct.unpack_from('<I',raw,16)[0]
            report['status']='bridge-process-exited' if BRIDGE else 'process-exited'
            K.ContinueDebugEvent(pid,tid,continuation);pending=None;break
        elif kind==1:
            code=struct.unpack_from('<I',raw,16)[0]
            addr=struct.unpack_from('<Q',raw,32)[0]
            first=struct.unpack_from('<I',raw,168)[0]
            if code==0x80000003 and not initialized:
                modules=h.modules(pid)
                report['modules']=modules
                kernelbase=next(m for m in modules if m['name'].lower()=='kernelbase.dll')
                dll=pefile.PE(kernelbase['path'])
                for sym in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name and sym.name.decode() in file_names and not sym.forwarder:
                        file_apis[sym.name.decode()]=kernelbase['base']+sym.address
                if set(file_apis)!=set(file_names):raise RuntimeError('File API exports incomplete')
                report['apiAddresses']={n:hex(a) for n,a in file_apis.items()}
                ntdll=next(m for m in modules if m['name'].lower()=='ntdll.dll')
                ntpe=pefile.PE(ntdll['path'])
                nt_exports={ntdll['base']+s.address:s.name.decode(errors='replace') for s in ntpe.DIRECTORY_ENTRY_EXPORT.symbols if s.name and not s.forwarder}
                continue_address=ntdll['base']+next(s.address for s in ntpe.DIRECTORY_ENTRY_EXPORT.symbols if s.name==b'NtContinue')
                if MODE=='fixture-network' or MODE in REQUEST_MODES or MODE in RESPONSE_MODES:
                    net_module=next(m for m in modules if m['name'].lower()=='ws2_32.dll')
                    net_pe=pefile.PE(net_module['path'])
                    network_exports={s.name.decode():net_module['base']+s.address for s in net_pe.DIRECTORY_ENTRY_EXPORT.symbols
                        if s.name and s.name.decode() in network_names and not s.forwarder}
                    exit_exports={s.name.decode():ntdll['base']+s.address for s in ntpe.DIRECTORY_ENTRY_EXPORT.symbols
                        if s.name and s.name.decode() in ('RtlExitUserProcess','NtTerminateProcess') and not s.forwarder}
                    if len(network_exports)!=4 or len(exit_exports)!=2:raise RuntimeError('Network or termination exports incomplete')
                    report['networkExports']={n:hex(a) for n,a in network_exports.items()}
                    report['exitExports']={n:hex(a) for n,a in exit_exports.items()}
                    runtime_module=next(m for m in modules if m['name'].lower()=='ucrtbase.dll')
                    runtime_pe=pefile.PE(runtime_module['path'])
                    runtime_exit=runtime_module['base']+next(s.address for s in runtime_pe.DIRECTORY_ENTRY_EXPORT.symbols
                        if s.name==b'exit' and not s.forwarder)
                    report['runtimeExit']={'module':runtime_module['name'],'address':hex(runtime_exit),
                        'moduleRva':hex(runtime_exit-runtime_module['base'])}
                report['continueApi']=hex(continue_address)
                for task_tid in thread_ids(pid):arm_files(task_tid,initial=True)
                initialized=True
            elif code==0x80000003 and soft_breakpoint and addr==soft_breakpoint['address']:
                write_debug_byte(addr,soft_breakpoint['original'])
                if read(addr,1)!=soft_breakpoint['original']:raise RuntimeError('Breakpoint restoration mismatch')
                report['temporaryBreakpoint']['restored']=True
                th,buf,ptr=get_context(tid)
                try:
                    put64(ptr,'rip',addr)
                    apply_context(th,ptr)
                    snapshot(tid,ptr,'continuation-entry-restored')
                finally:K.CloseHandle(th)
                arm_files(tid)
                soft_breakpoint=None
            elif code==0x80000001 and body_guard and body_guard['page']<=struct.unpack_from('<Q',raw,56)[0]<body_guard['page']+body_guard['size']:
                th,buf,ptr=get_context(tid)
                try:
                    r=regs(ptr);access,at=struct.unpack_from('<QQ',raw,48)
                    instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                    size=1
                    if instruction:
                        for operand in instruction.operands:
                            if operand.type==capstone.x86.X86_OP_MEM:size=max(size,operand.size)
                    overlap=at<body_guard['address']+608 and at+size>body_guard['address']
                    item={'rva':hex(r['rip']-base),'address':hex(at),'bodyOffset':at-body_guard['address'],
                        'access':access,'instruction':instruction.mnemonic+' '+instruction.op_str if instruction else None,
                        'operandMaximumSize':size,'overlapsBody':overlap}
                    report.setdefault('bodyPageAccesses',[]).append(item)
                    if overlap:
                        snapshot(tid,ptr,'response-body-first-page-access')
                        report['status']='synthetic-response-body-access'
                    elif len(report['bodyPageAccesses'])>=2000:
                        report['status']='synthetic-response-body-page-limit'
                    else:
                        body_guard_pending.add(tid);flags(ptr,enable=0x100)
                        apply_context(th,ptr)
                finally:K.CloseHandle(th)
            elif code==0x80000004:
                th,buf,ptr=get_context(tid)
                try:
                    r=regs(ptr);hardware=r['dr6']&15
                    execution_hardware=execution_breakpoint_hit(hardware,r)
                    repair_pushed_trap_flag(tid,r)
                    if tid in body_guard_pending:
                        body_guard_pending.discard(tid);flags(ptr,disable=0x100)
                        old=W.DWORD()
                        if not K.VirtualProtectEx(ph,body_guard['page'],body_guard['size'],body_guard['protection']|0x100,C.byref(old)):
                            raise C.WinError(C.get_last_error())
                    report['hardwareHitCount']=report.get('hardwareHitCount',0)+bool(hardware)
                    exit_trace_terminal=(MODE=='fixture-response-exittrace' and key_trace_active
                        and tid==key_trace_tid and r['rip']==exit_exports['RtlExitUserProcess'])
                    if handle_com_selector(tid,ptr,r,hardware):
                        r=regs(ptr)
                    elif handle_eval(tid,ptr,r,hardware):
                        pass
                    elif handle_nnue_file(tid,ptr,r,hardware):
                        pass
                    elif tid in response_states and (hardware or exit_trace_terminal):
                        response=response_states[tid]
                        if exit_trace_terminal:
                            report['syntheticResponse']['exitCode']=r['rcx']&0xffffffff
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            if report.get('responseBody'):
                                body=report['responseBody'];body['atExitHex']=read(int(body['address'],16),body['bytes']).hex()
                            snapshot(tid,ptr,'synthetic-response-exit-request')
                            report['status']='synthetic-response-exit-request'
                            report['keyTrace']['terminal']={'name':'RtlExitUserProcess','address':hex(r['rip']),
                                'threadId':tid,'exitCode':r['rcx']&0xffffffff}
                            report['keyTrace']['complete']=True
                            key_trace_active=False;key_trace_paused=False;flags(ptr,disable=0x100)
                        elif key_trace_active and hardware&1 and r['rip']==key_trace_resume:
                            put64(ptr,'dr7',key_trace_dr7_base);key_trace_resume=0
                        elif hardware&1 and response.get('bodyBoundaryStage')=='copy-complete' and r['rip']==base+0x13c62dc:
                            copied=read(r['rax'],608)
                            if len(copied)!=608 or copied!=read(response['address']+24,608):
                                raise RuntimeError('Copied response body boundary mismatch')
                            report['responseBody']={'address':hex(r['rax']),'bytes':608,'sourceOffset':24,
                                'copyVerified':True,'beforeHex':copied.hex(),'entryRva':'0x13c62dc',
                                'returnRva':'0x13c62e1','entryRegisters':{n:hex(v) for n,v in r.items()}}
                            snapshot(tid,ptr,'response-body-copy-complete')
                            response['bodyBoundaryStage']='call-return'
                            put64(ptr,'dr0',base+0x13c62e1)
                            if MODE=='fixture-response-bodytrace':
                                response['bodyBoundaryStage']='tracing'
                                key_trace_file=(OUT/'key-trace.jsonl').open('w',encoding='utf-8')
                                key_trace_active=True;key_trace_dr7_base=0x50|4|(0xf<<20)
                                put64(ptr,'dr1',r['rax']);put64(ptr,'dr7',key_trace_dr7_base)
                                report['keyTrace']={'scope':'After copying synthetic response[24:632], with first dword intervention only',
                                    'startRva':'0x13c62dc','instructions':0}
                            if MODE=='fixture-response-bodybranch':
                                response['bodyBoundaryStage']='branch-tracing'
                                anchor_instruction=require_runtime_instruction(
                                    0x10d01a2,'mov rdi, qword ptr [rdi + r8 - 0x1f933200]',8)
                                branch_trace_active=True;branch_trace_tid=tid;branch_trace_resume=0
                                branch_trace_state={'started':time.monotonic(),'instructions':0,
                                    'interestingInstructions':0,'discardedEvents':0,
                                    'events':deque(maxlen=BRANCH_TRACE_EVENT_LIMIT),
                                    'tail':deque(maxlen=BRANCH_TRACE_TAIL_LIMIT),'pendingControl':None}
                                report['bodyBranchTrace']={'scope':'Same-thread control-flow trace after synthetic response[24:632] copy',
                                    'startRva':'0x13c62dc','threadId':tid,
                                    'markerRsp':hex(response['bodyBranchMarkerRsp']),
                                    'sourceAnchor':{'rva':'0x10d01a2','bytes':anchor_instruction.bytes.hex(),
                                        'expectedAddress':hex(response['bodyBranchMarkerRsp']+0x98),'expectedValue':'0x1'},
                                    'terminalRvas':['0x10d01a2 conditional source anchor','0xbbc0c','0xe5770'],
                                    'eventClasses':['jcc','jmp','call','ret','cmp','test','cmovcc','setcc'],
                                    'eventLimit':BRANCH_TRACE_EVENT_LIMIT,'tailLimit':BRANCH_TRACE_TAIL_LIMIT,
                                    'instructionLimit':BRANCH_TRACE_INSTRUCTION_LIMIT,
                                    'instrumentation':'TF single-step on one thread; execution stops at a terminal RVA; no RIP change or control-flow skip'}
                                for branch_slot in range(4):put64(ptr,'dr'+str(branch_slot),0)
                                put64(ptr,'dr7',0)
                            if MODE=='fixture-response-bodyguard':
                                page=r['rax']&~0xfff;size=((r['rax']+608+0xfff)&~0xfff)-page
                                old=W.DWORD()
                                if not K.VirtualProtectEx(ph,page,size,0x104,C.byref(old)):
                                    raise C.WinError(C.get_last_error())
                                body_guard={'page':page,'size':size,'address':r['rax'],'protection':old.value&~0x100}
                                report['bodyPageGuard']={**body_guard,'note':'Temporary PAGE_GUARD observation until first structure access; memory protection is an instrumentation change.'}
                                response['bodyBoundaryStage']='page-guard'
                                put64(ptr,'dr7',0x50)
                        elif hardware&1 and response.get('bodyBoundaryStage')=='call-return' and r['rip']==base+0x13c62e1:
                            body=report['responseBody']
                            body['afterHex']=read(int(body['address'],16),body['bytes']).hex()
                            body['returnRegisters']={n:hex(v) for n,v in r.items()}
                            snapshot(tid,ptr,'response-body-call-return')
                            report['status']='synthetic-response-body-return'
                        elif MODE in ZF_SELECT_MODES and response.get('zfSelector') and hardware:
                            selector=response['zfSelector'];selection_report=selector['report']
                            selection_report['hardwareHits']+=1
                            terminal=None;matched=False
                            event={'rva':hex(r['rip']-base),'threadId':tid,
                                'registers':{name:hex(value) for name,value in r.items() if not name.startswith('dr')}}
                            if selector['phase']=='feature-writer-watch' and hardware&3:
                                matched=True
                                event['previousInstructionCandidates']=[]
                                for back in range(1,16):
                                    previous=next(dis.disasm(read(r['rip']-back,back),r['rip']-back,count=1),None)
                                    if previous and previous.size==back:
                                        event['previousInstructionCandidates'].append({'rva':hex(previous.address-base),
                                            'bytes':previous.bytes.hex(),'instruction':(previous.mnemonic+' '+previous.op_str).strip()})
                                writer_debug_mask=r['dr7']
                                for slot,(name,address) in enumerate((('base',0x1f3abe),('threats',0x28bec8))):
                                    if not hardware&(1<<slot):continue
                                    observation={**event,'table':name,'watchedRva':hex(address),
                                        'value':int.from_bytes(read(base+address,2),'little'),
                                        'stackHex':read(r['rsp'],128).hex()}
                                    if observation['value']==0:
                                        report.setdefault('featureTableZeroWrites',[]).append(observation)
                                        assert len(report['featureTableZeroWrites'])<=32, 'Excessive table clears'
                                        continue
                                    report['featureTableWriters'].append(observation)
                                    code_start=(r['rip']-base)&~0xfff
                                    (OUT/('feature-writer-'+name+'-'+hex(code_start)+'.bin')).write_bytes(read(base+code_start,0x2000))
                                    put64(ptr,'dr'+str(slot),0)
                                    writer_debug_mask&=~((3<<(slot*2))|(15<<(16+slot*4)))
                                    put64(ptr,'dr7',writer_debug_mask)
                                if len(report['featureTableWriters'])>=2:
                                    terminal={'kind':'feature-table-writers-captured'}
                            elif selector['phase']=='protocol' and TEST_PLAN and TEST_PLAN.get('nativeProbeSites') and hardware&7:
                                matched=True
                                event['case']=report.get('uciProbe',{}).get('activeCase')
                                event['xmmHex']={str(n):C.string_at(ptr+416+n*16,16).hex() for n in range(8)}
                                if r['rip']==base+0xb675b:
                                    event['betweenMaskHex']=read(r['rax']+r['rcx'],16).hex()
                                    event['positionHex']=read(r['r13'],0x160).hex()
                                event['stackHex']=read(r['rsp'],0xa0).hex()
                                event['extraGeometry']={hex(site):read(base+site,16).hex() for site in (0x630b78,0x631300)}
                                selection_report['nativeProbe'].append(event)
                                if len(selection_report['nativeProbe'])>=120:
                                    for slot in range(3):put64(ptr,'dr'+str(slot),0)
                                    put64(ptr,'dr7',0x40)
                            elif hardware&1 and selector['phase']=='flags' and r['rip']==base+0x10f362e:
                                selection_report['shiftHits']+=1
                                matched=(r['r11']==base+0xb163ba and r['rsi']==selector['markerRsp']+0x2d6
                                    and r['rcx']&0xff==3)
                                if matched:
                                    selection_report['flagsBefore']=event
                                    if r['rbx']!=0x202:
                                        raise RuntimeError('Saved-flags selector differs from the v77 baseline')
                                    new_flags=r['rbx']|(0x40 if MODE!='fixture-response-zfbaseline' else 0)
                                    selection_report['flagAction']={'register':'rbx','before':hex(r['rbx']),
                                        'after':hex(new_flags),'changedBits':hex(r['rbx']^new_flags),
                                        'ripUnchanged':True,'nativeEflagsUnchanged':True}
                                    put64(ptr,'rbx',new_flags)
                                    selector['phase']='target';put64(ptr,'dr0',base+0x10c441e)
                            elif hardware&2 and r['rip']==base+0xd75f2c:
                                selection_report['tableReadHits']+=1
                                matched=(selector['phase']=='target' and r['r11']==base+0xb16395
                                    and r['rsi']==selector['markerRsp']+0x2c8)
                                if matched:
                                    address=(r['rax']+r['rbx']+0x37730000)&0xffffffffffffffff
                                    table=selector['markerRsp']+0x2e0;raw=read(table,16)
                                    if len(raw)!=16:raise RuntimeError('Selector table read is incomplete')
                                    targets=struct.unpack('<QQ',raw)
                                    wanted_index=0 if MODE!='fixture-response-zfbaseline' else 8
                                    event.update(effectiveAddress=hex(address),tableAddress=hex(table),
                                        tableHex=raw.hex(),targets=[hex(value) for value in targets],
                                        indexBytes=address-table,expectedIndexBytes=wanted_index)
                                    selection_report['selectedTarget']=event
                                    if targets!=(0x1408c733d,0x140b162d3) or address!=table+wanted_index:
                                        raise RuntimeError('Selector table or selected index differs from the prediction')
                                    selector['expectedTargetRva']=targets[wanted_index//8]-0x140000000
                                    selector['phase']='commit';put64(ptr,'dr1',0)
                                    put64(ptr,'dr7',r['dr7']&~0xc)
                            elif hardware&1 and r['rip']==base+0x10c441e:
                                selection_report['commitHits']+=1
                                matched=(selector['phase']=='commit' and r['r11']==base+0xb16356
                                    and r['rsi']==selector['markerRsp']+0x268)
                                if matched:
                                    event.update(targetRva=hex(r['rdx']-base),
                                        expectedTargetRva=hex(selector['expectedTargetRva']))
                                    selection_report['virtualTargetCommit']=event
                                    if r['rdx']!=base+selector['expectedTargetRva']:
                                        raise RuntimeError('Virtual target does not match the selected table entry')
                                    selection_report['globalsBeforeWatchHex']=read(base+0x62de00,0x280).hex()
                                    selection_report['globalWrites']=[]
                                    selector['phase']='native-copies';put64(ptr,'dr0',base+0xae6c0)
                                    put64(ptr,'dr1',base+0x95f6c);put64(ptr,'dr7',0x55)
                            elif selector['phase']=='native-copies' and hardware&1 and r['rip']==base+0xae6c0:
                                matched=True
                                if base+0x62de00<=r['rcx']<base+0x62de70:
                                    event.update(destinationRva=hex(r['rcx']-base),sourceAddress=hex(r['rdx']),
                                        sourceOffsetFromMarker=hex(r['rdx']-selector['markerRsp']),sourceHex=read(r['rdx'],16).hex())
                                    return_bytes=read(r['rsp'],8)
                                    if len(return_bytes)==8:
                                        return_address=struct.unpack('<Q',return_bytes)[0]
                                        event['returnRva']=hex(return_address-base)
                                        event['callerAfter']=[{'rva':hex(ins.address-base),
                                            'instruction':(ins.mnemonic+' '+ins.op_str).strip()}
                                            for ins in dis.disasm(read(return_address,96),return_address)]
                                    selection_report['globalWrites'].append(event)
                                    if len(selection_report['globalWrites'])>=32:
                                        terminal={'kind':'global-copy-limit'}
                            elif selector['phase']=='native-copies' and hardware&2 and r['rip']==base+0x95f6c:
                                matched=True
                                record_feature_tables('before-native-init')
                                event['globalHex']=read(base+0x62de00,0x280).hex()
                                selection_report['beforeNativeInitialization']=event
                                if TEST_PLAN and TEST_PLAN.get('watchUnknownDuringInit'):
                                    selection_report['postResponseInitializationCode']=[{'rva':hex(i.address-base),
                                        'instruction':(i.mnemonic+' '+i.op_str).strip(),'bytes':i.bytes.hex()}
                                        for i in dis.disasm(read(base+0x13c6460,0x280),base+0x13c6460)]
                                if MODE in ('fixture-response-zfzero','fixture-response-zfuci','fixture-response-zfperft','fixture-response-zfgeometry','fixture-response-zfsearch'):
                                    instruction=require_runtime_instruction(0x95f6c,
                                        'vbroadcasti128 ymm0, xmmword ptr [rip + 0x597eeb]',9)
                                    original=read(base+0x62de60,16)
                                    data=C.create_string_buffer(bytes(16));written=C.c_size_t()
                                    if not K.WriteProcessMemory(ph,base+0x62de60,data,16,C.byref(written)) or written.value!=16:
                                        raise RuntimeError('Zero-vector diagnostic write failed')
                                    if read(base+0x62de60,16)!=bytes(16):raise RuntimeError('Zero-vector write verification failed')
                                    selection_report['zeroVectorIntervention']={'rva':'0x62de60','beforeHex':original.hex(),
                                        'afterHex':bytes(16).hex(),'bytes':16,'atRva':'0x95f6c',
                                        'scope':'Single empty-bitboard diagnostic correction; other six vectors unchanged'}
                                if MODE in ('fixture-response-zfgeometry','fixture-response-zfsearch'):
                                    repair_feature_membership()
                                    low_half=(1<<45)-1;high_half=low_half<<45
                                    lower_palace=sum(1<<(rank*9+file) for rank in range(3) for file in range(3,6))
                                    upper_palace=sum(1<<(rank*9+file) for rank in range(7,10) for file in range(3,6))
                                    geometry={0x62de00:('lower-half',low_half),0x62de10:('upper-half',high_half),
                                        0x62de20:('both-palaces',lower_palace|upper_palace),0x62de30:('lower-palace',lower_palace),
                                        0x62de40:('upper-palace',upper_palace)}
                                    if TEST_PLAN and TEST_PLAN.get('earlyFeatureGeometry'):
                                        pawn_points=[(x,y) for y in (3,4) for x in (0,2,4,6,8)]+[(x,y) for y in range(5,10) for x in range(9)]
                                        geometry[0x62de30]=('lower-side-pawn-reachable',sum(1<<(y*9+x) for x,y in pawn_points))
                                        geometry[0x62de40]=('upper-side-pawn-reachable',sum(1<<((9-y)*9+x) for x,y in pawn_points))
                                    seen={int(copy['destinationRva'],16) for copy in selection_report['globalWrites']}
                                    if seen!=set(range(0x62de00,0x62de70,16)):
                                        raise RuntimeError('Global vector initialization coverage changed')
                                    changes=[]
                                    for target,(meaning,value) in geometry.items():
                                        before=read(base+target,16);replacement=value.to_bytes(16,'little')
                                        data=C.create_string_buffer(replacement);written=C.c_size_t()
                                        if not K.WriteProcessMemory(ph,base+target,data,16,C.byref(written)) or written.value!=16:
                                            raise RuntimeError('Geometry-vector diagnostic write failed')
                                        if read(base+target,16)!=replacement:raise RuntimeError('Geometry-vector write verification failed')
                                        changes.append({'rva':hex(target),'meaning':meaning,'beforeHex':before.hex(),
                                            'afterHex':replacement.hex(),'setBits':value.bit_count()})
                                    selection_report['geometryIntervention']={'atRva':'0x95f6c','changes':changes,
                                        'unmodifiedUnknownVectorRva':'0x62de50',
                                        'scope':'Reconstructed standard 9x10 board geometry; runtime validation required'}
                                    if TEST_PLAN and TEST_PLAN.get('earlyFeatureGeometry'):
                                        apply_case_repairs({'perftResults':[]},{'repairEvasionGeometry':True})
                                        report['earlyFeatureGeometry']={'atRva':'0x95f6c',
                                            'masks':{hex(address):read(base+address,16).hex() for address in (0x62de30,0x62de40,0x630b78,0x631300)}}
                                selector['phase']='native-input-load'
                                if TEST_PLAN and (TEST_PLAN.get('observeStepTable') or TEST_PLAN.get('repairHorseStepTable')):
                                    pointer_raw=read(base+0x1fed50,8)
                                    assert len(pointer_raw)==8
                                    step_pointer=struct.unpack('<Q',pointer_raw)[0]
                                    step_bytes=read(step_pointer,41)
                                    assert len(step_bytes)==41
                                    report['horseStepTable']={'pointerRva':'0x1fed50','address':hex(step_pointer),
                                        'beforeHex':step_bytes.hex(),'atRva':'0x95f6c'}
                                    if TEST_PLAN.get('repairHorseStepTable'):
                                        directions={-19:-9,-17:-9,-11:-1,-7:1,7:-1,11:1,17:9,19:9}
                                        changes=[]
                                        for difference,leg_offset in directions.items():
                                            index=20+difference;replacement=bytes((leg_offset&255,))
                                            data=C.create_string_buffer(replacement);written=C.c_size_t()
                                            if not K.WriteProcessMemory(ph,step_pointer+index,data,1,C.byref(written)) or written.value!=1:
                                                raise RuntimeError('Horse-leg offset repair failed')
                                            assert read(step_pointer+index,1)==replacement
                                            changes.append({'difference':difference,'index':index,'before':step_bytes[index],'afterSigned':leg_offset})
                                        after=read(step_pointer,41)
                                        assert all(after[index]==step_bytes[index] for index in range(41) if index-20 not in directions)
                                        report['horseStepTable'].update(afterHex=after.hex(),changes=changes)
                                put64(ptr,'dr0',0);put64(ptr,'dr1',base+0x962bf);put64(ptr,'dr7',0x54)
                                if TEST_PLAN and TEST_PLAN.get('watchUnknownDuringInit'):
                                    selector['phase']='native-unknown-watch';selection_report['unknownVectorReads']=[]
                                    put64(ptr,'dr0',base+0x62de50);put64(ptr,'dr1',base+0x62de58)
                                    put64(ptr,'dr7',0x55|(0xb<<16)|(0xb<<20))
                                if TEST_PLAN and TEST_PLAN.get('nnueFileTrace'):
                                    require_runtime_instruction(0xe1aed,'mov r9d, dword ptr [rax]',3)
                                    selector['phase']='native-metadata'
                                    arm_nnue_files(tid,ptr)
                                if TEST_PLAN and TEST_PLAN.get('traceFeatureTableWriters'):
                                    assert not TEST_PLAN.get('nnueFileTrace'), 'Writer probes need dedicated debug slots'
                                    selector['phase']='feature-writer-watch'
                                    report['featureTableWriters']=[]
                                    put64(ptr,'dr0',base+0x1f3abe);put64(ptr,'dr1',base+0x28bec8)
                                    put64(ptr,'dr7',0x55|(5<<16)|(5<<20))
                            elif selector['phase']=='native-input-load' and hardware&2 and r['rip']==base+0x962bf:
                                matched=True
                                native_instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                                event['instruction']=(native_instruction.mnemonic+' '+native_instruction.op_str).strip() if native_instruction else None
                                event['globalHex']=read(base+0x62de00,0x280).hex()
                                event['responseHex']=read(response['address'],response['capacity']).hex()
                                event['squareBitboardsHex']=read(base+0x630d60,90*16).hex()
                                event['xmmHex']={str(n):C.string_at(ptr+416+n*16,16).hex() for n in range(8)}
                                selection_report['nativeInput']=event
                                snapshot(tid,ptr,'native-bitboard-input')
                                selector['phase']='terminal'
                                put64(ptr,'dr0',0);put64(ptr,'dr1',0);put64(ptr,'dr7',0x50)
                                if TEST_PLAN and TEST_PLAN.get('repairThreadLimit'):
                                    require_runtime_instruction(0xe1aed,'mov r9d, dword ptr [rax]',3)
                                    selector['phase']='native-metadata';put64(ptr,'dr0',base+0xe1aed);put64(ptr,'dr7',0x51)
                            elif selector['phase']=='native-metadata' and hardware&9 and r['rip']==base+0xe1aed:
                                matched=True
                                pointer=read(base+0x138280,8)
                                assert len(pointer)==8 and struct.unpack('<Q',pointer)[0]==r['rax']
                                before=read(r['rax'],4);assert len(before)==4
                                value=os.cpu_count() or 1;assert 1<=value<=256
                                event['sourceAddress']=hex(r['rax']);event['before']=struct.unpack('<i',before)[0]
                                event['surroundingHex']=read(r['rax']-16,80).hex()
                                replacement=struct.pack('<I',value);buffer=C.create_string_buffer(replacement);written=C.c_size_t()
                                if not K.WriteProcessMemory(ph,r['rax'],buffer,4,C.byref(written)) or written.value!=4:
                                    raise RuntimeError('Thread-limit source repair failed')
                                assert read(r['rax'],4)==replacement
                                event['after']=value;event['sourceOffsetFromMarker']=hex(r['rax']-selector['markerRsp'])
                                selection_report['threadLimitRepair']=event
                                selector['phase']='terminal'
                                if TEST_PLAN and TEST_PLAN.get('nnueFileTrace'):
                                    put64(ptr,'dr3',0);put64(ptr,'dr7',0x15)
                                else:
                                    put64(ptr,'dr0',0);put64(ptr,'dr7',0x50)
                            elif hardware&4 and r['rip']==base+0xe5770:
                                matched=True
                                if MODE in ('fixture-response-zfuci','fixture-response-zfperft','fixture-response-zfgeometry','fixture-response-zfsearch'):
                                    selection_report['protocolEntry']=event
                                    record_feature_tables('at-protocol')
                                    verify_feature_tables()
                                    if TEST_PLAN and TEST_PLAN.get('earlyFeatureGeometry'):
                                        report['earlyFeatureGeometry']['atProtocol']={hex(address):read(base+address,16).hex()
                                            for address in (0x62de30,0x62de40,0x630b78,0x631300)}
                                    selector['phase']='protocol'
                                    put64(ptr,'dr2',0);put64(ptr,'dr7',r['dr7']&~0x30)
                                    if MODE=='fixture-response-zfsearch':
                                        selection_report['unknownVectorReads']=[]
                                        put64(ptr,'dr0',base+0x62de50);put64(ptr,'dr1',base+0x62de58)
                                        put64(ptr,'dr7',0x45|(0xb<<16)|(0xb<<20))
                                    if TEST_PLAN and TEST_PLAN.get('nativeProbeSites'):
                                        sites=TEST_PLAN['nativeProbeSites'];assert len(sites)<=3
                                        guards={0xb675b:('vmovdqa xmm0, xmmword ptr [rcx + rax]',5),
                                            0xb67e6:('vpxor xmm0, xmm0, xmm1',4),0xb6f6e:('mov rax, r8',3),
                                            0xb73c3:('or rcx, rax',3),0xb7258:('mov rax, qword ptr [rsp + 0x58]',5)}
                                        selection_report['nativeProbe']=[]
                                        mask=0x40
                                        for slot,site in enumerate(sites):
                                            site=int(site,16);require_runtime_instruction(site,*guards[site])
                                            put64(ptr,'dr'+str(slot),base+site);mask|=1<<(2*slot)
                                        put64(ptr,'dr7',mask)
                                    report['uciProbe']={'stage':'uci','commands':['uci'],'uciok':False,'readyok':False,
                                        'warning':'Diagnostic only; license metadata remains synthetic and complete chess correctness is not established'}
                                    if BRIDGE:
                                        report.pop('uciProbe')
                                        if not TEST_PLAN.get('earlyFeatureGeometry'):
                                            apply_case_repairs({'perftResults':[]},{'repairEvasionGeometry':True,'repairPawnGeometry':True})
                                        else:
                                            for address,expected in report['earlyFeatureGeometry']['masks'].items():
                                                assert read(base+int(address,16),16).hex()==expected, 'Early geometry changed before bridge'
                                        for other_tid in thread_ids(proc.pid):
                                            if other_tid==tid:
                                                for slot in range(4):put64(ptr,'dr'+str(slot),0)
                                                put64(ptr,'dr6',0);put64(ptr,'dr7',0)
                                            else:
                                                other_handle,other_buffer,other_ptr=get_context(other_tid)
                                                try:
                                                    for slot in range(4):put64(other_ptr,'dr'+str(slot),0)
                                                    put64(other_ptr,'dr6',0);put64(other_ptr,'dr7',0);apply_context(other_handle,other_ptr)
                                                finally:K.CloseHandle(other_handle)
                                        report['bridgeReady']=True;report['status']='bridge-ready'
                                    else:
                                        proc.stdin.write(b'uci\n');proc.stdin.flush()
                                        report['status']='awaiting-synthetic-response-uci'
                                    snapshot(tid,ptr,'synthetic-response-uci-start')
                                    if TEST_PLAN and TEST_PLAN.get('traceEvaluation'):
                                        require_runtime_instruction(0xa5750,'push rbp',1)
                                        for evaluation_tid in thread_ids(proc.pid):
                                            if evaluation_tid==tid:arm_eval_thread(tid,ptr)
                                            else:
                                                eh,eb,ep=get_context(evaluation_tid)
                                                try:arm_eval_thread(evaluation_tid,ep);apply_context(eh,ep)
                                                finally:K.CloseHandle(eh)
                                        report['evaluationTraceInstalled']=True
                                else:terminal={'kind':'protocol-entry','rva':'0xe5770'}
                            elif selector['phase'] in ('native-unknown-watch','protocol') and hardware&3 and (MODE=='fixture-response-zfsearch' or (TEST_PLAN and TEST_PLAN.get('watchUnknownDuringInit'))):
                                matched=True
                                event['stage']=report.get('uciProbe',{}).get('stage')
                                event['unknownVectorHex']=read(base+0x62de50,16).hex()
                                event['previousInstructionCandidates']=[]
                                for back in range(1,16):
                                    previous=next(dis.disasm(read(r['rip']-back,back),r['rip']-back,count=1),None)
                                    if previous and previous.size==back:
                                        event['previousInstructionCandidates'].append({'rva':hex(previous.address-base),
                                            'instruction':(previous.mnemonic+' '+previous.op_str).strip()})
                                selection_report['unknownVectorReads'].append(event)
                                if len(selection_report['unknownVectorReads'])>=16:
                                    put64(ptr,'dr0',0);put64(ptr,'dr1',0);put64(ptr,'dr7',0x40)
                            elif hardware&8 and r['rip']==exit_exports['RtlExitUserProcess']:
                                matched=True;terminal={'kind':'exit-api','api':'RtlExitUserProcess',
                                    'exitCodeArgument':r['rcx']&0xffffffff}
                            else:raise RuntimeError('Unexpected ZF-selector hardware breakpoint')
                            if not matched and len(selection_report['decoyExamples'])<6:
                                selection_report['decoyExamples'].append(event)
                            if selection_report['hardwareHits']>=10000:
                                terminal={'kind':'hardware-hit-limit'}
                            if terminal is not None:
                                selection_report['terminal']={**terminal,**event,'phase':selector['phase']}
                                snapshot(tid,ptr,'response-zf-selector-terminal')
                                report['status']='synthetic-response-zf-selector'
                            flags(ptr,disable=0x100)
                        elif MODE=='fixture-response-sourcewindow' and response.get('sourceWindowStarted') and hardware:
                            source=response['sourceWatch'];terminal=None
                            if hardware&2 and r['rip']==base+0x1204d6c:
                                actual=(r['rcx']+r['rax'])&0xffffffffffffffff
                                report['sourceWindow']['writerHits']+=1
                                if actual==source['address']:
                                    terminal={'kind':'matched-source-writer-pre','rva':'0x1204d6c',
                                        'actualAddress':hex(actual),'value':hex(r['r8']),
                                        'beforeHex':read(actual,8).hex()}
                            elif hardware&4 and r['rip']==base+0xe5770:
                                terminal={'kind':'protocol-entry','rva':'0xe5770'}
                            elif hardware&8 and r['rip']==base+0xbbc0c:
                                terminal={'kind':'exit-call-before-writer','rva':'0xbbc0c','exitCodeArgument':r['rcx']&0xffffffff}
                            else:raise RuntimeError('Source-window hardware address mismatch')
                            if terminal is not None:
                                report['sourceWindow']['terminal']={**terminal,'threadId':tid,
                                    'registers':{name:hex(value) for name,value in r.items() if not name.startswith('dr')}}
                                report['keyTrace']['terminal']=terminal
                                snapshot(tid,ptr,'response-source-window-terminal')
                                key_trace_active=False;flags(ptr,disable=0x100)
                                report['status']='synthetic-response-source-watch'
                        elif MODE in ('fixture-response-sourcewatch','fixture-response-sourcefollow','fixture-response-sourcewindow') and response.get('sourceWatch') and hardware:
                            source=response['sourceWatch'];source_report=source['report'];handled=False;terminal=None
                            if hardware&1:
                                handled=True;raw=read(source['address'],8)
                                if len(raw)!=8:raise RuntimeError('Source-watch slot read was incomplete')
                                value=struct.unpack('<Q',raw)[0];changed=value!=source['lastValue']
                                candidates=[]
                                for back in range(1,16):
                                    previous=next(dis.disasm(read(r['rip']-back,back),r['rip']-back,count=1),None)
                                    if previous and previous.size==back:
                                        candidates.append({'rva':hex(previous.address-base),'bytes':previous.bytes.hex(),
                                            'instruction':(previous.mnemonic+' '+previous.op_str).strip()})
                                event={'index':source_report['accessCount'],'kind':'source-access-post','tid':tid,
                                    'afterRva':hex(r['rip']-base),'slotHex':raw.hex(),'slotValue':hex(value),
                                    'previousValue':hex(source['lastValue']),'valueChanged':changed,
                                    'previousInstructionCandidates':candidates,
                                    'registers':{name:hex(register) for name,register in r.items() if not name.startswith('dr')}}
                                source_report['accessCount']+=1;source_report['lastAccess']=event
                                source_report['accessTail'].append(event)
                                if len(source_report['accessTail'])>256:del source_report['accessTail'][0]
                                if changed:
                                    source_report['transitions'].append(event)
                                    if len(source_report['transitions'])>256:del source_report['transitions'][0]
                                    source_report['lastTransition']=event
                                source['lastValue']=value
                                if (MODE=='fixture-response-sourcewindow' and r['rip']==base+0x10d0594
                                        and value==0x7ffffffffffffffc and not response.get('sourceWindowStarted')):
                                    writer=require_runtime_instruction(0x1204d6c,'mov qword ptr [rcx + rax], r8',4)
                                    response['sourceWindowStarted']=True
                                    report['sourceWindow']={'start':event,'threadId':tid,'writerRva':'0x1204d6c',
                                        'writerBytes':writer.bytes.hex(),'writerHits':0,'instructionLimit':20000,
                                        'scope':'From the observed last predecessor source-slot write to the next source-slot writer'}
                                    key_trace_file=(OUT/'key-trace.jsonl').open('w',encoding='utf-8')
                                    key_trace_active=True;key_trace_tid=tid;key_trace_paused=False
                                    key_trace_dr7_base=0x54;key_trace_resume=0
                                    put64(ptr,'dr0',0);put64(ptr,'dr1',base+0x1204d6c)
                                    put64(ptr,'dr2',base+0xe5770);put64(ptr,'dr3',base+0xbbc0c)
                                    put64(ptr,'dr7',key_trace_dr7_base)
                                    report['keyTrace']={'scope':'Narrow trace before the final source-slot write',
                                        'startRva':'0x10d0594','threadId':tid,'instructions':0}
                                if changed and value==1:
                                    source_report['oneTransitionCount']+=1
                                    source_report['lastOneTransition']=event
                                    if MODE=='fixture-response-sourcewatch':terminal={'kind':'source-transition-one','event':event}
                            if hardware&2 and source.get('phase')=='writer' and r['rip']==base+0x10d01b5:
                                handled=True;actual=(r['rbx']+r['rbp']*4-0x10)&0xffffffffffffffff
                                pair={'loader':source.pop('pendingLoader'),'writerRva':'0x10d01b5',
                                    'actualAddress':hex(actual),'expectedAddress':hex(source['markerRsp']+0x298),
                                    'writesFinalSlot':actual==source['markerRsp']+0x298,
                                    'sourceValue':hex(r['rdi']),'beforeHex':read(actual,8).hex(),
                                    'registers':{name:hex(register) for name,register in r.items() if not name.startswith('dr')}}
                                pair['valuePreserved']=r['rdi']==1
                                source_report['pairedWriterCount']+=1
                                source_report['pairedWriters'].append(pair)
                                if len(source_report['pairedWriters'])>128:del source_report['pairedWriters'][0]
                                if pair['writesFinalSlot'] and pair['valuePreserved']:source_report['lastFinalSlotPair']=pair
                                source['phase']='loader';put64(ptr,'dr1',base+source['loaderRva'])
                            elif hardware&2 and r['rip']==base+source['loaderRva']:
                                handled=True;actual=(r['rdi']+r['r8']-0x1f933200)&0xffffffffffffffff
                                raw=read(actual,8);value=struct.unpack('<Q',raw)[0] if len(raw)==8 else None
                                event={'index':source_report['loaderCount'],'kind':'loader-pre','tid':tid,
                                    'rva':hex(source['loaderRva']),'actualAddress':hex(actual),
                                    'inputHex':raw.hex(),'inputValue':hex(value) if value is not None else None,
                                    'matchesSourceSlot':actual==source['address'],
                                    'registers':{name:hex(register) for name,register in r.items() if not name.startswith('dr')}}
                                source_report['loaderCount']+=1;source_report['lastLoader']=event
                                source_report['loaderTail'].append(event)
                                if len(source_report['loaderTail'])>128:del source_report['loaderTail'][0]
                                if actual==source['address'] and value==1:
                                    event['lastSourceTransition']=source_report.get('lastTransition')
                                    source_report['oneLoaderCount']+=1
                                    if MODE=='fixture-response-sourcewatch':terminal={'kind':'target-loader-one','event':event}
                                    elif MODE=='fixture-response-sourcefollow':
                                        source['pendingLoader']=event;source['phase']='writer'
                                        put64(ptr,'dr1',base+0x10d01b5)
                            if hardware&4 and r['rip']==base+0xe5770:
                                handled=True;terminal={'kind':'protocol-entry','rva':'0xe5770'}
                            if hardware&8 and r['rip']==base+0xbbc0c:
                                handled=True
                                exit_instruction=require_runtime_instruction(
                                    0xbbc0c,'call '+hex(base+0x950131),5)
                                terminal={'kind':'exit-call','rva':'0xbbc0c','bytes':exit_instruction.bytes.hex(),
                                    'exitCodeArgument':r['rcx']&0xffffffff,
                                    'finalSlotHex':read(source['markerRsp']+0x298,8).hex(),
                                    'lastFinalSlotPair':source_report.get('lastFinalSlotPair'),
                                    'pendingLoader':source.get('pendingLoader')}
                            if not handled:raise RuntimeError('Source-watch hardware mask or instruction address mismatch')
                            if terminal is not None:
                                source_report['terminal']={**terminal,'threadId':tid,
                                    'sourceHex':read(source['address'],8).hex(),
                                    'sourceValue':hex(struct.unpack('<Q',read(source['address'],8))[0]),
                                    'registers':{name:hex(register) for name,register in r.items() if not name.startswith('dr')}}
                                report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                                snapshot(tid,ptr,'synthetic-response-source-watch')
                                report['status']='synthetic-response-source-watch';flags(ptr,disable=0x100)
                        elif MODE=='fixture-response-rcxsource' and response.get('rcxSource') and hardware&3:
                            source=response['rcxSource'];source_report=source['report'];handled=False
                            if hardware&1 and r['rip']==base+source['loaderRva']:
                                handled=True
                                actual=(r['rdi']+r['r8']-0x1f933200)&0xffffffffffffffff
                                raw=read(actual,8)
                                event={'index':source_report['loaderCount'],'kind':'rdi-loader',
                                    'rva':hex(source['loaderRva']),'tid':tid,'actualAddress':hex(actual),
                                    'inputHex':raw.hex(),'inputValue':hex(struct.unpack('<Q',raw)[0]) if len(raw)==8 else None,
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                source_report['loaderCount']+=1;source_report['lastLoader']=event
                                source_report['loaderEvents'].append(event)
                                if len(source_report['loaderEvents'])>128:del source_report['loaderEvents'][0]
                            if hardware&2 and r['rip']==base+source['writerRva']:
                                handled=True
                                actual=(r['rbx']+r['rbp']*4-0x10)&0xffffffffffffffff
                                if actual==source['slotAddress']:
                                    event={'index':source_report['matchedWriterCount'],'kind':'slot-writer',
                                        'rva':hex(source['writerRva']),'tid':tid,'actualAddress':hex(actual),
                                        'beforeHex':read(actual,8).hex(),'sourceRegister':'rdi','sourceValue':hex(r['rdi']),
                                        'lastLoader':source_report.get('lastLoader'),
                                        'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                    source_report['matchedWriterCount']+=1;source_report['lastWriter']=event
                                    source_report['writerEvents'].append(event)
                                    if len(source_report['writerEvents'])>128:del source_report['writerEvents'][0]
                                    if r['rdi']==1 and source_report['valueOneSnapshots']<3:
                                        source_report['valueOneSnapshots']+=1
                                        snapshot(tid,ptr,'rcx-source-writer-one-'+str(source_report['valueOneSnapshots']))
                                else:
                                    source_report['writerDecoyCount']+=1
                            if not handled:
                                raise RuntimeError('RCX-source hardware mask or instruction address mismatch')
                        elif MODE=='fixture-response-rcxchain' and response.get('rcxChain') and hardware&3:
                            chain=response['rcxChain'];chain_report=chain['report']
                            if hardware&1 and r['rip']==base+chain['writerRva']:
                                actual=(r['rbx']+r['rbp']*4-0x10)&0xffffffffffffffff
                                if actual==chain['slotAddress']:
                                    before=read(actual,8)
                                    event={'index':chain_report['matchedWriterCount'],'kind':'writer',
                                        'rva':hex(chain['writerRva']),'tid':tid,'actualAddress':hex(actual),
                                        'beforeHex':before.hex(),'sourceRegister':'rdi','sourceValue':hex(r['rdi']),
                                        'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                    chain_report['matchedWriterCount']+=1
                                    chain_report['lastWriter']=event
                                    chain_report['writerEvents'].append(event)
                                    if len(chain_report['writerEvents'])>128:del chain_report['writerEvents'][0]
                                else:
                                    chain_report['writerDecoyCount']+=1
                            elif hardware&2 and r['rip']==base+chain['consumerRva']:
                                actual=(r['rsp']+r['r13']+0x30)&0xffffffffffffffff
                                if actual==chain['slotAddress']:
                                    raw=read(actual,8);value=struct.unpack('<Q',raw)[0]
                                    event={'index':chain_report['matchedConsumerCount'],'kind':'consumer',
                                        'rva':hex(chain['consumerRva']),'tid':tid,'actualAddress':hex(actual),
                                        'inputHex':raw.hex(),'inputValue':hex(value),
                                        'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                    chain_report['matchedConsumerCount']+=1
                                    chain_report['lastConsumer']=event
                                    chain_report['consumerEvents'].append(event)
                                    if len(chain_report['consumerEvents'])>128:del chain_report['consumerEvents'][0]
                                    if value==1 and chain_report['valueOneSnapshots']<3:
                                        chain_report['valueOneSnapshots']+=1
                                        snapshot(tid,ptr,'rcx-chain-consumer-one-'+str(chain_report['valueOneSnapshots']))
                                else:
                                    chain_report['consumerDecoyCount']+=1
                            else:
                                raise RuntimeError('RCX-chain hardware mask or instruction address mismatch')
                        elif MODE=='fixture-response-slotwatch' and response.get('slotWatch') and hardware&3:
                            watch=response['slotWatch'];handled=False
                            for watch_slot in (0,1):
                                if not hardware&(1<<watch_slot):continue
                                handled=True;path=watch['paths'][watch_slot];path_report=path['report']
                                after_rva=r['rip']-base
                                raw=read(path['slotAddress'],8)
                                if len(raw)!=8:
                                    raise RuntimeError(f'Slot-watch read was incomplete for DR{watch_slot}')
                                value=struct.unpack('<Q',raw)[0]
                                path['accessCount']+=1
                                event={'index':path['accessCount']-1,'tid':tid,
                                    'hardwareMask':hardware,'afterRva':hex(after_rva),
                                    'slotHex':raw.hex(),'slotValue':hex(value),
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                if after_rva==path['writerNextRva']:
                                    event.update(kind='known-writer-post',writerRva=hex(path['writerRva']),
                                        sourceRegister=path['sourceRegister'],
                                        sourceValue=hex(r[path['sourceRegister']]&0xffffffffffffffff))
                                    path_report['latestKnownWriter']=event
                                elif after_rva==path['consumerNextRva']:
                                    destination=r[path['destinationRegister']]&0xffffffffffffffff
                                    event.update(kind='known-consumer-post',consumerRva=hex(path['consumerRva']),
                                        destinationRegister=path['destinationRegister'],
                                        destinationValue=hex(destination),
                                        destinationMatchesSlot=destination==value)
                                    path_report['consumerSeen']=True
                                    path_report['consumerValue']=hex(value)
                                    path_report['latestKnownConsumer']=event
                                else:
                                    event['kind']='other-overlapping-access'
                                changed=value!=path['lastValue']
                                event['valueChanged']=changed
                                if changed:
                                    event['previousValue']=hex(path['lastValue'])
                                    transitions=path_report['transitions'];transitions.append(event)
                                    if len(transitions)>256:
                                        del transitions[0];path_report['discardedTransitions']+=1
                                if event['kind']!='other-overlapping-access':
                                    known=path_report['knownEvents'];known.append(event)
                                    if len(known)>512:
                                        del known[0];path_report['discardedKnownEvents']+=1
                                tail=path_report['tail'];tail.append(event)
                                if len(tail)>64:del tail[0]
                                path['lastValue']=value
                                path_report['lastEvent']=event
                                path_report['accessCount']=path['accessCount']
                                if path['accessCount']>20000:
                                    raise RuntimeError(f'Slot-watch access limit exceeded for DR{watch_slot}')
                            if not handled:
                                raise RuntimeError('Slot-watch hardware mask did not identify DR0 or DR1')
                        elif MODE=='fixture-response-flagprobe' and response.get('flagProbe') and hardware&3:
                            probe=response['flagProbe'];handled=False
                            for flag_slot in (0,1):
                                if not hardware&(1<<flag_slot):continue
                                handled=True;path=probe['paths'][flag_slot];path_report=path['report']
                                phase=path['phase']
                                expected_rva={'writer':path['writerRva'],'writer-post':path['writerNextRva'],
                                    'consumer':path['consumerRva'],'consumer-post':path['consumerNextRva']}.get(phase)
                                if expected_rva is None or r['rip']!=base+expected_rva:
                                    raise RuntimeError(
                                        f'Flag-probe state mismatch for DR{flag_slot}: phase={phase}, '
                                        f'rip={r["rip"]-base:#x}, expected={expected_rva!r}')
                                event={'phase':phase,'rva':hex(expected_rva),'tid':tid,
                                    'hardwareMask':hardware,
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                if phase=='writer':
                                    instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                                    actual_text=(instruction.mnemonic+' '+instruction.op_str).strip() if instruction else None
                                    if not instruction or actual_text!=path['writerText']:
                                        raise RuntimeError(
                                            f'Flag-probe writer changed at {expected_rva:#x}: {actual_text!r}')
                                    actual_address=((r['rax']+r['rbx']-0xa66c) if flag_slot==0
                                        else (r['rbx']+r['rbp']*4-0x10))&0xffffffffffffffff
                                    event.update(instruction=actual_text,actualAddress=hex(actual_address),
                                        expectedAddress=hex(path['slotAddress']))
                                    if actual_address!=path['slotAddress']:
                                        path['decoyHits']+=1;path_report['decoyHits']=path['decoyHits']
                                        event['result']='decoy-address';path_report['events'].append(event)
                                        if path['decoyHits']>probe['report']['decoyLimitPerPath']:
                                            raise RuntimeError(f'Flag-probe writer decoy limit exceeded for DR{flag_slot}')
                                        continue
                                    before=read(path['slotAddress'],8)
                                    if len(before)!=8:
                                        raise RuntimeError('Flag-probe writer slot read was incomplete')
                                    source_value=r[path['sourceRegister']]&0xffffffffffffffff
                                    event.update(result='matched',beforeHex=before.hex(),
                                        sourceRegister=path['sourceRegister'],sourceValue=hex(source_value))
                                    path['pendingSourceValue']=source_value
                                    path['phase']='writer-post';path_report['phase']='writer-post'
                                    path_report['events'].append(event)
                                    snapshot(tid,ptr,'flagprobe-'+path['name']+'-writer')
                                    put64(ptr,'dr'+str(flag_slot),base+path['writerNextRva'])
                                elif phase=='writer-post':
                                    after=read(path['slotAddress'],8)
                                    expected=struct.pack('<Q',path['pendingSourceValue'])
                                    if len(after)!=8 or after!=expected:
                                        event.update(result='mismatch',afterHex=after.hex(),expectedHex=expected.hex())
                                        path_report['events'].append(event)
                                        raise RuntimeError(f'Flag-probe writer post-value mismatch for DR{flag_slot}')
                                    event.update(result='matched',afterHex=after.hex(),expectedHex=expected.hex())
                                    path['phase']='consumer';path_report['phase']='consumer'
                                    path_report['events'].append(event)
                                    put64(ptr,'dr'+str(flag_slot),base+path['consumerRva'])
                                elif phase=='consumer':
                                    instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                                    actual_text=(instruction.mnemonic+' '+instruction.op_str).strip() if instruction else None
                                    if not instruction or actual_text!=path['consumerText']:
                                        raise RuntimeError(
                                            f'Flag-probe consumer changed at {expected_rva:#x}: {actual_text!r}')
                                    actual_address=((r['rsp']+r['r13']*2+0x40) if flag_slot==0
                                        else (r['rsp']+r['r13']+0x30))&0xffffffffffffffff
                                    event.update(instruction=actual_text,actualAddress=hex(actual_address),
                                        expectedAddress=hex(path['slotAddress']))
                                    if actual_address!=path['slotAddress']:
                                        path['decoyHits']+=1;path_report['decoyHits']=path['decoyHits']
                                        event['result']='decoy-address';path_report['events'].append(event)
                                        if path['decoyHits']>probe['report']['decoyLimitPerPath']:
                                            raise RuntimeError(f'Flag-probe consumer decoy limit exceeded for DR{flag_slot}')
                                        continue
                                    consumed=read(path['slotAddress'],8)
                                    if len(consumed)!=8:
                                        raise RuntimeError('Flag-probe consumer slot read was incomplete')
                                    path['pendingInputValue']=struct.unpack('<Q',consumed)[0]
                                    event.update(result='matched',inputHex=consumed.hex(),
                                        inputValue=hex(path['pendingInputValue']))
                                    path['phase']='consumer-post';path_report['phase']='consumer-post'
                                    path_report['events'].append(event)
                                    snapshot(tid,ptr,'flagprobe-'+path['name']+'-consumer')
                                    put64(ptr,'dr'+str(flag_slot),base+path['consumerNextRva'])
                                else:
                                    destination_value=r[path['destinationRegister']]&0xffffffffffffffff
                                    event.update(destinationRegister=path['destinationRegister'],
                                        destinationValue=hex(destination_value),
                                        expectedValue=hex(path['pendingInputValue']),
                                        result='matched' if destination_value==path['pendingInputValue'] else 'mismatch')
                                    path_report['events'].append(event)
                                    if destination_value!=path['pendingInputValue']:
                                        raise RuntimeError(f'Flag-probe consumer post-value mismatch for DR{flag_slot}')
                                    path['phase']='complete';path_report['phase']='complete'
                                    path_report['complete']=True
                                    put64(ptr,'dr'+str(flag_slot),0)
                                    current_dr7=C.c_uint64.from_address(ptr+REG['dr7']).value
                                    put64(ptr,'dr7',current_dr7&~(3<<(flag_slot*2)))
                            if not handled:
                                raise RuntimeError('Flag-probe hardware mask did not identify DR0 or DR1')
                            probe['report']['complete']=all(
                                flag_path['phase']=='complete' for flag_path in probe['paths'].values())
                        elif MODE=='fixture-response-flagprobe' and response.get('flagProbe') and hardware&8 and r['rip']==base+0xbbc0c:
                            probe=response['flagProbe'];probe_report=probe['report']
                            instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                            if (not instruction or instruction.mnemonic!='call' or not instruction.operands
                                    or instruction.operands[0].type!=capstone.x86.X86_OP_IMM
                                    or instruction.operands[0].imm!=base+0x950131):
                                raise RuntimeError('Flag-probe terminal exit call precondition changed')
                            probe_report['complete']=all(
                                flag_path['phase']=='complete' for flag_path in probe['paths'].values())
                            probe_report['terminal']={'kind':'observed-exit-call','rva':'0xbbc0c',
                                'targetRva':'0x950131','threadId':tid,'instruction':instruction.mnemonic+' '+instruction.op_str,
                                'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                'exitCodeArgument':r['rcx']&0xffffffff,
                                'pathPhases':{str(slot):path['phase'] for slot,path in probe['paths'].items()},
                                'slotHex':{str(slot):read(path['slotAddress'],8).hex() for slot,path in probe['paths'].items()},
                                'allPathsComplete':probe_report['complete']}
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            snapshot(tid,ptr,'synthetic-response-rejection-flags')
                            report['status']='synthetic-response-rejection-flags'
                            flags(ptr,disable=0x100)
                        elif MODE=='fixture-response-slotwatch' and response.get('slotWatch') and hardware&8 and r['rip']==base+0xbbc0c:
                            watch=response['slotWatch'];watch_report=watch['report']
                            instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                            if (not instruction or instruction.mnemonic!='call' or not instruction.operands
                                    or instruction.operands[0].type!=capstone.x86.X86_OP_IMM
                                    or instruction.operands[0].imm!=base+0x950131):
                                raise RuntimeError('Slot-watch terminal exit call precondition changed')
                            watch_report['terminal']={'kind':'observed-exit-call','rva':'0xbbc0c',
                                'targetRva':'0x950131','threadId':tid,
                                'instruction':instruction.mnemonic+' '+instruction.op_str,
                                'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                'exitCodeArgument':r['rcx']&0xffffffff,
                                'slotHex':{str(slot):read(path['slotAddress'],8).hex()
                                    for slot,path in watch['paths'].items()},
                                'consumerSeen':{str(slot):path['report']['consumerSeen']
                                    for slot,path in watch['paths'].items()}}
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            snapshot(tid,ptr,'synthetic-response-slot-watch')
                            report['status']='synthetic-response-slot-watch'
                            flags(ptr,disable=0x100)
                        elif MODE=='fixture-response-rcxsource' and response.get('rcxSource') and hardware&8 and r['rip']==base+0xbbc0c:
                            source=response['rcxSource'];source_report=source['report']
                            instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                            if (not instruction or instruction.mnemonic!='call' or not instruction.operands
                                    or instruction.operands[0].type!=capstone.x86.X86_OP_IMM
                                    or instruction.operands[0].imm!=base+0x950131):
                                raise RuntimeError('RCX-source terminal exit call precondition changed')
                            source_report['terminal']={'kind':'observed-exit-call','rva':'0xbbc0c',
                                'targetRva':'0x950131','threadId':tid,
                                'instruction':instruction.mnemonic+' '+instruction.op_str,
                                'exitCodeArgument':r['rcx']&0xffffffff,
                                'slotHex':read(source['slotAddress'],8).hex(),
                                'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                'lastLoader':source_report.get('lastLoader'),
                                'lastWriter':source_report.get('lastWriter')}
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            snapshot(tid,ptr,'synthetic-response-rcx-source')
                            report['status']='synthetic-response-rcx-source'
                            flags(ptr,disable=0x100)
                        elif MODE=='fixture-response-rcxchain' and response.get('rcxChain') and hardware&8 and r['rip']==base+0xbbc0c:
                            chain=response['rcxChain'];chain_report=chain['report']
                            instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                            if (not instruction or instruction.mnemonic!='call' or not instruction.operands
                                    or instruction.operands[0].type!=capstone.x86.X86_OP_IMM
                                    or instruction.operands[0].imm!=base+0x950131):
                                raise RuntimeError('RCX-chain terminal exit call precondition changed')
                            chain_report['terminal']={'kind':'observed-exit-call','rva':'0xbbc0c',
                                'targetRva':'0x950131','threadId':tid,
                                'instruction':instruction.mnemonic+' '+instruction.op_str,
                                'exitCodeArgument':r['rcx']&0xffffffff,
                                'slotHex':read(chain['slotAddress'],8).hex(),
                                'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                'lastWriter':chain_report.get('lastWriter'),
                                'lastConsumer':chain_report.get('lastConsumer')}
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            snapshot(tid,ptr,'synthetic-response-rcx-chain')
                            report['status']='synthetic-response-rcx-chain'
                            flags(ptr,disable=0x100)
                        elif response.get('exitCandidateSlots') and any(
                                hardware&(1<<slot) and r['rip']==base+rva
                                for slot,rva in response['exitCandidateSlots'].items()):
                            slot=next(slot for slot,rva in response['exitCandidateSlots'].items()
                                      if hardware&(1<<slot) and r['rip']==base+rva)
                            instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                            expected_exit_wrapper=base+0x950131
                            if MODE in ('fixture-response-exittrace','fixture-response-exitreturn') and r['rip']-base==0xbbc0c and (
                                    not instruction or instruction.mnemonic!='call' or not instruction.operands
                                    or instruction.operands[0].type!=capstone.x86.X86_OP_IMM
                                    or instruction.operands[0].imm!=expected_exit_wrapper):
                                raise RuntimeError('Exit-trace candidate no longer calls RVA 0x950131')
                            item={'slot':slot,'rva':hex(r['rip']-base),'tid':tid,
                                  'instruction':instruction.mnemonic+' '+instruction.op_str if instruction else None,
                                  'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                  'stackTopHex':read(r['rsp'],128).hex()}
                            hits=report.setdefault('exitCandidateHits',[]);hits.append(item)
                            if sum(1 for hit in hits if hit['rva']==item['rva'])<=3:
                                snapshot(tid,ptr,'exit-candidate-'+str(slot)+'-'+str(len(hits)))
                            if MODE=='fixture-response-exitreturn' and item['rva']=='0xbbc0c':
                                report['controlIntervention']={'kind':'skip observed process-exit call',
                                    'siteRva':item['rva'],'skippedTargetRva':'0x950131','resumeRva':'0xbbc11',
                                    'threadId':tid,'stackPointer':hex(r['rsp']),
                                    'scope':'Diagnostic control-flow test after the synthetic response; no disk code patch'}
                                put64(ptr,'rip',base+0xbbc11);put64(ptr,'dr0',0);put64(ptr,'dr7',0x50)
                            elif MODE=='fixture-response-exittrace' and item['rva']=='0xbbc0c' and not key_trace_file:
                                key_trace_file=(OUT/'key-trace.jsonl').open('w',encoding='utf-8')
                                key_trace_active=True;key_trace_paused=False;key_trace_tid=tid;key_trace_dr7_base=0x50
                                put64(ptr,'dr0',0);put64(ptr,'dr7',key_trace_dr7_base)
                                report['keyTrace']={'scope':'Trace from observed call RVA 0xBBC0C toward the process-exit path',
                                    'startRva':item['rva'],'expectedCallTargetRva':'0x950131',
                                    'threadId':tid,'instructions':0,'complete':False}
                        elif hardware&4 and r['rip']==base+0xe5770:
                            if MODE=='fixture-response-flagprobe' and response.get('flagProbe'):
                                probe=response['flagProbe'];probe_report=probe['report']
                                probe_report['complete']=all(
                                    flag_path['phase']=='complete' for flag_path in probe['paths'].values())
                                probe_report['terminal']={'kind':'protocol-entry','rva':'0xe5770','threadId':tid,
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                    'pathPhases':{str(slot):path['phase'] for slot,path in probe['paths'].items()},
                                    'slotHex':{str(slot):read(path['slotAddress'],8).hex() for slot,path in probe['paths'].items()},
                                    'allPathsComplete':probe_report['complete']}
                            if MODE=='fixture-response-slotwatch' and response.get('slotWatch'):
                                watch=response['slotWatch'];watch_report=watch['report']
                                watch_report['terminal']={'kind':'protocol-entry','rva':'0xe5770','threadId':tid,
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                    'slotHex':{str(slot):read(path['slotAddress'],8).hex()
                                        for slot,path in watch['paths'].items()},
                                    'consumerSeen':{str(slot):path['report']['consumerSeen']
                                        for slot,path in watch['paths'].items()}}
                            if MODE=='fixture-response-rcxchain' and response.get('rcxChain'):
                                chain=response['rcxChain'];chain_report=chain['report']
                                chain_report['terminal']={'kind':'protocol-entry','rva':'0xe5770','threadId':tid,
                                    'slotHex':read(chain['slotAddress'],8).hex(),
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                    'lastWriter':chain_report.get('lastWriter'),
                                    'lastConsumer':chain_report.get('lastConsumer')}
                            if MODE=='fixture-response-rcxsource' and response.get('rcxSource'):
                                source=response['rcxSource'];source_report=source['report']
                                source_report['terminal']={'kind':'protocol-entry','rva':'0xe5770','threadId':tid,
                                    'slotHex':read(source['slotAddress'],8).hex(),
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                    'lastLoader':source_report.get('lastLoader'),
                                    'lastWriter':source_report.get('lastWriter')}
                            snapshot(tid,ptr,'synthetic-response-protocol-entry')
                            report['status']='synthetic-response-protocol-entry'
                            key_trace_active=False;flags(ptr,disable=0x100)
                        elif hardware&8 and r['rip']==exit_exports['RtlExitUserProcess']:
                            report['syntheticResponse']['exitCode']=r['rcx']&0xffffffff
                            report['syntheticResponse']['finalHex']=read(response['address'],response['capacity']).hex()
                            if report.get('responseBody'):
                                body=report['responseBody'];body['atExitHex']=read(int(body['address'],16),body['bytes']).hex()
                            snapshot(tid,ptr,'synthetic-response-exit-request')
                            report['status']='synthetic-response-exit-request'
                            key_trace_active=False;flags(ptr,disable=0x100)
                        else:
                            site=hex(r['rip']-base)
                            response['siteCounts'][site]=response['siteCounts'].get(site,0)+1
                            report['syntheticResponse']['siteCounts']=response['siteCounts']
                            if response['siteCounts'][site]<=3:
                                response['observations'].append({'ripRva':site,'hardwareMask':hardware,
                                    'bufferHex':read(response['address'],response['capacity']).hex()})
                                snapshot(tid,ptr,'response-access-'+str(len(response['observations'])))
                            if len(response['observations'])>=40:report['status']='synthetic-response-access-limit'
                            if site=='0x111036a' and not report.get('dataIntervention'):
                                require_runtime_instruction(0x1110366,'mov edx, dword ptr [rcx + rdx*4 - 4]',4)
                                candidate=read(r['rbp']+16,4)
                                assert candidate==bytes.fromhex('3bc47a8f')
                                replay=bytes.fromhex('000000000000000000000000000000003bc47a8f7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a775')
                                assert len(replay)==1040 and replay[16:20]==candidate
                                data=C.create_string_buffer(replay);written=C.c_size_t()
                                if not K.WriteProcessMemory(ph,response['address'],data,len(replay),C.byref(written)) or written.value!=len(replay):
                                    raise RuntimeError('Replay write failed')
                                assert read(response['address'],len(replay))==replay
                                put64(ptr,'rdx',int.from_bytes(candidate,'little'))
                                report['dataIntervention']={'scope':'Replay fixed decrypted synthetic response, including first-field equality',
                                    'siteRva':site,'sha256':hashlib.sha256(replay).hexdigest()}
                                report['comSelection']={'case':COM_CASE,'tableHits':0,'commitHits':0}
                                put64(ptr,'dr0',response['address']+64);put64(ptr,'dr1',base+0x951e0);put64(ptr,'dr7',0xb0055)
                    elif tid in request_states and hardware:
                        request=request_states[tid]
                        if request.get('keyTraceWaiting') and hardware&1 and r['rip']==base+KEY_TRACE_START_RVA:
                            request['keyTraceWaiting']=False;key_trace_active=True
                            put64(ptr,'dr7',0x44)
                            snapshot(tid,ptr,'key-trace-focused-start')
                        elif key_trace_active and hardware&1 and r['rip']==key_trace_resume:
                            put64(ptr,'dr7',r['dr7']&~1)
                            key_trace_resume=0
                            skips=report.get('keyTraceNaturalLoopSkips',[])
                            if skips and 'resumed' not in skips[-1]:
                                skips[-1]['resumed']={'rva':hex(r['rip']-base),'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                                snapshot(tid,ptr,'key-loop-natural-return')
                        elif key_trace_active and hardware&2 and r['rip']==base+0xd7203f:
                            snapshot(tid,ptr,'raw-key-first-byte-written')
                            key_trace_active=False
                            flags(ptr,disable=0x100)
                            report['status']='request-key-trace-captured'
                        elif hardware&8 and r['rip']==network_exports['send']:
                            report['requestBuffer']['actualAddress']=hex(r['rdx'])
                            report['requestBuffer']['addressMatched']=r['rdx']==request['address']
                            report['requestBuffer']['sendBytes']=r['r8']
                            report['requestBuffer']['finalHex']=read(r['rdx'],min(r['r8'],4096)).hex()
                            report['requestBuffer']['scheduleHex']=read(request['scheduleAddress'],240).hex()
                            native=read(base+0x13c5000,0x6000)
                            (OUT/'request-native.bin').write_bytes(native)
                            report['requestNative']={'rva':'0x13c5000','size':len(native),'sha256':hashlib.sha256(native).hexdigest()}
                            snapshot(tid,ptr,'request-pre-send')
                            report['status']='request-writes-captured'
                        else:
                            observations=request['observations']
                            data=read(request['address'],140)
                            site=hex(r['rip']-base)
                            counts=request.setdefault('siteCounts',{})
                            counts[site]=counts.get(site,0)+1
                            report['requestBuffer']['siteCounts']=counts
                            observation={'index':len(observations),'ripRva':site,
                                'observationType':'before-aes-store' if MODE=='fixture-request-plain' else 'after-watched-write',
                                'blockPointer':hex(r['r8']) if MODE=='fixture-request-plain' else None,
                                'hardwareMask':hardware,'bufferHex':data.hex(),
                                'scheduleHex':read(request['scheduleAddress'],240).hex(),
                                'rawKeyHex':read(request['rawKeyAddress'],32).hex(),
                                'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}}
                            if MODE not in ORIGIN_MODES or counts[site]<=3:
                                observations.append(observation)
                                snapshot(tid,ptr,'request-write-'+str(len(observations)))
                            else:
                                report['requestBuffer'].setdefault('lastRepeatedWrites',{})[site]=observation
                                report['requestBuffer']['samplingNote']='First three full snapshots per instruction; repeated writes counted and latest retained, not a complete write log.'
                            if len(observations)>=160:report['status']='request-write-limit'
                            if MODE in ORIGIN_MODES and site=='0xd75699' and hardware&6 and not request.get('keyWatchArmed'):
                                request['keyWatchArmed']=True
                                report['requestBuffer']['rawKeyAddress']=hex(request['rawKeyAddress'])
                                report['requestBuffer']['keyWatchArmedAt']=site
                                put64(ptr,'dr0',request['rawKeyAddress'])
                                put64(ptr,'dr1',request['rawKeyAddress']+28)
                                if read(base+0x13ca1cc,3)!=bytes.fromhex('418908'):
                                    raise RuntimeError('Observed AES store instruction bytes changed')
                                put64(ptr,'dr2',base+0x13ca1cc)
                                put64(ptr,'dr7',0x55|(0xd<<16)|(0xd<<20))
                                if MODE=='fixture-key-trace':
                                    request['keyTraceWaiting']=True
                                    key_trace_file=(OUT/'key-trace.jsonl').open('w',encoding='utf-8')
                                    if read(base+KEY_TRACE_START_RVA,1)!=b'\x9c':raise RuntimeError('Key trace start bytes changed')
                                    put64(ptr,'dr0',base+KEY_TRACE_START_RVA)
                                    put64(ptr,'dr1',base+0xd7203f)
                                    put64(ptr,'dr7',0x45)
                                    report['keyTrace']={'armedAtRva':site,'startRva':hex(KEY_TRACE_START_RVA),'stopRva':'0xd7203f','instructions':0}
                            elif MODE=='fixture-request-origin' and request.get('keyWatchArmed') and hardware&4:
                                # Preserve one fully assembled plaintext before AES writes it.
                                report['requestBuffer']['beforeAesHex']=data.hex()
                                put64(ptr,'dr7',0x45|(0xd<<16)|(0xd<<20))
                    elif tid in network_threads and hardware:
                        network_event(tid,ptr,r,hardware)
                    elif MODE=='fixture-fields' and hardware&2 and r['rip']==base+0x13c5b8b:
                        snapshot(tid,ptr,'field-trace-network-boundary')
                        report['status']='field-follow-to-network';trace_active=False
                    elif MODE=='fixture-fields' and hardware&1 and r['rip']==base+0x13c5729:
                        snapshot(tid,ptr,'license-marker-compare-return')
                        report['markerCompareReturn']=C.c_int32(r['rax']&0xffffffff).value
                        if report['markerCompareReturn']!=0:raise RuntimeError('Matching fixture did not pass observed marker comparison')
                        put64(ptr,'dr0',base+FIELD_START_RVA)
                        put64(ptr,'dr1',base+0x13c5b8b)
                        put64(ptr,'dr7',0x45)
                        report['status']='waiting-known-license-field-read'
                    elif MODE=='fixture-fields' and hardware&1 and r['rip']==base+FIELD_START_RVA and not trace_active:
                        snapshot(tid,ptr,'license-field-trace-start')
                        trace_active=True
                        field_trace=(OUT/'license-field-trace.jsonl').open('w',encoding='utf-8')
                        put64(ptr,'dr7',0x44)
                        report['status']='tracing-license-field-consumption'
                    elif trace_active and hardware&1 and r['rip']==single_step_aux:
                        put64(ptr,'dr7',r['dr7']&~1)
                        single_step_aux=0
                        if external_pending is not None:
                            external_pending['returnValue']=hex(r['rax'])
                            external_pending['returnedAtTraceIndex']=trace_count
                            external_pending['argumentMemoryAfter']={n:read(a,128).hex() for n,a in external_pending['argumentAddresses'].items()}
                            snapshot(tid,ptr,'external-call-return')
                            external_pending=None
                    elif license_watch_active and hardware:
                        is_transform_return=hardware&8 and r['rip']==base+0x13c56e4
                        snapshot(tid,ptr,'license-transform-return' if is_transform_return else 'license-data-'+hex(hardware))
                        report['licenseDataHits']=report.get('licenseDataHits',0)+1
                        if is_transform_return:
                            if MODE=='fixture-fields':
                                license_watch_active=False
                                put64(ptr,'dr0',base+0x13c5729)
                                put64(ptr,'dr3',base+0xe5770)
                                put64(ptr,'dr7',0x41)
                                report['status']='waiting-marker-compare-return'
                            elif MODE=='license-slice':
                                trace_active=True
                                field_trace=(OUT/'license-field-trace.jsonl').open('w',encoding='utf-8')
                                put64(ptr,'dr3',base+0xe5770)
                                put64(ptr,'dr7',0x40)
                                report['status']='tracing-decoded-license'
                            elif MODE=='license-validate':
                                payload=int(report['licensePayload']['address'],16)
                                put64(ptr,'dr0',payload&~3)
                                put64(ptr,'dr1',(payload+4)&~3)
                                put64(ptr,'dr2',(payload+128)&~3)
                                put64(ptr,'dr3',base+0xe5770)
                                put64(ptr,'dr7',0x55|(0xf<<16)|(0xf<<20)|(0xf<<24))
                                report['status']='watching-decoded-license'
                            else:report['status']='license-transform-return-captured'
                        elif hardware&8:
                            report['status']='protocol-loop-reached-with-fixture'
                        elif report['licenseDataHits']>=10:
                            report['status']='license-data-watches-captured'
                    elif hardware&8:
                        if r['rip']==continue_address:
                            context=read(r['rcx'],1232)
                            if len(context)!=1232:raise RuntimeError('NtContinue context read incomplete')
                            target=struct.unpack_from('<Q',context,248)[0]
                            report.setdefault('continuations',[]).append({'tid':tid,'contextAddress':hex(r['rcx']),
                                'target':hex(target),'flags':hex(struct.unpack_from('<I',context,48)[0]),
                                'dr7':hex(struct.unpack_from('<Q',context,112)[0]),'targetExport':nt_exports.get(target)})
                            snapshot(tid,ptr,'NtContinue-entry')
                            target_module=next((m for m in modules if m['base']<=target<m['base']+m['size']),None)
                            target_mbi=h.MBI()
                            executable=K.VirtualQueryEx(ph,target,C.byref(target_mbi),C.sizeof(target_mbi)) and target_mbi.protect&0xff in (0x10,0x20,0x40,0x80)
                            if target_module and executable and soft_breakpoint is None:
                                original=read(target,1)
                                if len(original)!=1 or original==b'\xcc':raise RuntimeError('Unexpected continuation byte')
                                write_debug_byte(target,b'\xcc')
                                soft_breakpoint={'address':target,'original':original}
                                report['codePatched']=True
                                report['temporaryBreakpoint']={'address':hex(target),'originalByte':original.hex(),
                                    'module':target_module['name'],'purpose':'Restore hardware observation after context reset','restored':False}
                        elif r['rip']==base+0x11099:
                            snapshot(tid,ptr,'istream-read-return')
                            put64(ptr,'dr3',base+0x13c560c)
                        elif r['rip']==base+0x13c560c:
                            snapshot(tid,ptr,'license-read-caller')
                            if MODE in ('license-watch','license-tail','license-validate','license-slice','fixture-fields'):
                                mbi=h.MBI()
                                if not K.VirtualQueryEx(ph,r['rsp'],C.byref(mbi),C.sizeof(mbi)):raise RuntimeError('Stack query failed')
                                stackdata=read(r['rsp'],min(0x20000,mbi.base+mbi.regionSize-r['rsp']))
                                pattern=(RUN/'user.lic').read_bytes() if MODE=='fixture-fields' else bytes(range(132))
                                offset=stackdata.find(pattern)
                                if offset<0 or stackdata.find(pattern,offset+1)>=0:raise RuntimeError('Expected exactly one synthetic license copy on stack')
                                payload=r['rsp']+offset
                                report['licensePayload']={'address':hex(payload),'bytes':132,'sha256':hashlib.sha256(read(payload,132)).hexdigest()}
                                put64(ptr,'dr0',payload&~7)
                                put64(ptr,'dr1',(payload+128)&~3)
                                put64(ptr,'dr2',(payload+64)&~7)
                                put64(ptr,'dr3',base+0xe5770)
                                put64(ptr,'dr7',0x55|(0xb<<16)|(0xf<<20)|(0xb<<24))
                                if MODE in ('license-tail','license-validate','license-slice','fixture-fields'):
                                    put64(ptr,'dr0',(payload+128)&~3)
                                    put64(ptr,'dr3',base+0x13c56e4)
                                    put64(ptr,'dr7',0x41|(0xf<<16))
                                license_watch_active=True
                                report['status']='watching-license-data'
                            else:
                                report['status']='license-file-boundary-captured'
                                put64(ptr,'dr7',r['dr7']&~0x40)
                        else:
                            label='main-entry' if r['rip']==base+0xa5fd0 else 'protocol-loop-entry'
                            snapshot(tid,ptr,label)
                            if label=='main-entry' and (MODE=='fixture-network' or MODE in REQUEST_MODES or MODE in RESPONSE_MODES):arm_network_context(tid,ptr)
                            elif label=='main-entry':put64(ptr,'dr3',base+0xe5770)
                            else:put64(ptr,'dr7',r['dr7']&~0x40)
                    elif hardware:
                        slot=next(i for i in range(3) if hardware&(1<<i))
                        state=file_slots[tid,slot];name=state['name']
                        item={'name':name,'phase':state['phase'],'time':time.time(),'tid':tid}
                        if state['phase']=='enter':
                            ret=struct.unpack('<Q',read(r['rsp'],8))[0]
                            item['returnAddress']=hex(ret)
                            item['callerRva']=hex(ret-base) if base<=ret<base+0x4000000 else None
                            if name.startswith('CreateFile'):
                                rawname=read(r['rcx'],1024)
                                path=rawname.decode('utf-16-le' if name.endswith('W') else 'utf-8',errors='replace').split('\0',1)[0]
                                item['path']=path
                                state['path']=path
                                state['capture']=any(x in path.lower() for x in ('user.lic','sn.txt','config.ini','.nnue'))
                                item['desiredAccess']=hex(r['rdx']);item['disposition']=int.from_bytes(read(r['rsp']+0x28,8),'little')
                            else:
                                state.update(handle=r['rcx'],buffer=r['rdx'],capacity=r['r8'],countPointer=r['r9'])
                                state['path']=file_handles.get(r['rcx'])
                                state['capture']=state['path'] is not None
                                item.update(path=state['path'],requestedBytes=r['r8'])
                            state['phase']='return';put64(ptr,'dr'+str(slot),ret)
                        else:
                            item.update(path=state.get('path'),returnValue=hex(r['rax']))
                            if name.startswith('CreateFile') and state['capture'] and r['rax'] not in (0,0xffffffffffffffff):
                                file_handles[r['rax']]=state['path']
                            if name=='ReadFile' and state['capture'] and r['rax']:
                                count=int.from_bytes(read(state['countPointer'],4),'little')
                                item['actualBytes']=count
                                if state['path'].lower().endswith(('user.lic','sn.txt')):
                                    data=read(state['buffer'],min(count,state['capacity'],4096))
                                    item['bufferHex']=data.hex()
                                    put64(ptr,'dr3',base+0x11099)
                            state['phase']='enter';put64(ptr,'dr'+str(slot),file_apis[name])
                        if state.get('capture'):
                            report['fileEvents'].append(item)
                            snapshot(tid,ptr,'file-'+name+'-'+item['phase'])
                    if key_trace_active and key_trace_tid is None:
                        key_trace_tid=tid
                        report['keyTrace']['threadId']=tid
                    if key_trace_active and not key_trace_paused and tid==key_trace_tid:
                        instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                        if not instruction:raise RuntimeError('Key trace instruction unavailable')
                        accesses=[]
                        for op in instruction.operands:
                            if op.type!=capstone.x86.X86_OP_MEM:continue
                            bn=instruction.reg_name(op.mem.base);ix=instruction.reg_name(op.mem.index)
                            bv=r['rip']+instruction.size if bn=='rip' else r.get(bn,0)
                            av=(bv+r.get(ix,0)*op.mem.scale+op.mem.disp)&0xffffffffffffffff
                            accesses.append({'address':hex(av),'size':op.size,'access':op.access,
                                             'hex':read(av,min(op.size,32)).hex()})
                        index=report['keyTrace']['instructions']
                        trace_module=next((m for m in modules if m['base']<=r['rip']<m['base']+m['size']),None)
                        trace_row={'n':index,'tid':tid,'address':hex(r['rip']),'rva':hex(r['rip']-base),
                            'bytes':instruction.bytes.hex(),'instruction':instruction.mnemonic+' '+instruction.op_str,
                            'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},'memory':accesses}
                        if trace_module:
                            trace_row['module']=trace_module['name']
                            trace_row['moduleRva']=hex(r['rip']-trace_module['base'])
                        key_trace_file.write(json.dumps(trace_row)+'\n')
                        report['keyTrace']['instructions']=index+1
                        if (index+1)%5000==0:
                            key_trace_file.flush();os.fsync(key_trace_file.fileno())
                            report['keyTrace']['fsyncedInstructions']=index+1
                        if MODE=='fixture-response-exittrace' and r['rip']==runtime_exit:
                            key_trace_file.flush();os.fsync(key_trace_file.fileno())
                            report['keyTrace']['fsyncedInstructions']=index+1
                            report['keyTrace']['nativeResume']={'name':'ucrtbase!exit','address':hex(r['rip']),
                                'moduleRva':hex(r['rip']-trace_module['base']) if trace_module else None,
                                'traceIndex':index,'threadId':tid}
                            key_trace_paused=True
                            put64(ptr,'dr7',key_trace_dr7_base);flags(ptr,disable=0x100)
                        elif index>=(19999 if MODE=='fixture-response-sourcewindow' else (299999 if MODE=='fixture-response-bodytrace' else 8191)):
                            key_trace_active=False;report['status']='request-key-trace-limit';flags(ptr,disable=0x100)
                        else:
                            flags(ptr,enable=0x100)
                            arm_pushfq_repair(tid,r,instruction,index,'key')
                            if instruction.mnemonic=='popfq':
                                key_trace_resume=r['rip']+instruction.size
                                put64(ptr,'dr0',key_trace_resume);put64(ptr,'dr7',key_trace_dr7_base|1)
                            if r['rip']-base in (0x12c9cad,0x11a6e86) and instruction.mnemonic=='jne':
                                key_trace_resume=r['rip']+instruction.size
                                report.setdefault('keyTraceNaturalLoopSkips',[]).append({'fromRva':hex(r['rip']-base),
                                    'resumeRva':hex(key_trace_resume-base),'traceIndex':index,
                                    'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')},
                                    'note':'Observed repeated loop executes normally; only instruction logging pauses.'})
                                put64(ptr,'dr0',key_trace_resume);put64(ptr,'dr7',key_trace_dr7_base|1)
                                flags(ptr,disable=0x100)
                    if branch_trace_active and tid==branch_trace_tid:
                        if hardware&1 and branch_trace_resume and r['rip']==branch_trace_resume:
                            put64(ptr,'dr0',0);put64(ptr,'dr7',0);branch_trace_resume=0
                        state=branch_trace_state
                        pending_control=state.get('pendingControl')
                        if pending_control:
                            pending_control['nextAddress']=hex(r['rip'])
                            pending_control['nextRva']=hex(r['rip']-base)
                            if pending_control.get('targetAddress') is not None:
                                pending_control['taken']=r['rip']==pending_control['targetAddress']
                            state['pendingControl']=None
                        instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                        if not instruction:raise RuntimeError('Body-branch trace instruction unavailable')
                        index=state['instructions']
                        trace_module=next((m for m in modules if m['base']<=r['rip']<m['base']+m['size']),None)
                        compact={'n':index,'address':hex(r['rip']),'rva':hex(r['rip']-base),
                            'bytes':instruction.bytes.hex(),
                            'instruction':(instruction.mnemonic+' '+instruction.op_str).strip()}
                        if trace_module:
                            compact['module']=trace_module['name']
                            compact['moduleRva']=hex(r['rip']-trace_module['base'])
                        state['tail'].append(compact)
                        mnemonic=instruction.mnemonic
                        interesting=(mnemonic in ('cmp','test','call','ret','retf') or mnemonic.startswith('j')
                            or mnemonic.startswith('loop') or mnemonic.startswith('cmov') or mnemonic.startswith('set'))
                        if interesting:
                            event={**compact,'eflags':hex(r['eflags']),
                                'registers':{name:hex(value) for name,value in r.items() if not name.startswith('dr')}}
                            if mnemonic.startswith('j') or mnemonic.startswith('loop') or mnemonic in ('call','ret','retf'):
                                event['fallthroughAddress']=hex(r['rip']+instruction.size)
                                event['fallthroughRva']=hex(r['rip']+instruction.size-base)
                                if instruction.operands and instruction.operands[0].type==capstone.x86.X86_OP_IMM:
                                    event['targetAddress']=instruction.operands[0].imm
                                    event['targetAddressHex']=hex(instruction.operands[0].imm)
                                    event['targetRva']=hex(instruction.operands[0].imm-base)
                                state['pendingControl']=event
                            if len(state['events'])==BRANCH_TRACE_EVENT_LIMIT:state['discardedEvents']+=1
                            state['events'].append(event);state['interestingInstructions']+=1
                        state['instructions']=index+1
                        terminal_rva=r['rip']-base;terminal_kind=None;terminal_detail={}
                        if terminal_rva==0x10d01a2:
                            actual=(r['rdi']+r['r8']-0x1f933200)&0xffffffffffffffff
                            raw=read(actual,8)
                            source_value=struct.unpack('<Q',raw)[0] if len(raw)==8 else None
                            terminal_detail={'sourceAddress':hex(actual),'sourceHex':raw.hex(),
                                'sourceValue':hex(source_value) if source_value is not None else None,
                                'expectedAddress':hex(response_states[tid]['bodyBranchMarkerRsp']+0x98)}
                            if actual==response_states[tid]['bodyBranchMarkerRsp']+0x98 and source_value==1:
                                terminal_kind='rcx-source-one'
                        elif terminal_rva==0xbbc0c:terminal_kind='exit-call'
                        elif terminal_rva==0xe5770:terminal_kind='protocol-entry'
                        if terminal_kind is not None:
                            report['bodyBranchTrace']['terminal']={'kind':terminal_kind,'rva':hex(terminal_rva),
                                'address':hex(r['rip']),'threadId':tid,**terminal_detail,
                                'registers':{name:hex(value) for name,value in r.items() if not name.startswith('dr')}}
                            publish_branch_trace(terminal_kind)
                            snapshot(tid,ptr,'response-body-branch-'+terminal_kind)
                            report['status']='synthetic-response-body-branch'
                            branch_trace_active=False;flags(ptr,disable=0x100)
                        elif state['instructions']>=BRANCH_TRACE_INSTRUCTION_LIMIT:
                            publish_branch_trace('instruction-limit')
                            report['status']='synthetic-response-body-branch-limit'
                            branch_trace_active=False;flags(ptr,disable=0x100)
                        else:
                            flags(ptr,enable=0x100)
                            arm_pushfq_repair(tid,r,instruction,index,'branch')
                            if mnemonic=='popfq':
                                branch_trace_resume=r['rip']+instruction.size
                                put64(ptr,'dr0',branch_trace_resume);put64(ptr,'dr7',1)
                    if trace_active:
                        instruction=next(dis.disasm(read(r['rip'],15),r['rip'],count=1),None)
                        if not instruction:raise RuntimeError('Decoded-license trace instruction unavailable')
                        field_trace.write(json.dumps({'n':trace_count,'rva':hex(r['rip']-base),'bytes':instruction.bytes.hex(),
                            'instruction':instruction.mnemonic+' '+instruction.op_str,
                            'registers':{n:hex(v) for n,v in r.items() if not n.startswith('dr')}})+'\n')
                        trace_count+=1
                        payload=int(report['licensePayload']['address'],16)
                        def register_value(name):
                            if not name:return 0
                            if name in r:return r[name]
                            if name.startswith('e') and ('r'+name[1:]) in r:return r['r'+name[1:]]&0xffffffff
                            return 0
                        for op in instruction.operands:
                            if op.type!=capstone.x86.X86_OP_MEM or not op.access&capstone.CS_AC_READ:continue
                            bn=instruction.reg_name(op.mem.base);ix=instruction.reg_name(op.mem.index)
                            address=((r['rip']+instruction.size if bn=='rip' else register_value(bn))+register_value(ix)*op.mem.scale+op.mem.disp)&0xffffffffffffffff
                            if address<payload+132 and address+op.size>payload:
                                access={'n':trace_count-1,'rva':hex(r['rip']-base),'offset':address-payload,'size':op.size,
                                    'instruction':instruction.mnemonic+' '+instruction.op_str,'bytesHex':read(address,op.size).hex()}
                                report.setdefault('licenseFieldReads',[]).append(access)
                                if 'firstLicenseFieldRead' not in report:
                                    report['firstLicenseFieldRead']=access
                                    snapshot(tid,ptr,'license-first-field-read')
                                if MODE!='fixture-fields':
                                    report['status']='license-field-read-captured';trace_active=False;break
                        if MODE=='fixture-fields' and 'firstLicenseFieldRead' in report and trace_count>=report['firstLicenseFieldRead']['n']+140000:
                            snapshot(tid,ptr,'license-field-follow-limit')
                            report['status']='license-field-follow-limit';trace_active=False
                        if trace_active and trace_count>=(140000 if MODE=='fixture-fields' else 50000):
                            report['status']='license-field-trace-limit';trace_active=False
                        if trace_active:
                            flags(ptr,enable=0x100)
                            arm_pushfq_repair(tid,r,instruction,trace_count-1,'field')
                            if instruction.mnemonic=='popfq':
                                single_step_aux=r['rip']+instruction.size
                                put64(ptr,'dr0',single_step_aux)
                                put64(ptr,'dr7',C.c_uint64.from_address(ptr+REG['dr7']).value|1)
                            if r['rip']-base in (0x12061fa,0x10ebd98,0x11db0a4) and instruction.mnemonic=='jne':
                                # v28 dynamically records this repeated loop and its actual
                                # conditional branch. Let it finish without altering state.
                                single_step_aux=r['rip']+instruction.size
                                report.setdefault('naturalLoopSkips',[]).append({'fromRva':hex(r['rip']-base),
                                    'resumeRva':hex(single_step_aux-base),'traceIndex':trace_count-1,
                                    'registers':{n:hex(r[n]) for n in ('rax','rdx','rbx','rcx','rdi','rsi')}})
                                put64(ptr,'dr0',single_step_aux)
                                put64(ptr,'dr7',C.c_uint64.from_address(ptr+REG['dr7']).value|1)
                                flags(ptr,disable=0x100)
                            if MODE=='fixture-fields' and not base<=r['rip']<base+0x4000000:
                                return_bytes=read(r['rsp'],8)
                                call_return=int.from_bytes(return_bytes,'little')
                                module=next((m for m in modules if m['base']<=r['rip']<m['base']+m['size']),None)
                                if module and len(return_bytes)==8 and base<=call_return<base+0x4000000:
                                    if module['name'] not in external_export_cache:
                                        external_pe=pefile.PE(module['path'])
                                        external_export_cache[module['name']]=sorted((module['base']+s.address,s.name.decode(errors='replace'))
                                            for s in external_pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name and not s.forwarder)
                                    preceding=max((x for x in external_export_cache[module['name']] if x[0]<=r['rip']),default=None)
                                    external_pending={'module':module['name'],'moduleRva':hex(r['rip']-module['base']),
                                        'export':preceding[1] if preceding and preceding[0]==r['rip'] else None,
                                        'returnRva':hex(call_return-base),'traceIndex':trace_count-1,
                                        'argumentAddresses':{n:r[n] for n in ('rcx','rdx','r8','r9')},
                                        'argumentMemoryBefore':{n:read(r[n],128).hex() for n in ('rcx','rdx','r8','r9')}}
                                    report.setdefault('externalCallSkips',[]).append(external_pending)
                                    snapshot(tid,ptr,'external-call-entry')
                                    single_step_aux=call_return
                                    put64(ptr,'dr0',call_return)
                                    put64(ptr,'dr7',C.c_uint64.from_address(ptr+REG['dr7']).value|1)
                                    flags(ptr,disable=0x100)
                        else:flags(ptr,disable=0x100)
                    current_rip=C.c_uint64.from_address(ptr+REG['rip']).value
                    resume_faulting_instruction=execution_hardware and current_rip==r['rip']
                    flags(ptr,enable=0x10000 if resume_faulting_instruction else 0,
                          disable=0 if resume_faulting_instruction else 0x10000)
                    put64(ptr,'dr6',0);apply_context(th,ptr)
                finally:K.CloseHandle(th)
            else:
                exception_event={'code':hex(code),'address':hex(addr),'firstChance':first,'threadId':tid}
                if code==0xc0000005 and len(report.get('faultContexts',[]))<2:
                    th,buf,ptr=get_context(tid)
                    try:
                        fault_regs=regs(ptr)
                        parameter_count=min(struct.unpack_from('<I',raw,40)[0],15)
                        parameters=list(struct.unpack_from('<'+'Q'*parameter_count,raw,48))
                        instruction=next(dis.disasm(read(fault_regs['rip'],15),fault_regs['rip'],count=1),None)
                        fault={'threadId':tid,'firstChance':first,'rva':hex(addr-base),
                            'parameters':[hex(value) for value in parameters],
                            'accessType':parameters[0] if parameters else None,
                            'accessAddress':hex(parameters[1]) if len(parameters)>1 else None,
                            'instruction':(instruction.mnemonic+' '+instruction.op_str).strip() if instruction else None,
                            'instructionBytes':instruction.bytes.hex() if instruction else None,
                            'registers':{name:hex(value) for name,value in fault_regs.items()},
                            'stackHex':read(fault_regs['rsp'],256).hex()}
                        response_at_fault=response_states.get(tid)
                        if response_at_fault:
                            fault['responseAddress']=hex(response_at_fault['address'])
                            fault['responseHex']=read(response_at_fault['address'],response_at_fault['capacity']).hex()
                            selector=response_at_fault.get('zfSelector')
                            if selector:
                                fault['markerRsp']=hex(selector['markerRsp'])
                                fault['frameHex']=read(selector['markerRsp'],0x740).hex()
                        report.setdefault('faultContexts',[]).append(fault)
                        code_start=max(base,fault_regs['rip']-0x100)
                        code_bytes=read(code_start,0x300)
                        code_name='fault-code-'+str(len(report['faultContexts']))+'.bin'
                        (OUT/code_name).write_bytes(code_bytes)
                        fault['codeWindow']={'file':code_name,'address':hex(code_start),'bytes':len(code_bytes),
                            'sha256':hashlib.sha256(code_bytes).hexdigest()}
                        snapshot(tid,ptr,'zf-selector-access-violation')
                    finally:K.CloseHandle(th)
                report['events'].append(exception_event)
                continuation=0x80010001
                if not first:
                    report['status']='unhandled-exception';break
        if report.get('status') in ('license-file-boundary-captured','license-data-watches-captured','protocol-loop-reached-with-fixture','license-transform-return-captured','license-field-read-captured','license-field-trace-limit','license-field-follow-limit','field-follow-to-network','request-writes-captured','request-write-limit','request-key-trace-captured','request-key-trace-limit','synthetic-response-protocol-entry','synthetic-response-exit-request','synthetic-response-access-limit','synthetic-response-body-return','synthetic-response-body-access','synthetic-response-body-page-limit','synthetic-response-body-branch','synthetic-response-body-branch-limit','synthetic-response-rejection-flags','synthetic-response-slot-watch','synthetic-response-source-watch','synthetic-response-rcx-chain','synthetic-response-rcx-source','synthetic-response-zf-selector'):break
        K.ContinueDebugEvent(pid,tid,continuation);pending=None
        if BRIDGE and report.get('bridgeReady') and not report.get('bridgeInputStarted'):
            if not TEST_PLAN.get('bridgeKeepDebugger'):
                if not K.DebugSetProcessKillOnExit(False) or not K.DebugActiveProcessStop(proc.pid):
                    raise C.WinError(C.get_last_error())
                attached=False;report['bridgeDetached']=True
            report['bridgeInputStarted']=True;report['bridgeReadyTime']=time.time()
            bridge_input_thread=threading.Thread(target=forward_client_input,daemon=True)
            bridge_input_thread.start()
            save()
    else:
        if branch_trace_active:
            publish_branch_trace('deadline')
            report['status']='synthetic-response-body-branch-timeout'
        else:report['status']='bounded-timeout'
except Exception as exc:
    report.update(status='error',error=str(exc),traceback=traceback.format_exc())
finally:
    bridge_stop.set()
    if bridge_input_thread and os.environ.get('CYCLONE_CONTROLLER_HANDLE'):
        bridge_input_thread.join(timeout=2)
        report['bridgeInputThreadStopped']=not bridge_input_thread.is_alive()
    if branch_trace_state is not None and 'tail' not in report.get('bodyBranchTrace',{}):
        publish_branch_trace(report.get('status','finalize'))
    if key_trace_file:
        key_trace_file.flush();os.fsync(key_trace_file.fileno());key_trace_file.close()
        report['keyTrace']['fsyncedInstructions']=report['keyTrace']['instructions']
    if field_trace:field_trace.close()
    report['fieldTraceInstructions']=trace_count
    if proc is not None:
        if proc.poll() is None:proc.terminate()
        if pending:K.ContinueDebugEvent(*pending,0x10002)
        stop=time.monotonic()+3
        while attached and time.monotonic()<stop:
            event=C.create_string_buffer(176)
            if K.WaitForDebugEvent(event,100):
                kind,pid,tid=struct.unpack_from('<III',event.raw)
                K.ContinueDebugEvent(pid,tid,0x10002)
                if kind==5:break
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:report['cleanupError']='Timeout'
        for t in readers:t.join(timeout=1)
    if ph:K.CloseHandle(ph)
    if nnue_hidden_model:
        model,hidden=nnue_hidden_model
        assert not model.exists()
        hidden.rename(model)
        report['nnueModel']['restored']=True
    if bridge_job:K.CloseHandle(bridge_job)
    for handle in handles:
        if handle:K.CloseHandle(handle)
    K.SetThreadExecutionState(0x80000000)
    report['finished']=time.time();save()


