"""Guest-only native MAX validation using runtime-checked COM logic."""
from pathlib import Path
import ctypes as C, hashlib, importlib.util, json, os, re, struct, subprocess, sys, threading, time, traceback
import capstone, pefile, queue

version = 'v406'
resources=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))
engine=Path(os.environ['CYCLONE_MAX_ENGINE']).resolve(strict=True)
run=engine.parent;out=Path(os.environ['CYCLONE_MAX_OUTPUT']);root=out
sde=Path(os.environ['CYCLONE_MAX_SDE'])
launch_engine=Path(os.environ.get('CYCLONE_MAX_LAUNCH_ENGINE',str(engine)))
marker=Path(os.environ['CYCLONE_MAX_MARKER'])
owner_pid=int(os.environ['CYCLONE_MAX_OWNER'])
assert hashlib.sha256(engine.read_bytes()).hexdigest()=='fa9b8e8ad7560140bdee671b8bf18c2e4146019983a4ee475fc425ea3539b0c1'
assert hashlib.sha256((run/'cyclone-eval.nnue').read_bytes()).hexdigest()=='324d1fb215d5dacb1278da0820ce79b8cbadca2c0fce01f1d3c83bb04459709d'
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
rspmod = module('rsp', str(resources/'max_rsp.py'))
h = module('helpers', str(resources/'max_helpers.py'))
pipebroker = module('max_pipe',str(resources/'max_pipe.py')).Broker()
report = {'version': version, 'status': 'starting', 'passed': False, 'protocolAccepted': False,
          'scope': 'MAX native initialization, protocol and short chess-rule validation; no strength acceptance', 'events': []}
proc = None; debugger = None; handle = None; stdout = bytearray(); stderr = bytearray(); workers = []
def save():
    temp=out/'max-summary.json.tmp';temp.write_text(json.dumps(report,indent=2),encoding='utf-8');temp.replace(out/'max-summary.json')
def stage(name):
    report['stage'] = name; report['updated'] = time.time(); save()
def consume(stream, buffer):
    for part in iter(lambda: stream.read1(4096), b''):
        buffer.extend(part)
        if stream is proc.stdout: pipebroker.on_data(part)
def read_local(address, size):
    buf = C.create_string_buffer(size); got = C.c_size_t()
    assert h.K.ReadProcessMemory(handle, address, buf, size, C.byref(got)) and got.value == size, hex(address)
    return buf.raw
def check_instruction(rva, expected_hex=None, target=None):
    ins = next(md.disasm(debugger.read(base+rva, 16), base+rva))
    if expected_hex: assert ins.bytes.hex() == expected_hex, (hex(rva), ins.bytes.hex())
    if target is not None:
        refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
                if op.type == capstone.CS_OP_MEM and op.mem.base == capstone.x86_const.X86_REG_RIP]
        assert refs == [base+target], (hex(rva), refs, hex(target))
    return ins
def write_checked(address, content, label):
    before = debugger.read(address, len(content)); debugger.write(address, content)
    assert debugger.read(address, len(content)) == content, label
    return {'label': label, 'bytes': len(content), 'beforeSha256': hashlib.sha256(before).hexdigest(),
            'afterSha256': hashlib.sha256(content).hexdigest()}
def go_to(rva):
    address = base+rva; debugger.breakpoint(address)
    packet = debugger.ask('c'); regs = debugger.regs(); debugger.breakpoint(address, remove=True)
    if regs['rip'] not in (address, address+1):
        report['unexpectedStop'] = {'expectedRva': hex(rva), 'actualRva': hex(regs['rip']-base), 'packet': packet,
            'code': [i.mnemonic+' '+i.op_str for i in md.disasm(debugger.read(regs['rip'],48),regs['rip'])]}
        raise RuntimeError('Unexpected stop before '+hex(rva))
    debugger.setreg('rip', address); regs['rip'] = address
    report['events'].append({'nativeRva': hex(rva)}); return regs
def command(text):
    proc.stdin.write((text+'\n').encode()); proc.stdin.flush()
stop_queue=queue.Queue()
def receive_running_stop():
    try:stop_queue.put({'packet':debugger.receive()})
    except Exception as exc:stop_queue.put({'receiveError':str(exc)})
def wait_text(pattern, offset, timeout=35):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        text = bytes(stdout[offset:]).decode(errors='replace'); match = re.search(pattern,text,re.MULTILINE)
        if match: return text, match
        if not stop_queue.empty():
            event=stop_queue.get_nowait();report['runningStop']=event
            if 'packet' in event and event['packet'].startswith('T'):
                rr=debugger.regs();event['rva']=hex(rr['rip']-base)
                event['code']=[{'rva':hex(i.address-base),'asm':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()} for i in md.disasm(debugger.read(rr['rip'],48),rr['rip'])]
                event['module']=next((m['name'] for m in modules if m['base']<=rr['rip']<m['base']+m['size']),None)
                (out/'running-stop-registers.json').write_text(json.dumps(rr,indent=2),encoding='utf-8')
            raise RuntimeError('SDE stopped while awaiting '+pattern)
        if proc.poll() is not None: raise RuntimeError('Process ended while waiting for '+pattern)
        time.sleep(.1)
    raise TimeoutError('Output timeout: '+pattern)
def owner_watch():
    from ctypes import wintypes as W
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];kernel.OpenProcess.restype=W.HANDLE
    kernel.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];kernel.CloseHandle.argtypes=[W.HANDLE]
    owner=kernel.OpenProcess(0x100000,False,owner_pid)
    try:
        while owner and kernel.WaitForSingleObject(owner,1000)==258 and marker.exists():pass
        (out/'stop.flag').write_text('controller ended',encoding='utf-8')
        time.sleep(18)
        if proc and proc.poll() is None:subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    finally:
        if owner:kernel.CloseHandle(owner)
threading.Thread(target=owner_watch,daemon=True).start()
try:
    stage('launch')
    proc = subprocess.Popen([str(sde), '-spr', '-debug', '--', str(launch_engine)], cwd=launch_engine.parent,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    for stream, buffer in ((proc.stdout,stdout),(proc.stderr,stderr)):
        w=threading.Thread(target=consume,args=(stream,buffer),daemon=True);w.start();workers.append(w)
    _, match=wait_text(r'port\s+(\d+)',0)
    debugger=rspmod.Rsp(int(match.group(1)));debugger.socket.settimeout(55);report['initialStop']=debugger.ask('?')
    pid=None
    for attempt in range(100):
        matches=[]
        for candidate in h.processes():
            if candidate['name'].casefold()!=engine.name.casefold():continue
            candidate_path=h.process_path(candidate['pid'])
            if candidate_path and os.path.samefile(candidate_path,engine):matches.append(candidate['pid'])
        if len(matches)==1:pid=matches[0];break
        if len(matches)>1:raise RuntimeError('Multiple copies of this exact MAX path are running')
        time.sleep(.1)
    assert pid,'MAX process not found';report['pid']=pid
    modules=h.modules(pid);base=next(m['base'] for m in modules if m['name'].lower()==engine.name.lower())
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    apis={}
    for dll,names in {'ws2_32.dll':['gethostbyname','connect','send','recv'],'ntdll.dll':['RtlExitUserProcess']}.items():
        m=next(m for m in modules if m['name'].lower()==dll);pe=pefile.PE(m['path'])
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name and symbol.name.decode() in names and not symbol.forwarder:apis[symbol.name.decode()]=m['base']+symbol.address
    assert len(apis)==5
    for address in apis.values():debugger.breakpoint(address)
    h.K.VirtualAllocEx.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t,C.c_uint,C.c_uint];h.K.VirtualAllocEx.restype=C.c_void_p
    handle=h.K.OpenProcess(0x1fffff,False,pid);assert handle
    dns=h.K.VirtualAllocEx(handle,None,4096,0x3000,4);assert dns
    blob=bytearray(128);struct.pack_into('<QQhh4xQ',blob,0,dns+80,dns+48,2,4,dns+56)
    struct.pack_into('<Q',blob,56,dns+72);blob[72:76]=bytes((127,0,0,1));blob[80:90]=b'localhost\0';debugger.write(dns,blob)
    debugger.send('c')
    startup_reader=threading.Thread(target=receive_running_stop,daemon=True);startup_reader.start()
    startup_deadline=time.monotonic()+55;report['startupSerialSupplied']=False
    while time.monotonic()<startup_deadline:
        if b'input serial number' in bytes(stdout).lower() and not report['startupSerialSupplied']:
            command('111111111222222222333');report['startupSerialSupplied']=True
        if not stop_queue.empty():
            startup_event=stop_queue.get_nowait();assert 'packet' in startup_event,startup_event
            initial_packet=startup_event['packet'];break
        if proc.poll() is not None:raise RuntimeError('SDE exited during startup')
        time.sleep(.1)
    else:raise TimeoutError('No startup API stop or serial response')
    response=None;stage('response-boundary')
    for event in range(160):
        if event:debugger.send('c')
        packet=initial_packet if event==0 else debugger.receive();regs=debugger.regs();ip=regs['rip']
        name=next((n for n,a in apis.items() if ip in (a,a+1)),None)
        if name=='RtlExitUserProcess':raise RuntimeError('Early exit '+str(regs['rcx']))
        if name in ('gethostbyname','connect','send','recv'):
            ret=int.from_bytes(debugger.read(regs['rsp'],8),'little')
            value=dns if name=='gethostbyname' else (0 if name=='connect' else regs['r8']&0xffffffff)
            report['events'].append({'api':name,'capacity':regs['r8']&0xffffffff})
            if name=='recv':
                assert value==1040;response=regs['rdx'];debugger.write(response,bytes(1040))
                watch=debugger.monitor(f'break if load from {response+16:#x}')
                watch_match=re.search(r'Breakpoint #(\d+)',watch['output']);assert watch_match,watch
            debugger.setreg('rax',value);debugger.setreg('rsp',regs['rsp']+8);debugger.setreg('rip',ret)
            continue
        assert response is not None,hex(ip-base)
        if ip!=base+0xf57560:
            report['events'].append({'responseReader':hex(ip-base)});continue
        debugger.monitor('delete breakpoint '+watch_match.group(1))
        check_instruction(0xf57560,'36448b842901ffffff')
        assert (regs['rcx']+regs['rbp']-255)&((1<<64)-1)==response+16
        replay=bytes.fromhex('000000000000000000000000000000003bc47a8f7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a7751d7bc75d7258b8243ae7054d3e94a775')
        assert len(replay)==1040 and replay[16:20]==bytes.fromhex('3bc47a8f')
        report['responseReplay']=write_checked(response,replay,'first-field-before-load')
        break
    else:raise RuntimeError('Response event limit')
    stage('common-header')
    regs=go_to(0xa8840);check_instruction(0xa8840,'c5fa6f01');check_instruction(0xa8844,target=0x10c600)
    expected=debugger.read(base+0x10c600,16);assert expected==bytes.fromhex('7cc870a1c2870f153a7a830300000000')
    report['headerRepair']=write_checked(regs['rcx'],expected,'verified-common-header')
    regs=go_to(0xa8854);assert regs['rax']&255==0;report['headerEqual']=True
    go_to(0x90060);stage('native-initializer');go_to(0x9036e)
    check_instruction(0x9036e,'62f27d485a05e8ca5900',0x62ce60)
    repairs=[write_checked(base+0x62ce60,bytes(16),'zero-vector')]
    lower=(1<<45)-1
    king={y*9+x for y in (0,1,2,7,8,9) for x in (3,4,5)}
    elephant_lower=[(2,0),(6,0),(0,2),(4,2),(8,2),(2,4),(6,4)]
    advisor_lower=[(3,0),(5,0),(4,1),(3,2),(5,2)]
    elephant={y*9+x for x,y in elephant_lower}|{(9-y)*9+x for x,y in elephant_lower}
    advisor={y*9+x for x,y in advisor_lower}|{(9-y)*9+x for x,y in advisor_lower}
    pawns=[(x,y) for y in (3,4) for x in (0,2,4,6,8)]+[(x,y) for y in range(5,10) for x in range(9)]
    geometry=[(0x9082c,0x62ce00,'lower-half',lower),(0xb4860,0x62ce10,'upper-half',lower<<45),
        (0x92128,0x62ce20,'palaces',sum(1<<sq for sq in king)),
        (0xb666b,0x62ce30,'pawn-lower',sum(1<<(y*9+x) for x,y in pawns)),
        (0xb0fdb,0x62fb78,'elephant-mask',sum(1<<sq for sq in elephant)),
        (0xb1149,0x630340,'advisor-mask',sum(1<<sq for sq in advisor))]
    for site,target,label,value in geometry:
        check_instruction(site,target=target);row=write_checked(base+target,value.to_bytes(16,'little'),label)
        row.update(siteRva=hex(site),targetRva=hex(target),setBits=value.bit_count());repairs.append(row)
    # The pawn consumer indexes the verified pair with side*16.
    repairs.append(write_checked(base+0x62ce40,sum(1<<((9-y)*9+x) for x,y in pawns).to_bytes(16,'little'),'pawn-upper'))
    for site,slot,label,allowed in [(0xb66c4,0x137278,'king-membership',king),(0xb66b0,0x13e4c0,'elephant-membership',elephant),(0xb669c,0x1f3510,'advisor-membership',advisor)]:
        check_instruction(site,target=slot);pointer=int.from_bytes(debugger.read(base+slot,8),'little');assert pointer
        row=write_checked(pointer,bytes(0 if sq in allowed else 255 for sq in range(90)),label)
        row.update(siteRva=hex(site),slotRva=hex(slot),allowedCount=len(allowed));repairs.append(row)
    check_instruction(0x92e79,target=0x1fdd50);pointer=int.from_bytes(debugger.read(base+0x1fdd50,8),'little');assert pointer
    content=bytearray(debugger.read(pointer,41))
    for difference,offset in {-19:-9,-17:-9,-11:-1,-7:1,7:-1,11:1,17:9,19:9}.items():content[20+difference]=offset&255
    repairs.append(write_checked(pointer,bytes(content),'horse-leg-offsets'))
    check_instruction(0xdb286,target=0x137280);pointer=int.from_bytes(debugger.read(base+0x137280,8),'little');assert pointer
    repairs.append(write_checked(pointer,struct.pack('<I',os.cpu_count() or 1),'thread-limit'))
    report['nativeRepairs']=repairs;stage('native-repaired')
    go_to(0xdf250);stage('protocol-entry')
    report['featureTables']={}
    for label,at,size,limit in [('base',0x1f29d0,2880,689),('threats',0x238600,4147200,50620)]:
        content=read_local(base+at,size);values=struct.unpack('<'+'H'*(size//2),content)
        row={'rva':hex(at),'bytes':size,'sha256':hashlib.sha256(content).hexdigest(),'maximum':max(values),'outOfRange':sum(v>=limit for v in values)}
        expected={'base':'0c172b70b4a41300db8c752868f0a38cb1c9839b201edd24e9f5829cf8cc71f2','threats':'4cc1e843e63f5ce7d003d28af1c743660fe964215ef53da7e06c63a418b1cbc8'}
        row['matchesCOM']=row['sha256']==expected[label]
        report['featureTables'][label]=row
    assert all(row['outOfRange']==0 for row in report['featureTables'].values()),'Feature index out of range'
    assert all(row.get('matchesCOM',True) for row in report['featureTables'].values()),'Feature table differs from COM'
    report['continueAllThreads']=debugger.ask('Hc-1')
    assert report['continueAllThreads']=='OK','SDE did not accept all-thread continuation'
    offset=len(stdout);command('uci');debugger.send('c');stage('uci')
    debugger.socket.settimeout(None)
    running_reader=threading.Thread(target=receive_running_stop,daemon=True);running_reader.start()
    wait_text(r'^uciok\s*$',offset);report['uciok']=True
    offset=len(stdout);command('isready');stage('default-ready');wait_text(r'^readyok\s*$',offset,100);report['defaultReady']=True
    command('setoption name Threads value 1');command('setoption name Hash value 32')
    offset=len(stdout);command('isready');stage('configured-ready');wait_text(r'^readyok\s*$',offset,40);report['readyok']=True;report['protocolAccepted']=True
    report['scope']='Interactive MAX SDE chess-strength test; original engine and model preserved'
    uci_lines=[line for line in bytes(stdout).decode(errors='replace').splitlines() if line.startswith(('id ','option ')) or line=='uciok']
    assert uci_lines and uci_lines[-1]=='uciok'
    (out/'uci-cache.txt').write_text('\n'.join(uci_lines)+'\n',encoding='utf-8')
    pipebroker.serve(command,wait_text,stdout,proc,stop_queue,report,save,out/'stop.flag')
    command('quit');terminal_event=stop_queue.get(timeout=55);packet=terminal_event['packet'];regs=debugger.regs()
    if regs['rip'] in (apis['RtlExitUserProcess'],apis['RtlExitUserProcess']+1):
        report['exitCode']=regs['rcx'];debugger.breakpoint(apis['RtlExitUserProcess'],remove=True)
        debugger.setreg('rip',apis['RtlExitUserProcess']);assert debugger.ask('Hc-1')=='OK'
        report['terminalPacket']=debugger.ask('c');assert report['terminalPacket'].startswith('W00'),report['terminalPacket']
        proc.wait(timeout=10)
        assert report['exitCode']==0
        report['passed']=True;report['status']='service-stopped-cleanly'
except Exception:
    report.update(status='error',passed=False,error=traceback.format_exc())
finally:
    pipebroker.close()
    if debugger:
        debugger.close()
    if handle:h.K.CloseHandle(handle)
    if proc and proc.poll() is None:
        subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
        proc.wait(timeout=5)
    for w in workers:w.join(timeout=1)
    report.update(stdout=stdout.decode(errors='replace')[-16000:],stderr=stderr.decode(errors='replace')[-4000:])
    save()
