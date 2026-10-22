"""Run only in the isolated Windows guest. Keep sample analysis and dumps there."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib, json, os, re, struct, subprocess, threading, time, traceback, zipfile
import pefile

ROOT = Path(os.environ.get('CYCLONE_RUNTIME_ROOT',r'C:\Lab\CycloneUltimate'))
PACKAGE = ROOT / 'original'
OUT = ROOT / 'evidence'
OUT.mkdir(exist_ok=True)
STATUS = {'stage': 'starting', 'samplesExecuted': [], 'memoryPatched': False}

def save(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')

def stage(name):
    STATUS['stage'] = name
    save('status.json', STATUS)
    (ROOT / 'PROGRESS.txt').write_text('Cyclone ultimate analysis\nStage: '+name+'\nAll sample operations run in this guest.\n', encoding='utf-8')

K = C.WinDLL('kernel32', use_last_error=True)
U = C.WinDLL('user32', use_last_error=True)
K.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]; K.OpenProcess.restype = W.HANDLE
K.CloseHandle.argtypes = [W.HANDLE]; K.CloseHandle.restype = W.BOOL
K.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]; K.ReadProcessMemory.restype = W.BOOL

class MODULE(C.Structure):
    _fields_ = [('size', W.DWORD), ('moduleid', W.DWORD), ('pid', W.DWORD), ('globalUse', W.DWORD), ('processUse', W.DWORD), ('base', C.c_void_p), ('imageSize', W.DWORD), ('module', W.HMODULE), ('name', W.WCHAR*256), ('path', W.WCHAR*260)]

class MBI(C.Structure):
    _fields_ = [('base', C.c_void_p), ('allocationBase', C.c_void_p), ('allocationProtect', W.DWORD), ('regionSize', C.c_size_t), ('state', W.DWORD), ('protect', W.DWORD), ('kind', W.DWORD)]

K.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]; K.CreateToolhelp32Snapshot.restype = W.HANDLE
K.Module32FirstW.argtypes = [W.HANDLE, C.POINTER(MODULE)]; K.Module32FirstW.restype = W.BOOL
K.Module32NextW.argtypes = [W.HANDLE, C.POINTER(MODULE)]; K.Module32NextW.restype = W.BOOL
K.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MBI), C.c_size_t]; K.VirtualQueryEx.restype = C.c_size_t

def modules(pid):
    handle = K.CreateToolhelp32Snapshot(0x18, pid)
    if handle == C.c_void_p(-1).value: raise C.WinError(C.get_last_error())
    result = []
    try:
        item = MODULE(); item.size = C.sizeof(item)
        ok = K.Module32FirstW(handle, C.byref(item))
        while ok:
            result.append({'name': item.name, 'base': item.base, 'size': item.imageSize, 'path': item.path})
            ok = K.Module32NextW(handle, C.byref(item))
    finally: K.CloseHandle(handle)
    return result

CALLBACK = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
U.EnumWindows.argtypes = [CALLBACK, W.LPARAM]
U.EnumChildWindows.argtypes = [W.HWND, CALLBACK, W.LPARAM]
U.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
U.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, C.c_int]

def windows(pid):
    texts = []
    @CALLBACK
    def child(hwnd, _):
        s = C.create_unicode_buffer(2048); U.GetWindowTextW(hwnd, s, len(s))
        if s.value: texts.append(s.value)
        return True
    @CALLBACK
    def top(hwnd, _):
        owner = W.DWORD(); U.GetWindowThreadProcessId(hwnd, C.byref(owner))
        if owner.value == pid:
            child(hwnd, 0); U.EnumChildWindows(hwnd, child, 0)
        return True
    U.EnumWindows(top, 0)
    return texts

KEYWORDS = re.compile(r'input serial|serial number|Activation|user\.lic|sn\.txt|cyclone-nn |maximum threads|update service|expired|authorization|VMProtect|Themida|WinLicense|https?://', re.I)

def relevant_strings(data):
    rows = []
    for encoding, pattern in [('ascii', rb'[\x20-\x7e]{6,}'), ('utf-16le', rb'(?:[\x20-\x7e]\x00){6,}')]:
        for match in re.finditer(pattern, data):
            text = match.group().decode(encoding)
            if KEYWORDS.search(text): rows.append({'offset': match.start(), 'encoding': encoding, 'text': text})
    return rows

def memory_capture(pid, engine):
    module_list = modules(pid)
    main = next(m for m in module_list if m['name'].lower() == engine.lower())
    handle = K.OpenProcess(0x410, False, pid)
    if not handle: raise C.WinError(C.get_last_error())
    image = bytearray(main['size']); regions = []; errors = []
    cursor = main['base']; end = cursor + main['size']
    try:
        while cursor < end:
            info = MBI()
            if not K.VirtualQueryEx(handle, cursor, C.byref(info), C.sizeof(info)): raise C.WinError(C.get_last_error())
            limit = min(end, info.base + info.regionSize)
            if limit <= cursor: raise ValueError('Non-advancing region')
            readable = info.state == 0x1000 and not info.protect & 0x101
            regions.append({'rva': cursor-main['base'], 'size': limit-cursor, 'state': info.state, 'protect': info.protect, 'readable': readable})
            if readable:
                while cursor < limit:
                    size = min(0x1000, limit-cursor); buf = C.create_string_buffer(size); read = C.c_size_t()
                    ok = K.ReadProcessMemory(handle, cursor, buf, size, C.byref(read))
                    offset = cursor-main['base']; image[offset:offset+read.value] = buf.raw[:read.value]
                    if not ok or read.value != size: errors.append({'rva': offset, 'expected': size, 'read': read.value, 'error': C.get_last_error()})
                    cursor += size
            else: cursor = limit
    finally: K.CloseHandle(handle)
    dump = OUT / (engine+'.memory.bin'); dump.write_bytes(image)
    hits = relevant_strings(image)
    refs = []; targets = {h['offset']: h['text'] for h in hits}
    for match in re.finditer(rb'[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', image):
        at = match.start()
        if at+7 <= len(image):
            target = at+7+struct.unpack_from('<i', image, at+3)[0]
            if target in targets: refs.append({'instructionRva': at, 'stringRva': target, 'text': targets[target]})
    report = {'engine': engine, 'pid': pid, 'base': hex(main['base']), 'size': len(image), 'sha256': hashlib.sha256(image).hexdigest(), 'regions': regions, 'readErrors': errors, 'modules': module_list, 'strings': hits, 'candidateRipReferences': refs}
    save(engine+'.memory.json', report)
    return {k: report[k] for k in ('base', 'size', 'sha256', 'readErrors', 'strings')}

def run_engine(path, capture=False):
    result = {'engine': path.name, 'commands': [], 'termination': None}
    stdout = bytearray(); stderr = bytearray()
    def consume(stream, target):
        while True:
            data = stream.read1(4096)
            if not data: break
            target.extend(data)
    proc = subprocess.Popen([str(path)], cwd=PACKAGE, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    STATUS['samplesExecuted'].append(path.name); stage('running '+path.name)
    readers = [threading.Thread(target=consume, args=(proc.stdout, stdout), daemon=True), threading.Thread(target=consume, args=(proc.stderr, stderr), daemon=True)]
    for t in readers: t.start()
    started = time.monotonic()
    try:
        for _ in range(100):
            if proc.poll() is not None or b'input serial number' in stdout.lower(): break
            time.sleep(.1)
        if b'input serial number' in stdout.lower():
            result['stage'] = 'serial-number-prompt'; result['windows'] = windows(proc.pid)
            if capture:
                stage('capturing memory '+path.name)
                result['memory'] = memory_capture(proc.pid, path.name)
        elif proc.poll() is None:
            proc.stdin.write(b'uci\n'); proc.stdin.flush(); result['commands'].append('uci')
            for _ in range(100):
                if proc.poll() is not None or b'uciok' in stdout or b'input serial number' in stdout.lower(): break
                time.sleep(.1)
            result['stage'] = 'uci-ready' if b'uciok' in stdout else 'no-uci-handshake'
            result['windows'] = windows(proc.pid)
        else: result['stage'] = 'early-exit'
        result['naturalExit'] = proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.terminate(); result['termination'] = 'probe-terminated'
        proc.wait(timeout=5)
        for t in readers: t.join(timeout=3)
        proc.stdin.close(); proc.stdout.close(); proc.stderr.close()
    result['exitCode'] = proc.returncode
    result['durationSeconds'] = round(time.monotonic()-started, 3)
    (OUT/(path.name+'.stdout.bin')).write_bytes(stdout)
    (OUT/(path.name+'.stderr.bin')).write_bytes(stderr)
    result['stdout'] = stdout.decode('utf-8', errors='replace')
    result['stderr'] = stderr.decode('utf-8', errors='replace')
    save(path.name+'.runtime.json', result)
    return result

def main():
    try:
        stage('validating archive CRCs')
        with zipfile.ZipFile(r'C:\Lab\cyclone-ultimate-folder-original.zip') as z:
            bad = z.testzip()
            if bad: raise ValueError('Archive CRC failure: '+bad)
        inventory = []; engines = []
        stage('guest static analysis')
        for p in sorted(PACKAGE.rglob('*')):
            if not p.is_file(): continue
            data = p.read_bytes(); entry = {'name': p.relative_to(PACKAGE).as_posix(), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            inventory.append(entry)
            if p.suffix.lower() == '.exe':
                pe = pefile.PE(data=data)
                report = {**entry, 'machine': hex(pe.FILE_HEADER.Machine), 'imageBase': hex(pe.OPTIONAL_HEADER.ImageBase), 'entryRva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 'imageSize': pe.OPTIONAL_HEADER.SizeOfImage, 'sections': [{'name': s.Name.rstrip(b'\0').decode(errors='replace'), 'rva': s.VirtualAddress, 'rawSize': s.SizeOfRawData, 'virtualSize': s.Misc_VirtualSize, 'entropy': round(s.get_entropy(),3)} for s in pe.sections], 'imports': {d.dll.decode(errors='replace'): [s.name.decode(errors='replace') if s.name else 'ordinal:'+str(s.ordinal) for s in d.imports] for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}, 'strings': relevant_strings(data)}
                save(p.name+'.static.json', report); engines.append(p)
        save('inventory.json', inventory)
        results = []
        for engine in engines:
            results.append(run_engine(engine, capture=engine.name=='cyclone-nn-com.exe'))
        save('summary.json', {'analysisLocation': 'isolated VMware guest', 'fileCount':len(inventory), 'engines':results, 'targetModified':False, 'crackVerified':False})
        stage('completed original-behavior inspection')
    except Exception as exc:
        STATUS['error'] = str(exc); STATUS['traceback'] = traceback.format_exc(); stage('error')

if __name__ == '__main__': main()
