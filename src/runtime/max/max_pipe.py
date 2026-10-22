"""Single-client local named pipe. All protocol replies come from the real engine."""
import ctypes as C
from ctypes import wintypes as W
import os, queue, threading, time
from pathlib import Path

class Broker:
    def __init__(self):
        self.k = C.WinDLL('kernel32', use_last_error=True)
        for name, args, result in [
            ('CreateNamedPipeW', [W.LPCWSTR,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,W.DWORD,C.c_void_p], W.HANDLE),
            ('ConnectNamedPipe', [W.HANDLE,C.c_void_p], W.BOOL),
            ('DisconnectNamedPipe', [W.HANDLE], W.BOOL),
            ('ReadFile', [W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p], W.BOOL),
            ('WriteFile', [W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p], W.BOOL),
            ('OpenThread', [W.DWORD,W.BOOL,W.DWORD], W.HANDLE),
            ('CancelSynchronousIo', [W.HANDLE], W.BOOL),
            ('CloseHandle', [W.HANDLE], W.BOOL),
        ]:
            f=getattr(self.k,name);f.argtypes=args;f.restype=result
        self.h=None;self.output_handle=None;self.active=False;self.partial=b'';self.lock=threading.Lock()
        self.events=queue.Queue();self.search_done=threading.Event();self.search_done.set()
        self.report=None;self.save=None;self.client_count=0

    def on_data(self, part):
        # Only protocol lines are forwarded, never licensing/startup banners.
        self.partial += part
        while b'\n' in self.partial:
            line,self.partial=self.partial.split(b'\n',1)
            line=line.rstrip(b'\r')
            if line.startswith(b'bestmove '):self.search_done.set()
            if not (line in (b'uciok',b'readyok') or line.startswith((b'id ',b'option ',b'info ',b'bestmove '))):continue
            with self.lock:
                if not self.active:continue
                data=line+b'\n';written=W.DWORD();buf=C.create_string_buffer(data)
                ok=self.k.WriteFile(self.output_handle,buf,len(data),C.byref(written),None)
                if not ok or written.value!=len(data):
                    self.active=False
                    if self.report is not None:self.report['pipeWriteError']=C.get_last_error()
                elif self.report is not None:self.report['forwardedLines']=self.report.get('forwardedLines',0)+1

    def connect_worker(self):
        try:
            ok=self.k.ConnectNamedPipe(self.h,None)
            if not ok and C.get_last_error()!=535:raise C.WinError(C.get_last_error())
            ok=self.k.ConnectNamedPipe(self.output_handle,None)
            if not ok and C.get_last_error()!=535:raise C.WinError(C.get_last_error())
            self.events.put(('connected',None))
            pending=b''
            while True:
                b=C.create_string_buffer(4096);got=W.DWORD()
                if not self.k.ReadFile(self.h,b,len(b),C.byref(got),None) or not got.value:break
                pending+=b.raw[:got.value]
                if len(pending)>65536:raise RuntimeError('Protocol line exceeds 64 KiB')
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    self.events.put(('line',line.rstrip(b'\r').decode('utf-8',errors='replace')))
            self.events.put(('disconnected',None))
        except Exception as exc:self.events.put(('disconnected',str(exc)))

    def serve(self, command, wait_text, stdout, proc, stop_queue, report, save, stop_path):
        self.report=report;self.save=save
        deadline=time.monotonic()+12*3600
        report.update(servicePid=os.getpid(),maximumHours=12,readyTime=time.time(),status='ready-for-board')
        save()
        while time.monotonic()<deadline and not stop_path.exists():
            self.h=self.k.CreateNamedPipeW('\\\\.\\pipe\\'+os.environ['CYCLONE_MAX_PIPE']+'-in',1,0x08,1,65536,65536,0,None)
            if self.h==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
            self.output_handle=self.k.CreateNamedPipeW('\\\\.\\pipe\\'+os.environ['CYCLONE_MAX_PIPE']+'-out',2,0x08,1,65536,65536,0,None)
            if self.output_handle==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
            connected=False
            reader=threading.Thread(target=self.connect_worker,daemon=True);reader.start()
            while time.monotonic()<deadline and not stop_path.exists():
                if proc.poll() is not None:raise RuntimeError('MAX exited while waiting for the board')
                if not stop_queue.empty():raise RuntimeError('Unexpected SDE stop: '+str(stop_queue.get_nowait()))
                try:kind,value=self.events.get(timeout=.2)
                except queue.Empty:continue
                if kind=='connected':
                    with self.lock:self.active=True
                    connected=True;self.client_count+=1
                    report.update(status='board-connected',clients=self.client_count);save()
                elif kind=='line':
                    if value.strip()=='quit':break
                    if value.startswith('go '):self.search_done.clear()
                    report['lastCommand']=value[:512];report['lastCommandTime']=time.time()
                    command(value)
                    if value.startswith(('position ','go ','stop')):save()
                else:break
            with self.lock:self.active=False
            cancel=self.k.OpenThread(1,False,reader.native_id)
            if cancel:self.k.CancelSynchronousIo(cancel);self.k.CloseHandle(cancel)
            reader.join(timeout=2)
            self.k.DisconnectNamedPipe(self.h);self.k.CloseHandle(self.h);self.h=None
            self.k.DisconnectNamedPipe(self.output_handle);self.k.CloseHandle(self.output_handle);self.output_handle=None
            reader.join(timeout=2)
            if connected:
                command('stop')
                if not self.search_done.wait(35):raise TimeoutError('Search did not stop after board detached')
                offset=len(stdout);command('isready');wait_text(r'^readyok\s*$',offset,45)
                command('ucinewgame')
                report.update(status='ready-for-board',lastDisconnect=time.time());save()
            while not self.events.empty():self.events.get_nowait()
        report['status']='stopping';save()

    def close(self):
        with self.lock:self.active=False
        if self.h:
            self.k.DisconnectNamedPipe(self.h);self.k.CloseHandle(self.h);self.h=None
        if self.output_handle:
            self.k.DisconnectNamedPipe(self.output_handle);self.k.CloseHandle(self.output_handle);self.output_handle=None
