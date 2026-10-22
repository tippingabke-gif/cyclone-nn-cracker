# Toolhelp helpers used only by the MAX service; no WMI or shell enumeration.
def processes():
    import ctypes as ct
    from ctypes import wintypes as wt
    class Entry(ct.Structure):
        _fields_=[('size',wt.DWORD),('usage',wt.DWORD),('pid',wt.DWORD),('heap',ct.c_size_t),('module',wt.DWORD),('threads',wt.DWORD),('parent',wt.DWORD),('priority',ct.c_long),('flags',wt.DWORD),('exe',wt.WCHAR*260)]
    kernel=ct.WinDLL('kernel32',use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes=[wt.DWORD,wt.DWORD];kernel.CreateToolhelp32Snapshot.restype=wt.HANDLE
    kernel.Process32FirstW.argtypes=[wt.HANDLE,ct.POINTER(Entry)];kernel.Process32NextW.argtypes=[wt.HANDLE,ct.POINTER(Entry)];kernel.CloseHandle.argtypes=[wt.HANDLE]
    snap=kernel.CreateToolhelp32Snapshot(2,0);result=[]
    if snap==ct.c_void_p(-1).value:raise ct.WinError(ct.get_last_error())
    try:
        entry=Entry();entry.size=ct.sizeof(entry);valid=kernel.Process32FirstW(snap,ct.byref(entry))
        while valid:
            result.append({'pid':entry.pid,'name':entry.exe});valid=kernel.Process32NextW(snap,ct.byref(entry))
    finally:kernel.CloseHandle(snap)
    return result

def process_path(pid):
    import ctypes as ct
    from ctypes import wintypes as wt
    kernel=ct.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wt.DWORD,wt.BOOL,wt.DWORD];kernel.OpenProcess.restype=wt.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=[wt.HANDLE,wt.DWORD,wt.LPWSTR,ct.POINTER(wt.DWORD)];kernel.CloseHandle.argtypes=[wt.HANDLE]
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle:return None
    try:
        size=wt.DWORD(32768);buf=ct.create_unicode_buffer(size.value)
        return buf.value if kernel.QueryFullProcessImageNameW(handle,0,buf,ct.byref(size)) else None
    finally:kernel.CloseHandle(handle)
