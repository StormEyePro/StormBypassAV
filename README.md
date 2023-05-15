# 风暴免杀

工具介绍：https://blog.csdn.net/u013797594/article/details/130502682

适用于红队的免杀工具。

***

## 声明

***

1.本工具仅限于学习和技术研究，不可用于任何非法用途。



## 效果

***

> 建议修改CS默认特征增强免杀效果，下面的测试使用了malleable-c2项目中的CS配置文件来修改默认的CS特征。

1.使用进程镂空（傀儡进程）winlogon.exe，Defender仅提示病毒威胁选择重启，但不会主动杀掉镂空的winlogon.exe，实现稳定上线。

![image-20230501114236799](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230501114236799.png)

2.360鲲鹏引擎下无感知上线稳定运行



3.VT查杀率1/69

![image-20230501143816011](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230501143816011.png)



## 使用

***

1.工具使用了python3.7.9 开发，安装相关依赖包：

```
pip3 install -r requirements.txt
python3 StormBypassAV.py
```

2.支持普通和隐匿2种模式:

![image-20230504173245872](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230504173245872.png)

3.普通模式下使用了几种不同的内存申请/写入内存方式，通过将shellcode和shellcode加载器代码都进行加密实现了不错的免杀效果，并添加一些随机位移使得最终的木马比较难找到静态特征。

![image-20230504174832022](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230504174832022.png)

4.隐匿模式下实现了进程注入和进程镂空（傀儡进程）

- 进程注入将shellcode注入到指定进程中运行，木马程序本身被杀毒软件检测到后会被删除。

- 进程镂空通过运行指定程序并挂起，然后将已有的exe木马写入目标进程中运行，杀毒软件检测到的恶意进程是我们运行的目标程序。defender基于行为的监测技术能够发现被镂空的程序在执行恶意指令，因此会主动终止目标程序，但如果是winlogon.exe，它只会提示重启。



5.实现了本地和网络分离免杀，由于shellcode每次生成的不一样，所以配置菜单中增加了SSH服务器，配置后可以自动将新生产的payload同步到web服务器上



6.已知bug：

> 1.因为使用了动态导入，所以shellcode.py文件名中不能有多余的点号.  



# 2023.5.15更新

***

发现部分杀软已经能查杀，更新一波。

360鲲鹏，无感知上线和执行普通命令，新增用户等高危命令会告警，需要结合其它技术绕过。

![image-20230515122955343](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230515122955343.png)

![image-20230515122503214](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230515122503214.png)

defender：

使用进程镂空winlogon.exe，结合malleable-c2项目修改CS默认特征，可以无感知上线，执行shell命令会被defender告警病毒，但不主动查杀，只提示重启：

![image-20230515120833534](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230515120833534.png)

火绒：

发现火绒把变量名当成静态特征查杀。。。增加了一些随机特性绕过火绒的静态特征查杀，火绒已经会对进程镂空winlogon.exe进行查杀，但镂空其他进程不会查杀，遇到火绒可以直接使用普通模式的那几个shellcode加载器。

更新后无感知上线和执行命令，不过新增用户等高危操作依然不可用，需要结合其它技术。

![image-20230515122042417](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230515122042417.png)

VT：

VT上有些厂家已经把pyinstaller打包的程序都当成病毒了，所以很难做到更低的免杀率：

![image-20230515124901099](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230515124901099.png)