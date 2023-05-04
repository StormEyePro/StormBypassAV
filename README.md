# 风暴免杀

***

## 声明

***

1.工具仅限于学习和技术研究。



## 效果

***

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
```

2.支持普通和隐匿2种模式:

![image-20230504173245872](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230504173245872.png)

3.普通模式下使用了几种不同的内存申请/写入内存方式，通过将shellcode和shellcode加载器代码都进行加密实现了不错的免杀效果，并添加一些随机位移使得最终的木马比较难找到静态特征。

![image-20230504174832022](https://dybimages.oss-cn-chengdu.aliyuncs.com/image-20230504174832022.png)

4.隐匿模式下实现了进程注入和进程镂空（傀儡进程）

- 进程注入将shellcode注入到指定进程中运行，木马程序本身被杀毒软件检测到后会被删除。

- 进程镂空通过运行指定程序并挂起，然后将已有的exe木马写入目标进程中运行，杀毒软件检测到的恶意进程是我们运行的目标程序。defender基于行为的监测技术能够发现被镂空的程序在执行恶意指令，因此会主动终止目标程序，但如果是winlogon.exe，它只会提示重启。



5.实现了本地和网络分离免杀，由于shellcode每次生成的不一样，所以配置菜单中增加了SSH服务器，配置后可以自动将新生产的payload同步到web服务器上