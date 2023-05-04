import os
import configparser
import paramiko

def main(ip,port,username,password,local_path='../result/PayloadFile',remotepath='/var/www/html'):
    # SSH连接信息
    ssh_host = ip
    ssh_port = port
    ssh_user = username
    ssh_password = password

    # 本地文件路径和上传目标路径
    remotepath=getRemotePath(local_path,remotepath)

    # 创建SSH客户端对象
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 连接SSH服务器
    ssh.connect(ssh_host, ssh_port, ssh_user, ssh_password)

    # 创建SFTP客户端对象
    sftp = ssh.open_sftp()

    # 上传文件
    print(local_path)
    print(remotepath)
    sftp.put(local_path, remotepath)

    # 关闭SFTP客户端和SSH连接
    sftp.close()
    ssh.close()






def getRemotePath(local_path,remote_path):
    local_path = local_path
    filename=os.path.basename(local_path)
    remote_path=remote_path.rstrip('/')+'/'
    remote_path = remote_path+filename
    return remote_path



def readConfig():
    try:
        configFile=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+os.sep+'config'+os.sep+'config.ini'
        print(configFile)
        cf=configparser.ConfigParser()
        cf.read(configFile)
        host=cf.get('SSH','host')
        port=cf.get('SSH','port')
        username=cf.get('SSH','username')
        password=cf.get('SSH','password')
        remotepath=cf.get('SSH','remotepath')
        url=cf.get('SSH','url')
    except:
        return False

    return host,port,username,password,remotepath,url




def saveConfig(ip,port,username,password,remotepath='/var/www/html',url=''):
    configFile=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+os.sep+'config'+os.sep+'config.ini'
    try:
        cf=configparser.ConfigParser()
        cf['SSH']={
            'host':ip,
            'port':port,
            'username':username,
            'password':password,
            'remotepath':remotepath,
            'url':url.rstrip('/')+'/'
        }
        with open(configFile,'w') as f:
            cf.write(f)
        return False #这里成功和失败是反的
    except:
        import traceback
        return traceback.format_exc()

if __name__ == '__main__':
    main('100.100.100.2',22,'root','root',f"{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+os.sep+'result'+os.sep+'PayloadFile'}",'/var/www/html')
    # v=readConfig()
    # print(v)
    # saveConfig('100.100.100.2',22,'root','root',r"C:\Users\d\Desktop\hack\1.txt",'/var/www/html')

    # print(testConnect('100.100.100.2',22,'root','root'))
