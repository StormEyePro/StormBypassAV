import json
import pefile
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


payloadSaveFile=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+os.sep+'temp'+os.sep+'PayloadFile'

def writePayload(PAYLOAD_EXE):
    pe_payload = pefile.PE(PAYLOAD_EXE)
    PE_TYPE=pe_payload.PE_TYPE
    ImageBase=pe_payload.OPTIONAL_HEADER.ImageBase
    SizeOfImage=pe_payload.OPTIONAL_HEADER.SizeOfImage
    SizeOfHeaders=pe_payload.OPTIONAL_HEADER.SizeOfHeaders
    AddressOfEntryPoint=pe_payload.OPTIONAL_HEADER.AddressOfEntryPoint
    get_field_absolute_offset=pe_payload.OPTIONAL_HEADER.get_field_absolute_offset("ImageBase")

    with open(PAYLOAD_EXE, "rb") as h_payload:
        payload_data = h_payload.read().decode('latin1')

    sections=[]
    for section in pe_payload.sections:
        dic_=dict()
        dic_['sectionName']=section.Name.decode("utf-8").strip("\x00")
        dic_['sectionVirtualAddress']=section.VirtualAddress
        dic_['sectionPointerToRawData']=section.PointerToRawData
        dic_['sectionSizeOfRawData']=section.SizeOfRawData
        sections.append(dic_)

    # print(sections)

    payload={'PE_TYPE':PE_TYPE,'ImageBase':ImageBase,'SizeOfImage':SizeOfImage,'SizeOfHeaders':SizeOfHeaders,'AddressOfEntryPoint':AddressOfEntryPoint,'get_field_absolute_offset':get_field_absolute_offset,'payload_data':payload_data,'sections':sections}
    with open(payloadSaveFile,'w') as f:
        json.dump(payload,f)

    return PE_TYPE,ImageBase,SizeOfImage,SizeOfHeaders,AddressOfEntryPoint,get_field_absolute_offset,payload_data,sections

def getPayload(payloadFile):

    writePayload(payloadFile)

    with open(payloadSaveFile,'r') as f:
        value=json.load(f)
    # print(value)
    return value
    # return value['PE_TYPE'],value['ImageBase'],value['SizeOfImage'],value['SizeOfHeaders'],value['AddressOfEntryPoint'],value['get_field_absolute_offset'],value['payload_data'].encode('latin1'),value['sections']



if __name__ == '__main__':
    PAYLOAD_EXE = r"D:\BaiduSyncdisk\dyb\a_penetration\kali_tools\my_project\project\BypassAV\掩月\config\artifact.exe"
    writePayload(PAYLOAD_EXE)       #将artifact.exe的内容提取出来，保存到payload文件中
    getPayload()