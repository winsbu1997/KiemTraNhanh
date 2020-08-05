from argparse import ArgumentParser
from sys import path
import magic
import os
import glob
import subprocess
import zipfile
import requests
import re
from threading import Thread
import threading
import time
import datetime
import shutil
import json


extract_Path = '/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract'
active_File = os.path.join(os.getcwd(),"Test.pcap")
extractZip_Path = '/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract_Zip'
if(os.path.exists(extract_Path) == False):
    os.mkdir(extract_Path)


class Task(object):
    def __init__(self, source_ip, destination_ip, destination_url):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_url = destination_url

    def obj_dict(self):
        return {'source_ip': self.source_ip, 'destination_ip': self.destination_ip, 'destination_url': self.destination_url}

uri = "http://192.168.126.26:5002/api/v1/capture/check"

def SendMultiFile(file_list, taskJson):
    files = []
    for index in range(len(file_list)):
        try:
            #files.append(('files[]', open(file, 'rb')))
 
            requests.post(uri, files=file_list[index], json= taskJson[index].obj)
            #data = r.json()
            #print(data)
        except:
            print("Error send file: " + file_list[index])

def SendFile(path):
    file = {'files': open(path,'rb')}
    r = requests.post(uri, files=file)
    print(r.json())

def dirwalk(dir, bag, wildcards):
    bag.extend(glob.glob(os.path.join(dir, wildcards)))
    for f in os.listdir(dir):
        fullpath = os.path.join(dir, f)
        if os.path.isdir(fullpath) and not os.path.islink(fullpath):
            dirwalk(fullpath, bag, wildcards)

def Extract_Zip(path):
    listFile = []
    dynamicFile = []
    fullPath = os.path.normpath(path)
    with zipfile.ZipFile(fullPath, 'r') as zip_ref:
        zip_ref.extractall(extractZip_Path)
    dirwalk(extractZip_Path, listFile, '*')
    #range(len(list)) = [f for f in listFile if os.path.isfile(f)]
    for index in listFile:
        if(os.path.isfile(index)):
            tmp = index.replace('(', '_')
            tmp = tmp.replace(')', '_')
            os.rename(index, tmp)
            file = Static_Analyst(tmp)
            if(file != ''):              
                dynamicFile.append(tmp)
    return dynamicFile

def Update_Virus(path):
    return 1

def Parse_FileName(dualIp, path):
    task = Task('','','')
    fullPath = os.path.join(path,dualIp)
    vlan = (int)(dualIp.split('--')[1][0:2])
    ip_Source = ''
    port_Source = ''
    port_Destination = ''
    ip_Destination = ''
    tt = 1
    realNamePath = fullPath
    ip = dualIp.split('-')
    ip_Source = ip[1][0:15]
    port_Source = ip[1][16:]
    ip_Destination = ip[0][0:15]
    port_Destination = ip[0][16:]
    # json
    task.source_ip = ip_Source
    task.destination_ip = ip_Destination

    realNamePath = ""
    subStr = ""
    count = 1
    tt = 1
    http_Rev = ""
    if(len(dualIp) > 43):
        http_Rev = ip_Source + '.' + port_Source + '-' + ip_Destination + '.' + port_Destination + '--' + str(vlan)   
        subStr = "GET"     
        tt = int(ip[-1][0:3])
        #print(ip[3][0:3])
    else:
        subStr = "RETR"
        port_Source = str(int(port_Source) - 1)
        add0 = 5 - len(port_Source)
        for x in range(add0):
            port_Source = '0' + port_Source
                                
        http_Rev = ip_Source + '.' + str(port_Source) + '-' + ip_Destination + '.' + "00021" + '--' + str(vlan)   

    full_FindPath = os.path.join(path,http_Rev)
    with open(full_FindPath, "r") as ins:
        for line in ins:
            line = line.strip()
            if(line.find("Host") != -1):
                task.destination_url = line.split(":")[1:]
            if(line.find(subStr) != -1):              
                if(tt == count):
                    fileName = ''
                    # Parse Http
                    if(subStr == 'GET'):
                        parseGet = line.split(' ')
                        fileName = parseGet[1].split('/')[-1]
                    else:
                    # Parse FTP
                        fileName = line.split('/')[-1]
                    realNamePath = os.path.join(path,fileName)
                    os.rename(fullPath, realNamePath)
                    break
                else:
                    count = count + 1

        #print (ip_Source + ':' + port_Source + '\n' + ip_Destination + ':' + port_Destination) 
    return realNamePath,task

def Static_Analyst(fullPath):
    tmp = fullPath.replace('(', '_')
    tmp = tmp.replace(')', '_')
    os.rename(fullPath, tmp)
    fullPath = tmp
    
    scan = "./BinarySearch " + fullPath
    out = subprocess.check_output(scan, shell = True)
    if(out != b''):
        print(out)
        Update_Virus(fullPath)
        return ''
    return fullPath
          
def Dynamic_Analyst(listFile, path, taskJson):
    SendMultiFile(listFile, taskJson)
    #shutil.rmtree(path, ignore_errors=True)
    #os.removedirs(path)

def Capture_Pcap():
    while(1):
        subprocess.check_output("tshark -i enp2s0f2 -w Test.pcap -a duration:60", shell = True)

        path = str(datetime.datetime.now().strftime('%d-%m-%Y-%H-%M'))
        path = os.path.join(extract_Path,path)
        os.mkdir(path)
        Handle_Pcap(path)         
        os.remove(active_File)


def Handle_Pcap(path):
    deny_MimiType = ['application/octet-stream','text/xml','text/html','image/png','image/jpg','text/css','text/x-asm','application/x-dosdriver','application/vnd.ms-cab-compressed','image/gif','application/x-chrome-extension','image/jpeg','application/font-sfnt']
    files_SendResquest = []
    task_SendRequest = []
    #active_File = os.path.join(os.getcwd(),"SMB2.pcap")
    # extract Http, Ftp
    query1 = "tcpflow -r " + active_File + " -o " + path + " -e http"
    subprocess.check_output(query1, shell = True)

    # extract SMB
    query2 = "tshark -nr " + active_File + " --export-objects smb," + path
    subprocess.check_output(query2, shell = True)
    list = os.listdir(path)
    mime = magic.Magic(mime=True)
    for index in range(len(list)):      
        #fullPath = Parse_FileName(list[index], path)
        fullPath = os.path.join(path,list[index])
        mime_Type = mime.from_file(fullPath)
        if(mime_Type in deny_MimiType):
            os.remove(fullPath)
        else:
            if(mime_Type != 'text/plain'):    
                #print(fullPath + "\n")
                check = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", list[index])
                if(check):
                    fullPath,task = Parse_FileName(list[index], path)    
                file = Static_Analyst(fullPath)
                task = task.obj_dict()
                task_SendRequest.append(task)
                if(file != ''):
                    files_SendResquest.append(file) 
                if(mime_Type == 'application/zip'):
                    try:
                        extract_files = Extract_Zip(fullPath)
                        files_SendResquest.extend(extract_files)
                    except:
                        print('not Extract file zip')
    print(files_SendResquest)
    t1 = threading.Thread(target=Dynamic_Analyst, args=(files_SendResquest,path,task_SendRequest))
    t1.start()

if __name__ == "__main__":
    #path = "/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract"
    # parser = ArgumentParser("Testing")
    # parser.add_argument('-r', dest='file', required="false", default= "kaka")
    # args = parser.parse_args()
    # inputfile = args.file   
    #Handle_Pcap(path)

    Capture_Pcap()
    # list = []
    # list.append("/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Virus.Win32.Xorer.eg")
    # SendMultiFile(list)


    