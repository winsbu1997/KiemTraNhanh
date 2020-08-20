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


extract_Path = '/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract'
active_File = os.path.join(os.getcwd(),"Test.pcap")
extractZip_Path = '/home/duong/Desktop/Do-An/Http2'
if(os.path.exists(extract_Path) == False):
    os.mkdir(extract_Path)

uri = "http://localhost:8123/upload-multifile"

def SendMultiFile(file_list):
    files = []
    for file in file_list:
        files.append(('files', open(file, 'rb')))
    try:
        r = requests.post(uri, files=files)
        data = r.json()
        print(data)
    except:
        print('client error')

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
    fullPath = os.path.join(path,dualIp)
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

  

    realNamePath = ""
    subStr = ""
    count = 1
    tt = 1
    http_Rev = ""
    if(len(dualIp) > 43):
        http_Rev = ip_Source + '.' + port_Source + '-' + ip_Destination + '.' + port_Destination            
        subStr = "GET"     
        tt = int(ip[3][0:3])
        #print(ip[3][0:3])
    else:
        subStr = "RETR"
        port_Source = str(int(port_Source) - 1)
        add0 = 5 - len(port_Source)
        for x in range(add0):
            port_Source = '0' + port_Source
                                
        http_Rev = ip_Source + '.' + str(port_Source) + '-' + ip_Destination + '.' + "00021"

    full_FindPath = os.path.join(path,http_Rev)
    with open(full_FindPath, "r") as ins:
        for line in ins:
            if(line.find(subStr) != -1):
                line = line.strip()
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
    return realNamePath

def Static_Analyst(fullPath):
    scan = "./BinarySearch " + fullPath
    out = subprocess.check_output(scan, shell = True)
    if(out != b''):
        print(out)
        Update_Virus(fullPath)
        return ''
    return fullPath
          
def Dynamic_Analyst(listFile, path):
    SendMultiFile(listFile)
    #shutil.rmtree(path, ignore_errors=True)

def Capture_Pcap():
    while(1):
        subprocess.check_output("tshark -i wlp2s0 -w Test.pcap -a duration:60", shell = True)
        path = str(datetime.datetime.now().strftime('%d-%m-%Y-%H-%M'))
        path = os.path.join(extract_Path,path)
        os.mkdir(path)
        Handle_Pcap(path)         
        os.remove(active_File)


def Handle_Pcap(path):
    files_SendResquest = []
    
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
        if((mime_Type != 'text/plain') and (mime_Type != 'application/octet-stream')  
            and (mime_Type != 'text/xml') and (mime_Type != 'image/png') 
            and (mime_Type != 'text/html') and (mime_Type != 'text/css')
            and (mime_Type != 'text/x-asm')
        ):     
            check = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", list[index])
            if(check):
                fullPath = Parse_FileName(list[index], path)    
            file = Static_Analyst(fullPath)
            if(file != ''):
                files_SendResquest.append(file) 
            if(mime_Type == 'application/zip'):
                extract_files = Extract_Zip(fullPath)
                files_SendResquest.extend(extract_files)
    print(files_SendResquest)
    #t1 = threading.Thread(target=Dynamic_Analyst, args=(files_SendResquest,path,))
    #t1.start()

if __name__ == "__main__":
    #path = "/home/duong/Desktop/Do-An/Http/"
    # parser = ArgumentParser("Testing")
    # parser.add_argument('-r', dest='file', required="false", default= "kaka")
    # args = parser.parse_args()
    # inputfile = args.file   
    #Handle_Pcap(path)
    
    Capture_Pcap()


    