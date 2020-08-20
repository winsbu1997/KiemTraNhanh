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
active_File = os.path.join(os.getcwd(), "Test.pcap")
extractZip_Path = '/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract_Zip'
if(os.path.exists(extract_Path) == False):
    os.mkdir(extract_Path)


class Task(object):
    def __init__(self, source_ip, destination_ip, destination_url, detected_by, malware_type, file_name, date_received, time_received, md5, protocol, file_size):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_url = destination_url
        self.detected_by = detected_by
        self.malware_type = malware_type
        self.file_name = file_name
        self.date_received = date_received
        self.time_received = time_received
        self.md5 = md5
        self.protocol = protocol
        self.file_size = file_size

    def obj_dict(self):
        return {'source_ip': self.source_ip, 'destination_ip': self.destination_ip, 'destination_url': self.destination_url, 'detected_by': self.detected_by,
                'malware_type': self.malware_type, 'file_name': self.file_name, 'date_received': self.date_received, 'time_received': self.time_received,
                'md5': self.md5, 'protocol': self.protocol, 'file_size': self.file_size}


uri = "http://192.168.126.26:5002/api/v1/capture/check"


def SendMultiFile(file_list, taskJson):
    for index in range(len(file_list)):
        req = {'files[]': open(file_list[index], 'rb')}

        print('taskJson[index]', taskJson[index])
        data = requests.post(uri, files=req, data=taskJson[index])
        r = data.json()
        print(r)


def dirwalk(dir, bag, wildcards):
    bag.extend(glob.glob(os.path.join(dir, wildcards)))
    for f in os.listdir(dir):
        fullpath = os.path.join(dir, f)
        if os.path.isdir(fullpath) and not os.path.islink(fullpath):
            dirwalk(fullpath, bag, wildcards)


def Extract_Zip(path, task):
    listFile = []
    dynamicFile = []
    taskFile = []
    fullPath = os.path.normpath(path)
    with zipfile.ZipFile(fullPath, 'r') as zip_ref:
        zip_ref.extractall(extractZip_Path)
    dirwalk(extractZip_Path, listFile, '*')
    # range(len(list)) = [f for f in listFile if os.path.isfile(f)]
    for index in listFile:
        if(os.path.isfile(index)):
            tmp = index.replace('(', '_')
            tmp = tmp.replace(')', '_')
            os.rename(index, tmp)
            file = Static_Analyst(tmp, task)
            if(file != ''):
                dynamicFile.append(tmp)
                taskFile.append(task)
    return dynamicFile, taskFile


def Parse_FileName(dualIp, path):
    task = Task('', '', '', '', '', '', '', '', '', '', '')
    fullPath = os.path.join(path, dualIp)
    if(os.path.isfile(fullPath) == False):
        return '', ''
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

    # if(port_Source == "443" or port_Destination == "443"):
    #     return "", ""
  
    task.source_ip = ip_Source
    task.destination_ip = ip_Destination

    realNamePath = ""
    subStr = ""
    count = 1
    tt = 1
    http_Rev = ""
    if(len(dualIp) > 43):
        http_Rev = ip_Source + '.' + port_Source + '-' + \
            ip_Destination + '.' + port_Destination + '--' + str(vlan)
        subStr = "GET"
        tt = 0
        try:
            tt = int(ip[-1][0:3])
        except:
            tt = -1
        # print(ip[3][0:3])
        if(tt == -1):
            return "", ""
    else:
        subStr = "RETR"
        port_Source = str(int(port_Source) - 1)
        add0 = 5 - len(port_Source)
        for x in range(add0):
            port_Source = '0' + port_Source

        http_Rev = ip_Source + '.' + \
            str(port_Source) + '-' + ip_Destination + \
            '.' + "00021" + '--' + str(vlan)

    full_FindPath = os.path.join(path, http_Rev)
    if(os.path.isfile(full_FindPath) == False):
        return '', ''
    try:
        with open(full_FindPath, "r") as ins:
            print('ins', ins)
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
                            task.protocol = "http"
                        else:
                            # Parse FTP
                            fileName = line.split('/')[-1]
                            task.protocol = "ftp"
                        realNamePath = os.path.join(path, fileName)
                        os.rename(fullPath, realNamePath)
                        break
                    else:
                        count = count + 1
    except:
        print("not read: " + full_FindPath)
        return '',''

        #print (ip_Source + ':' + port_Source + '\n' + ip_Destination + ':' + port_Destination)
    #task.destination_url = ''
    return realNamePath, task


def Static_Analyst(fullPath, taskJson):
    tmp = fullPath.replace('(', '_')
    tmp = tmp.replace(')', '_')
    os.rename(fullPath, tmp)
    fullPath = tmp

    scan = "./BinarySearch " + fullPath
    out = subprocess.check_output(scan, shell=True)
    out_str = out.decode("utf-8")
    if(out_str.split("/")[0] != ''):
        #print(out, out_str, out_str.split("/"), out.decode("utf-8"))
        taskJson.file_name = fullPath.split("/")[-1]
        taskJson.malware_type = out_str.split("/")[0]
        taskJson.detected_by = "static"
        file_Status = os.stat(fullPath)
        taskJson.file_size = file_Status.st_size
        taskJson.md5 = out_str.split("/")[1]
        taskJson.time_received = datetime.datetime.now().strftime('%H:%M:%S')
        taskJson.date_received = datetime.datetime.now().strftime('%Y-%m-%d')

        urlUpdate = "http://192.168.126.26:5002/api/v1/capture"
        #r = requests.post(urlUpdate, json=taskJson.obj_dict())
        #data = r.json()
        # print(data)
        return ''
    return fullPath


def Dynamic_Analyst(listFile, path, taskJson):
    SendMultiFile(listFile, taskJson)
    #shutil.rmtree(path, ignore_errors=True)
    # os.removedirs(path)


def Capture_Pcap():
    while(1):
        subprocess.check_output(
            "tshark -i enp2s0f2 -w Test.pcap -a duration:60", shell=True)

        path = str(datetime.datetime.now().strftime('%d-%m-%Y-%H-%M'))
        path = os.path.join(extract_Path, path)
        os.mkdir(path)
        Handle_Pcap(path)
        os.remove(active_File)


def Handle_Pcap(path):
    deny_MimiType = ['application/octet-stream', 'text/xml', 'text/html', 'image/png', 'image/jpg', 'text/css', 'text/x-asm', 'application/x-dosdriver',
                     'application/vnd.ms-cab-compressed', 'image/gif', 'application/x-chrome-extension', 'image/jpeg', 'application/font-sfnt']
    files_SendResquest = []
    task_SendRequest = []
    #active_File = os.path.join(os.getcwd(),"SMB2.pcap")
    # extract Http, Ftp
    query1 = "tcpflow -r " + active_File + " -o " + path + " -e http"
    subprocess.check_output(query1, shell=True)

    # extract SMB
    query2 = "tshark -nr " + active_File + " --export-objects smb," + path
    subprocess.check_output(query2, shell=True)
    list = os.listdir(path)
    mime = magic.Magic(mime=True)
    for index in range(len(list)):
        #fullPath = Parse_FileName(list[index], path)
        fullPath = os.path.join(path, list[index])
        mime_Type = mime.from_file(fullPath)
        if(mime_Type in deny_MimiType):
            os.remove(fullPath)
        else:
            if(mime_Type != 'text/plain'):
                #print(fullPath + "\n")
                ValidIpAddressRegex = r'''(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
                check = re.search(ValidIpAddressRegex, list[index])
                if(check):
                    fullPath, task = Parse_FileName(list[index], path)
                if(fullPath == ''):
                    continue
                file = Static_Analyst(fullPath, task)

                if(file != ''):
                    task = task.obj_dict()
                    task_SendRequest.append(task)
                    files_SendResquest.append(file)

            elif(mime_Type == 'application/zip'):
                try:
                    extract_Files, extract_Tasks = Extract_Zip(fullPath, task)
                    files_SendResquest.extend(extract_Files)
                    task_SendRequest.extend(extract_Tasks)
                except:
                    print('not Extract file zip')
    print(files_SendResquest)
    #t1 = threading.Thread(target=Dynamic_Analyst, args=(files_SendResquest, path, task_SendRequest))
    # t1.start()


if __name__ == "__main__":
    #path = "/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract/17-08-2020-14-02"
    # parser = ArgumentParser("Testing")
    # parser.add_argument('-r', dest='file', required="false", default= "kaka")
    # args = parser.parse_args()
    # inputfile = args.file
    # Handle_Pcap(path)
    # task = Task('192.168.1.18','192.168.147.85','http',1,'Xorer.eg','')
    # Static_Analyst('/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Virus.Win32.Xorer.eg', task)
    Capture_Pcap()
    # list = []
    # list.append("/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Virus.Win32.Xorer.eg")
    # SendMultiFile(list)
