from Url_Request import Run_FindUrl
from sys import path
import magic
import os
import glob
import subprocess
from pyunpack import Archive
import requests
import re
from threading import Thread
import threading
from multiprocessing import Process, Pool, TimeoutError
import time
import datetime
import shutil
import json
import shlex
from configparser import ConfigParser
import logging
import asyncio

config_object = ConfigParser()
config_object.read("config.ini")
# Dinh danh thu muc de luu
folderConfig = config_object["FOLDERCONFIG"]
extract_Path = folderConfig["Http_Ftp"]
active_File = os.path.join(os.getcwd(), "Test.pcap")
extractZip_Path = folderConfig["Compressed"]
export_SMB2 = folderConfig["Smb2"]
log = folderConfig["Log"]

portFtp = "08084"
apiConfig = config_object["APICONFIG"]
url_CheckMalware = apiConfig["UrlCheck_Malware"]
url_AddItems = apiConfig["UrlPost"]
url_Check = apiConfig["UrlCheck"]

deny_MimiType = ['application/octet-stream', 'application/x-dosdriver', 'application/vnd.ms-cab-compressed', 'application/json', 
                'application/x-chrome-extension', 'application/font-sfnt', 'application/vnd.ms-opentype','application/vnd.ms-fontobject', 
                'application/x-xz', 'application/zlib','application/gzip', 'application/x-setupscript', 'application/x-tex-tfm', 
                'application/x-bzip2', 'application/CDFV2']

mime = magic.Magic(mime=True)

if(os.path.exists(extract_Path) == False):
    os.mkdir(extract_Path)
if(os.path.exists(extractZip_Path) == False):
    os.mkdir(extractZip_Path)
if(os.path.exists(export_SMB2) == False):
    os.mkdir(export_SMB2)
if(os.path.exists(log) == False):
    os.mkdir(log)


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

def Check_UnFile(mime_Type):
    list = ["text","audio","font","image","video"]
    mime_Type = mime_Type.split("/")[0]
    for index in list:
        if(mime_Type == index):
            return 1
    return 0
    
def dirwalk(dir, bag, wildcards):
    bag.extend(glob.glob(os.path.join(dir, wildcards)))
    for f in os.listdir(dir):
        fullpath = os.path.join(dir, f)
        if os.path.isdir(fullpath) and not os.path.islink(fullpath):
            dirwalk(fullpath, bag, wildcards)

def Extract_FileCompressed(path, task):
    listFile = []
    dynamicFile = []
    taskFile = []
    fullPath = os.path.normpath(path)
    Archive(fullPath).extractall(extractZip_Path)
    dirwalk(extractZip_Path, listFile, '*')
    # range(len(list)) = [f for f in listFile if os.path.isfile(f)]
    for index in listFile:
        if(os.path.isfile(index)):
            # name: filename to arg c++ not read
            tmp = index
            # if(tmp.find("(") != -1):
            #     tmp = tmp.replace('(', '_')
            # if(tmp.find(")") != -1):
            #     tmp = tmp.replace(')', '_')
            # os.rename(index, tmp)
            mime_Type = mime.from_file(tmp)
            
            check = Check_UnFile(mime_Type)

            if(mime_Type not in deny_MimiType and mime_Type != "application/zip"  and check == 0):
                file = Static_Analyst(tmp, task)
                if(file != ''):   
                    taskRequest = task.obj_dict()           
                    dynamicFile.append(tmp)
                    taskFile.append(taskRequest)
    return dynamicFile, taskFile

# Http, Ftp
def Parse_FileName(dualIp, path, markFtp):
    task = Task('', '', '', '', '', '', '', '', '', '', '')
    fullPath = os.path.join(path, dualIp)
    if(os.path.isfile(fullPath) == False):
        return '', ''
    realNamePath = fullPath
    vlan = ''
    try:
        vlan = '--' + dualIp.split('--')[1][0:2]
    except:
        #print("not vlan")
        key = 1
    
    ip = dualIp.split('-')
    ip_Source = ip[1][0:15]
    port_Source = ip[1][16:]
    ip_Destination = ip[0][0:15]
    port_Destination = ip[0][16:]

    tt = 1
    count = 1

    # if(port_Source == "443" or port_Destination == "443"):
    #     return "", "" + '--' + str(vlan)
  
    task.source_ip = ip_Source
    task.destination_ip = ip_Destination
    task.time_received = datetime.datetime.now().strftime('%H:%M:%S')
    task.date_received = datetime.datetime.now().strftime('%Y-%m-%d')

    fileName = ''
    if(len(dualIp) > 47):
        http_Rev = ip_Source + '.' + port_Source + '-' + ip_Destination + '.' + port_Destination + vlan
        try:
            #if(ip[-1][0:3].isnumeric):
            tt = int(ip[-1][0:3])

            full_FindPath = os.path.join(path, http_Rev)
            if(os.path.isfile(full_FindPath) == False):
                return '', ''

            markHost = 0
            with open(full_FindPath, "r") as ins:
                for line in ins:
                    line = line.strip()
                    if(line.find("Host") != -1):
                        task.destination_url = str(line.split(" ")[1])
                        if(markHost == 1):
                            break
                        #print(task.destination_url)
                    if(line.find("GET") != -1):
                        if(tt == count):
                            # Parse http
                            parseGet = line.split(' ')
                            fileName = parseGet[1].split('/')[-1]
                            task.protocol = "http"
                            markHost = 1                          
                        else:
                            count = count + 1
        except:
            return '', ''

    else: 
        flag = 1
        find_Ftp = ip_Destination + "." + portFtp + '-' +  ip_Source 
        for f in markFtp:
            # port begin index: 15, 37
            if(f.find(find_Ftp) != -1):
                try:
                    f = f.split('--')[0]
                    port_ClientTranfer = f.split('.')[-1]
                    fullpath_FtpServer = os.path.join(path, f) + vlan
                    with open(fullpath_FtpServer, "r") as ins:
                        for line in ins:
                            line = line.strip()
                            if(line.find("227") != -1):
                                # port = p1*256 + p2
                                p = line.split(',')
                                p1= int(p[-2]) * 256
                                p2 = p[-1].replace(').','')
                                port_Control = p1 + int(p2) 
                                if(port_Control == int(port_Destination)):
                                    ftp_Rev = ip_Source + '.' + port_ClientTranfer + '-' + ip_Destination + '.' + portFtp + vlan
                                    full_FindPath = os.path.join(path, ftp_Rev)
                                    with open(full_FindPath, "r") as ins1:
                                        for index in ins1:
                                            index = index.strip()
                                            if(index.find("RETR") != -1):
                                                fileName = index.split('/')[-1]
                                                task.protocol = "ftp"
                                                flag = 0
                                                break

                                if(flag == 0):
                                    break
                    if(flag == 0):
                        break

                except:
                    continue

        if(flag == 1):
            return "",""

        #print (ip_Source + ':' + port_Source + '\n' + ip_Destination + ':' + port_Destination)
    #task.destination_url = ''
    if fileName:
        realNamePath = os.path.join(path, fileName.split('?')[0].split('=')[0])
        os.rename(fullPath, realNamePath)
        return realNamePath, task
    return None, None

# SMB
def Export_SMB2():
    files_SendResquest = [] 
    task_SendRequest = []
    tmp = []
    # active_File
    query2 = "tshark -nr " + active_File + " --export-objects smb," + export_SMB2 + " -Y 'smb2.flags.response == 1 && smb2.cmd == 5'"
    out = subprocess.Popen(shlex.split(query2), stdout=subprocess.PIPE)
    while(1):
        line = out.stdout.readline()
        if(not line):
            break
        line = line.decode('utf-8').strip()
        line = ' '.join(line.split())
        #line = line.replace("  "," ")
        result = line.split(" ")
        ip_Source = result[2]
        ip_Destination = result[4]
        fileName = line.split(":")[1].strip()

        task = Task('', '', '', '', '', '', '', '', '', 'smb', '')
        task.destination_ip = ip_Destination
        task.source_ip = ip_Source
        task.file_name = fileName
        task.time_received = datetime.datetime.now().strftime('%H:%M:%S')
        task.date_received = datetime.datetime.now().strftime('%Y-%m-%d')
        if(fileName in tmp):
            continue
        tmp.append(fileName)
        if(fileName.find(';') != -1 or fileName == ''):
            continue
        
        #print("ip_src = " + ip_Source, "ip_dst = " + ip_Destination, "fileName = " + fileName)

        checkPath = export_SMB2 + "/%5c" + fileName
        if(os.path.isfile(checkPath)):
            #print("File exits: ",checkPath)
            mime_Type = mime.from_file(checkPath)
            if(mime_Type not in deny_MimiType and mime_Type != "text/plain"):
                print("Path: " + checkPath + " --- mimme: " + mime_Type)
                file = Static_Analyst(checkPath, task)
                if(file != ''):              
                    if(mime_Type == 'application/zip' or mime_Type == 'application/x-7z-compressed' or mime_Type == 'application/x-rar-compressed'):
                        try:
                            extract_Files, extract_Tasks = Extract_FileCompressed(checkPath, task)
                            files_SendResquest.extend(extract_Files)
                            task_SendRequest.extend(extract_Tasks)
                        except:
                            print('Not Extract file compressed : ' + checkPath)
                    else:
                        task = task.obj_dict()
                        files_SendResquest.append(checkPath)
                        task_SendRequest.append(task)
    
    return files_SendResquest, task_SendRequest

# Phan tich goi tin
def Static_Analyst(fullPath, taskJson):
    tmp = fullPath.replace('(', '_')
    tmp = tmp.replace(')', '_')
    tmp = tmp.replace('&', '_')
    os.rename(fullPath, tmp)
    fullPath = tmp

    scan = "./BinarySearch " + fullPath
    out = ''
    try:
        out = subprocess.check_output(scan, shell=True)
    except:
        print(fullPath + "not analyst static")
    if(out == ''):
        return ''
    out_str = out.decode("utf-8")
    if(out_str.split("/")[0] != ''):
        #print(out, out_str, out_str.split("/"), out.decode("utf-8"))
        taskJson.file_name = fullPath.split("/")[-1]
        taskJson.malware_type = out_str.split("/")[0]
        taskJson.detected_by = "static"
        file_Status = os.stat(fullPath)
        taskJson.file_size = file_Status.st_size
        taskJson.md5 = out_str.split("/")[1]
        try:
            r = requests.post(url_AddItems, json=taskJson.obj_dict())
            data = r.json()
            print(data)
            return ''
        except:
            return fullPath
    return fullPath

async def Dynamic_Analyst(file_list, taskJson, logger):
    for index in range(len(file_list)):
        # Tu sua, neu ko check exist bi kill neu file ko ton tai 
        if os.path.exists(file_list[index]): # KHONG XOA DONG nAY !!!!!!
            req = {'files[]': open(file_list[index], 'rb')}

            #print('taskJson[index]', taskJson[index])
            logger.info("Analyst Begin[%d]: %s", index, file_list[index])
            data = await requests.post(url_CheckMalware, files=req, data=taskJson[index])
            r = data.json()
            print(r)
            logger.info("Analyst Success[%d]: %s", index, file_list[index])
        else:
            print(file_list[index] + ': File not exists')
            logger.warning("Analyst Error[%d]: %s", index, file_list[index]) 

# Bat va xu li goi tin
async def Capture_Pcap():
    # path1 = "/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract/21-08-2020-10-47"
    # Handle_Pcap(path1)
    iObject = config_object["INTERFACE"]
    interface = iObject["Interface"]
    command = "tshark -i " + interface + " -w Test.pcap -a duration:60"
    while(1):
        subprocess.check_output(command, shell=True)
        path = str(datetime.datetime.now().strftime('%d-%m-%Y-%H-%M'))
        path = os.path.join(extract_Path, path)
        os.mkdir(path)
        p = Process(target= Run_FindUrl, args= (active_File,url_Check, ))
        p.start()
        await Handle_Pcap(path)
        os.remove(active_File)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

async def Handle_Pcap(path):
    
    files_SendResquest = []
    task_SendRequest = []
    # extract http, ftp
    query1 = "tcpflow -r " + active_File + " -o " + path + " -e http"
    subprocess.check_output(query1, shell=True)

    # extract SMB
    list_SMB, list_Task = Export_SMB2()
    if(len(list_SMB) > 0):
        files_SendResquest.extend(list_SMB)
        task_SendRequest.extend(list_Task)
    list = os.listdir(path)

    markFtp = []
    # remove file unuse
    for index in list:
        fullPath = os.path.join(path, index)
        mime_Type = mime.from_file(fullPath)
        check = Check_UnFile(mime_Type)

        # Add find Ftp 
        if(mime_Type == "text/plain"):
            if(index.find(portFtp) != -1):
                markFtp.append(index)

        elif(mime_Type in deny_MimiType or check == 1):
            os.remove(fullPath)

    list = os.listdir(path)

    # handle file 
    for index in range(len(list)):  
        no_FullPath = os.path.join(path, list[index])
        mime_Type = mime.from_file(no_FullPath)  
        
        if(mime_Type != 'text/plain'):
            #print(fullPath + "\n")
            ValidIpAddressRegex = r'''(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
            check = re.search(ValidIpAddressRegex, list[index])
            if(check is not None):
                fullPath, task = Parse_FileName(list[index], path, markFtp)
                if fullPath is None:
                    continue
            if(fullPath == ''):
                os.remove(no_FullPath)
                continue
            
            if(mime_Type == 'application/zip' or mime_Type == 'application/x-7z-compressed' or mime_Type == 'application/x-rar-compressed'):
                try:
                    extract_Files, extract_Tasks = Extract_FileCompressed(fullPath, task)
                    files_SendResquest.extend(extract_Files)
                    task_SendRequest.extend(extract_Tasks)
                except:
                    print('not Extract file zip : ' + fullPath)
            else:
                file = Static_Analyst(fullPath, task)
                #print(fullPath + "\n")

                if(file != ''):
                    task = task.obj_dict()
                    task_SendRequest.append(task)
                    files_SendResquest.append(file)

    history = path.split("/")[-1] + ".log"
    logging.basicConfig(level= logging.DEBUG, filename= os.path.join('Log',history),format='%(asctime)s %(levelname)s:%(message)s')
    logger = logging.getLogger(__name__)
    logger.info(" -------  \t File Send Dynamic  \t  ------  \n ")
    logger.info("Count: %d", len(files_SendResquest))

    print(" -------  \t File Send Dynamic  \t  ------  \n ")
    print("Count: %d", len(files_SendResquest))
    #print("Send Count: " + str(len(files_SendResquest)))
    for i in files_SendResquest:
        print(i)
        logger.info(i)
        
    logger.info(" -------  \t Finish \t  ------  \n ")
    print(" -------  \t Finish \t  ------  \n ")

    await Dynamic_Analyst(files_SendResquest, task_SendRequest, logger)
    # my_thread = []
    # t1 = threading.Thread(target=Dynamic_Analyst, args=(files_SendResquest, task_SendRequest, logger))
    # t1.start()
    # my_thread.append(t1)

if __name__ == "__main__":
    #path = "/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Extract/17-08-2020-14-02"
    # parser = ArgumentParser("Testing")
    # parser.add_argument('-r', dest='file', required="false", default= "kaka")
    # args = parser.parse_args()
    # inputfile = args.file
    # Handle_Pcap(path)
    #task = Task('192.168.1.18','192.168.147.85','http',1,'Xorer.eg','','','','','','')
    # Static_Analyst('/home/mtaav/Desktop/QuetNhanh/QuickCheck_Virus/Virus.Win32.Xorer.eg', task)
    loop = asyncio.get_event_loop()

    asyncio.ensure_future(Capture_Pcap())
    loop.run_forever()