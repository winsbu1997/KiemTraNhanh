from configparser import ConfigParser

config_object = ConfigParser()

# set duong dan luu file cature
config_object["FOLDERCONFIG"] = {
    "Http_Ftp": "/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract",
    "Smb2": "/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract_SMB2",
    "Compressed" : "/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract_Zip",
    "Log" : "/home/duong/Desktop/Do-An/QuickCheck_Virus/Log"
}

config_object["APICONFIG"] = {
    "UrlCheck" : "http://192.168.126.26:5002/api/v1/capture/check",
    "UrlPost" : "http://192.168.126.26:5002/api/v1/capture"
}

config_object["INTERFACE"] = {
    "Interface" : "wlp2s0"
}

with open('config.ini', 'w') as conf:
    config_object.write(conf)