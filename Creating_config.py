from configparser import ConfigParser

config_object = ConfigParser()

# set duong dan luu file cature
config_object["FOLDERCONFIG"] = {
    "Http_Ftp": "Extract",
    "Smb2": "Extract_SMB2",
    "Compressed" : "Extract_Zip",
    "Log" : "Log"
}

config_object["APICONFIG"] = {
    "UrlCheck" : "http://192.168.126.25:5002/api/v1/capture/checkurl",
    "UrlPost" : "http://192.168.126.26:5002/api/v1/capture",
    "UrlCheck_Malware" : "http://192.168.126.25:5002/api/v1/capture/check"
}

config_object["INTERFACE"] = {
    "Interface" : "wlp2s0"
}

with open('config.ini', 'w') as conf:
    config_object.write(conf)