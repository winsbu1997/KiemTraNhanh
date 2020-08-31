import magic
import os
import shutil
from pyunpack import Archive

#Archive('/home/duong/Desktop/Do-An/picohttpparser-master.7z').extractall('/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract_Zip')
path = '/home/duong/Desktop/Do-An/QuickCheck_Virus/SMB2'
shutil.rmtree(path, ignore_errors=True)
#os.removedirs(path)
mime = magic.Magic(mime=True)
mime_Type = mime.from_file('/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract_Zip/flexisel-master/package.json')
print(mime_Type)
#192.168.147.013.36398-117.018.232.240.00080--47