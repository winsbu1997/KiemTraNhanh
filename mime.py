import magic

mime = magic.Magic(mime=True)
mime_Type = mime.from_file('/home/duong/Desktop/Do-An/QuickCheck_Virus/Extract/20-08-2020-23-43/main.js')
print(mime_Type)
#192.168.147.013.36398-117.018.232.240.00080--47