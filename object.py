import magic

mime = magic.Magic(mime=True)
mime_Type = mime.from_file("/home/duong/Desktop/Do-An/SMB/192.168.008.104.59772-192.168.008.103.00445")
print (mime_Type)