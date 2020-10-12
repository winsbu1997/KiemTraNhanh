import requests
import subprocess
import shlex
import json

def Run_FindUrl(path, urlCheck):
    #path = "/home/duong/Desktop/Do-An/ZeusGameOver.pcapng"
    query = "tshark -r " + path + " -Y 'dns.flags.response == 1' -T fields -e dns.qry.name"
    out = subprocess.Popen(shlex.split(query), stdout=subprocess.PIPE)
    listUrl = []
    added = set()
    while(1):
        line = out.stdout.readline().decode('utf-8')
        val = line.strip()
        if(not line):
            break
        if(not val in added):
            listUrl.append(val)
            added.add(val)
    res = {"urls" : listUrl}
    print(res)
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    try:
        r = requests.post(url = urlCheck, json = json.dumps(res), headers = headers)
        print(r.json())
    except:
        print("Not Url")

if __name__ == "__main__":
    command = "tshark -i vmnet8 -w TestUrl.pcap -a duration:10"
    while(1):
        subprocess.check_output(command, shell=True)
        Run_FindUrl("TestUrl.pcap",'http://127.0.0.1:5002/checkurl')
#     Run_FindUrl("",'http://localhost:5002/api/v1/capture/checkurl')
# for t in my_threads:
#     if not t.is_alive():
#         # get results from thread
#         t.handled = True
# my_threads = [t for t in my_threads if not t.handled]
#if __name__ == "__main__":
# number_cpu = multiprocessing.cpu_count()
# print("Number CPU {}".format(number_cpu))