#!/usr/bin/python3
# bdoctor

import requests,re,json, sys
from html.parser import HTMLParser

try:
    debug = sys.argv[1]
    debug = True
except Exception:
    debug = False

# https://github.com/abuisine/docker-claymore/blob/master/API.txt
#{"result": ["9.3 - ETH", "21", "182724;51;0", "30502;30457;30297;30481;30479;30505", "0;0;0", "off;off;off;off;off;off", "53;71;57;67;61;72;55;70;59;71;61;70", "eth-eu1.nanopool.org:9999", "0;0;0;0"]}
#"9.3 - ETH"                             - miner version.
#"21"                                    - running time, in minutes.
#"182724"                                - total ETH hashrate in MH/s, number of ETH shares, number of ETH rejected shares.
#"30502;30457;30297;30481;30479;30505"   - detailed ETH hashrate for all GPUs.
#"0;0;0"                                 - total DCR hashrate in MH/s, number of DCR shares, number of DCR rejected shares.
#"off;off;off;off;off;off"               - detailed DCR hashrate for all GPUs.
#"53;71;57;67;61;72;55;70;59;71;61;70"   - Temperature and Fan speed(%) pairs for all GPUs.
#"eth-eu1.nanopool.org:9999"             - current mining pool. For dual mode, there will be two pools here.
#"0;0;0;0"                               - number of ETH invalid shares, number of ETH pool switches, number of DCR invalid shares, number of DCR pool switches.

jsonblobMatch = re.compile('({.*})')

statsHosts = ['http://miner00.ps-ax.com:3333', 'http://miner01.ps-ax.com:3333', 'http://miner03.ps-ax.com:3333', 'http://miner04.ps-ax.com:3333']

#ZZZstatsHosts = ['http://miner01.ps-ax.com:3333']

badShareString = re.compile('(\S+)found incorrect share.')


class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def matchHashWithTempFan(hashes,gpustats):
    gpus = {}
    num  = 0
    splitFactor = -1

    for hashrate in hashes:
        if gpustats.split(';').__len__() > 2:
            splitFactor = 3
            gstats = gpustats[0:gpustats.find(';',splitFactor)].split(';')
        else:
            gstats = gpustats.split(';')

        gpustats = gpustats[gpustats.find(';',splitFactor):]

        gpustats = gpustats.lstrip(';')
        gpus[num] = {'gpuhash':hashrate,
                     'gputemp':gstats[0],
                     'gpufan': gstats[1]}
        num += 1
    return(gpus)

def matchGPUModel(blob):

    gpuModels = []
# GPU #0: Baffin, 4082 MB available, 16 compute units
# GPU #0 recognized as Radeon RX 460/560


    for l in blob.split('\n'):
        if l.startswith('GPU') and '#' in l:
            try:
                (discard,model) = l.split(':')
                gpuModels.append(model.strip())
            except Exception:
                print ('error with ', l)

    return(gpuModels)

burningGPUs = []

globalHashRate = 0

for host in statsHosts:

    response  = None
    gpuModels = None
    badShares = None
    jsonData  = None
    data      = None
    rdata     = None
    stripper  = MLStripper()

    try:
        response = requests.get(host)
    except Exception:
        print ('ERROR with (%s):' %host)
        response = None
        continue

    stripper.feed(response.text)
    rdata = stripper.get_data()

    gpuModels = matchGPUModel(rdata)
    badShares = badShareString.search(rdata)
    jsonData  = jsonblobMatch.search(rdata)

    if jsonData:
        jblob = json.loads(jsonData.group(1))

    if badShares:
        burningGPUs.append(badShares.group(1))

    data = jblob['result']

    uptime = data[1]
    (hpm,shares,rejectedshares) = data[2].split(';')
    gpuhashrates = data[3].split(';')
    gputempfan   = data[6]
    hashpool     = data[7]
    hashport     = data[8]

    gpuStats = matchHashWithTempFan(gpuhashrates,gputempfan)

    globalHashRate += int(hpm)

    print ('%s: Overall hashrate: %5s, total good shares: %5s, total bad shares: %5s, uptime: %5smin' % (host,hpm,shares,rejectedshares,uptime))
    for gpu in gpuStats:
        this = gpuStats[gpu]
        hashrate = this['gpuhash']
        temp     = this['gputemp']
        fanspeed = this['gpufan']
        print('GPU: %3s\tHASHRATE: %4s\tTEMP: %3s\tFAN: %3s\tMODEL: %s' % (gpu,hashrate,temp,fanspeed,gpuModels[gpu]))

    print ('-' * 80)
    print ('Burning GPUS:', burningGPUs)

    if debug:
        lines = rdata.split('\n')
        for l in lines:
            print(l)

print ('GLOBAL HASHRATE:', globalHashRate)
