#!/usr/bin/python3
# bdoctor

import requests,re,json, sys
from html.parser import HTMLParser

try:
    debug = sys.argv[1]
    debug = True
except Exception:
    debug = False

jsonblobMatch = re.compile('({.*})')

statsHosts = ['http://miner00.ps-ax.com:8080/api.json', 'http://miner01.ps-ax.com:8080/api.json', 'http://miner01.ps-ax.com:8081/api.json']

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

globalHashRate = 0

for host in statsHosts:

    response  = None
    jsonData  = None
    rdata     = None
    stripper  = MLStripper()

    try:
        response = requests.get(host)
    except Exception:
        print ('ERRO: with (%s):' %host)
        response = None
        continue

    stripper.feed(response.text)
    rdata = stripper.get_data()

    jsonData  = jsonblobMatch.search(rdata)

    if jsonData:
        jblob = json.loads(jsonData.group(1))

#{"version":"xmr-stak/2.2.0/2ae7260/master/lin/amd-cpu/aeon-monero/0","hashrate":{"threads":[[733.3,null,null],[734.3,null,null],[733.5,null,null],[736.6,null,null],[735.5,null,null],[739.5,null,null],[342.5,null,null],[343.4,null,null]],"total":[5098.4,null,null],"highest":5093.4},"results":{"diff_current":180007,"shares_good":5,"shares_total":5,"avg_time":6.2,"hashes_total":360014,"best":[1090789,507216,64915,25858,23171,0,0,0,0,0],"error_log":[]},"connection":{"pool": "pool.supportxmr.com:9000 ","uptime":31,"ping":85,"error_log":[]}}


    hpm = int(jblob['hashrate']['total'][0])

    globalHashRate += hpm

    uptime = jblob['connection']['uptime']
    shares = jblob['results']['shares_good']
    rejectedshares = ( int(jblob['results']['shares_total']) - int(jblob['results']['shares_good']) )

    print ('%s: Overall hashrate: %5s, total good shares: %5s, total bad shares: %5s, uptime: %5ssec' % (host,hpm,shares,rejectedshares,uptime))

    cnt = 0
    for gpu in jblob['hashrate']['threads']:
        print('GPU: %3s\tHASHRATE: %4s' % (cnt,gpu[0]))
        cnt = cnt + 1

    print ('-' * 80)

    if debug:
        lines = rdata.split('\n')
        for l in lines:
            print(l)

print ('GLOBAL HASHRATE:', globalHashRate)
