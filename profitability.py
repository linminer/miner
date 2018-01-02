#!/usr/bin/python3
# bdoctor
import sys
import json
import requests
from collections import OrderedDict
from operator import itemgetter    

profitSource = 'http://whattomine.com/coins.json'

response = requests.get(profitSource)

JSONData = json.loads(response.text)

Profits = {}

watchlist = [ 'monero', 'sumokoin' ]

for item in JSONData:
    #print(JSONData[item])
    for currency in JSONData[item]:
        thisCurrency = currency.lower()
        if not Profits.get(currency):
            Profits[thisCurrency] = {}

        if JSONData[item][currency].get('profitability24'):
            Profits[thisCurrency]['24hour'] = JSONData[item][currency]['profitability24']
            Profits[thisCurrency]['now']    = JSONData[item][currency]['profitability']

max24  = 0
maxnow = 0
Max24Coins = {}
MaxNowCoins = {}

for coin in Profits:
    if Profits[coin]['24hour'] > max24:
        if not Max24Coins.get(coin):
            Max24Coins[coin] = int(Profits[coin]['24hour'])
        else:
            Max24Coins[coin] = int(Profits[coin]['24hour'])

    if Profits[coin]['now'] > maxnow:
        if not MaxNowCoins.get(coin):
            MaxNowCoins[coin] = int(Profits[coin]['now'])
        else:
            MaxNowCoins[coin] = int(Profits[coin]['now'])

for curr in watchlist:
    if Max24Coins.get(curr):
        print ('W24h  : %-3.1f,%6s' % (Max24Coins[curr],curr))
    if MaxNowCoins.get(curr):
        print ('Wnow  : %-3.1f, %6s' % (Max24Coins[curr],curr))

cnt  = 0
maxc = 10

for hashitem in (Max24Coins,'24Hour'), (MaxNowCoins, 'Now'):
    cnt = 0
    for item in OrderedDict(sorted(hashitem[0].items(), key = itemgetter(1), reverse = True)):
        cnt += 1
        if hashitem[0][item] > 100:
            print ('%6s: %-3.1f, %s'% (hashitem[1],hashitem[0][item],item))
        else:
            if cnt >= maxc:
                break
            print ('%6s: %-3.1f, %s'% (hashitem[1],hashitem[0][item],item))

