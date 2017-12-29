#!/usr/bin/python
import sys, re, os
import syslog


adapters = '/sys/kernel/debug/dri'
stat_file = '/sys/kernel/debug/dri/%s/amdgpu_pm_info'

#/sys/kernel/debug/dri/0/amdgpu_pm_info

adapter_files = os.listdir(adapters)

for gpu in adapter_files:

    lines  = ''
    logMsg = ''
 
    try:
        lnfh = open(stat_file % gpu, 'r')
        lines = lnfh.readlines()
        lnfh.close()
        #print lines
    except Exception, e:
        pass
        #print 'error: %s' % e
    
    pwrRE = re.compile('(^.*)\((.*)\)$')
    powerout = False
    logMsg = ''
    Load = ''
    Temp = ''
    
    for l in lines:
        l = l.strip()
        l = l.lstrip()
        #print l
        if l == '': continue
    
        if 'GFX Clocks and Power' in l:
            powerout = True
            continue
    
        if 'GPU Load' in l:
            (Toss,Load) = l.split(':')
            powerout = False
            continue
    
        if 'GPU Temperature' in l:
            (Toss,Temp) = l.split(':')
            powerout = False
            continue
    
        if powerout:
            match = pwrRE.search(l)
            if match:
                #print 'gotit', match.group(1), match.group(2)
                #print '%10s\t\t%s' % (match.group(2), match.group(1))
                logMsg += '%s:%s,' % (match.group(2), match.group(1).strip())
            else:
                print 'missed ', l
    
    toLog = '%s,%s%s' % ('Adapter:%s' % gpu,logMsg,'GPUTemp:%s,GPULoad:%s' % (Temp,Load))
    if Temp and Load:
        syslog.syslog(toLog)
