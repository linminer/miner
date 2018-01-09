#!/usr/bin/python
import sys, re, os
import syslog
import commands

dead_strings = {}

#Jan  9 09:16:43 miner00 kernel: [ 2160.191729] INFO: task nsgpucnminer:2812 blocked for more than 120 seconds.
#Jan  9 09:16:43 miner00 kernel: [ 2160.191801]       Tainted: G           OE   4.4.0-104-generic #127-Ubuntu
#Jan  9 09:16:43 miner00 kernel: [ 2160.191861] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
#Jan  9 09:16:43 miner00 kernel: [ 2160.191930] nsgpucnminer    D ffff88019398b850     0  2812      1 0x00000002
#Jan  9 09:16:43 miner00 kernel: [ 2160.191939]  ffff88019398b850 ffff88019398b830 ffffffff81e11500 ffff8801b5aca700
#Jan  9 09:16:43 miner00 kernel: [ 2160.191945]  ffff88019398c000 ffff88019398b950 ffff880196e578b0 0000000000000001

dead_strings['nsgpucminer'] = 'Claymore hung on GPU failed'
dead_strings['amd_sched_entity_push_job'] = 'GPU died'

restart_script = '/home/bdoctor/claymore/restart.sh'

(s,o) = commands.getstatusoutput('/bin/dmesg')

this = o.split() 

for line in this:
    #print line
    for string in dead_strings:
        if string in line:
            syslog.syslog('GPU has died: (%s) -- REBOOTING' % line)
            (s,o) = commands.getstatusoutput(restart_script)
            print o

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
