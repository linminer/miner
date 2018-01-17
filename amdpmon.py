#!/usr/bin/python
import sys, re, os
import syslog
import commands

try:
    debug = sys.argv[1]
    debug = True
except:
    debug = False

adapters  = '/sys/kernel/debug/dri'
stat_file = '/sys/kernel/debug/dri/%s/amdgpu_pm_info'
fan_value = '/sys/class/hwmon/hwmon%s/pwm1'
fan_rpm   = '/sys/class/hwmon/hwmon%s/fan1_input'

dead_strings = {}

#Jan  9 09:16:43 miner00 kernel: [ 2160.191729] INFO: task nsgpucnminer:2812 blocked for more than 120 seconds.
#Jan  9 09:16:43 miner00 kernel: [ 2160.191801]       Tainted: G           OE   4.4.0-104-generic #127-Ubuntu
#Jan  9 09:16:43 miner00 kernel: [ 2160.191861] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
#Jan  9 09:16:43 miner00 kernel: [ 2160.191930] nsgpucnminer    D ffff88019398b850     0  2812      1 0x00000002
#Jan  9 09:16:43 miner00 kernel: [ 2160.191939]  ffff88019398b850 ffff88019398b830 ffffffff81e11500 ffff8801b5aca700
#Jan  9 09:16:43 miner00 kernel: [ 2160.191945]  ffff88019398c000 ffff88019398b950 ffff880196e578b0 0000000000000001

dead_strings['segfault at'] = 'detected segfault!'
dead_strings['amd_sched_entity_push_job'] = 'GPU died'

restart_script = '/home/bdoctor/miner/restart.sh'

(s,o) = commands.getstatusoutput('/bin/dmesg')

this = o.split('\n')

for line in this:
    #print line
    for string in dead_strings:
        if string in line:
            if debug:
                print 'reboot!! ', line

            syslog.syslog('GPU has died: (%s) -- REBOOTING' % line)
            (s,o) = commands.getstatusoutput(restart_script)
            print o


#/sys/kernel/debug/dri/0/amdgpu_pm_info

adapter_files = os.listdir(adapters)
numGPU = 0
total_power = 0

for gpu in adapter_files:

    lines  = ''
    logMsg = ''

    try:
        lnfh = open(stat_file % gpu, 'r')
        lines = lnfh.readlines()
        lnfh.close()
	fvfh = open(fan_value % gpu, 'r')
        fvlines = fvfh.readlines()
        fvfh.close()

	frpmfh    = open(fan_rpm % gpu, 'r')
        frpmlines = frpmfh.readlines()
        frpmfh.close()
        numGPU += 1
        #print lines
    except Exception, e:
	#if debug: print 'error: %s' % e
        pass

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
                logMsg += '%s:%s,' % (match.group(2), match.group(1).strip())
                if 'average GPU' == match.group(2):
                    this = match.group(1).strip()
                    this = this.replace(' W', '')
                    this,that = this.split('.',2)
                    this = int(this)
                    total_power += this
                #print match.group(2), match.group(1).strip()
            else:
                print 'missed ', l

    toLog = '%s,%s%s' % ('Adapter:%s' % gpu,logMsg,'GPUTemp:%s, GPUFanRPM:%s, GPUFanInput:%s, GPULoad:%s' % (Temp,frpmlines[0].strip(),fvlines[0].strip(),Load))
    if Temp and Load:
        if debug:
            print toLog
        syslog.syslog(toLog)

if debug:
    print 'total power: %s' % total_power


