#!/bin/bash

SPEED=255

ADAPTERS=`/usr/bin/lspci|grep VGA|grep ATI|wc|awk '{print $1}'`
 cnt=1

    while [ $cnt -le $ADAPTERS ]
         do
             #cat /sys/class/hwmon/hwmon$cnt/pwm1
             echo $SPEED > /sys/class/hwmon/hwmon$cnt/pwm1
             #cat /sys/class/hwmon/hwmon$cnt/fan1_input
             ((cnt++))
         done

