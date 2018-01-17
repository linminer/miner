#!/bin/bash

/bin/dmesg >> /tmp/GPUPANIC.log
echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger
