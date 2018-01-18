#!/bin/sh

ROCM=/home/bdoctor/ROC-smi/rocm-smi

# Vega Frontier
$ROCM -d 0 --setsclk 3 --setmclk 2

# RX570
$ROCM -d 3 --setsclk 3 --setmclk 1
