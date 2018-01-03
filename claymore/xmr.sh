#!/bin/bash
export GPU_FORCE_64BIT_PTR=1
export GPU_MAX_HEAP_SIZE=100
export GPU_USE_SYNC_OBJECTS=1
export GPU_MAX_ALLOC_PERCENT=100
export GPU_SINGLE_ALLOC_PERCENT=100

./nsgpucnminer -h 832 -dmem 1 -xpool stratum+tcp://pool.supportxmr.com:7777 -xwal 45tyvZfuS1T1hZuVqrZuk16gRipjuWDRyg6fR8WxBq4PLX5nFEmZ8rJeLXXQHfESseWv7qbmZbaFpdtMnBSXvr5vCjDzbQn -xpsw miner49erclaymore@ps-ax.com
