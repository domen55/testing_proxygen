#!/bin/bash
#!(cd /tmp/build/proxyweb/ && ninja install)
LD_LIBRARY_PATH="/tmp/build/install/lib64/;/tmp/build/install/lib:$LD_LIBRARY_PATH" gdb --args /tmp/build/install/bin/webapp -threads 4 -protocol=h3 -port=10000 -h2port=10000 -quic_version 1 -host="10.10.10.1" -static_root=/root/web/proxyweb/root -cert="/root/web/ca_create/server_ecdsa/server.crt" -key="/root/web/ca_create/server_ecdsa/server.key" -psk_file="/tmp/psk_cache" -qs_io_uring_capacity=2048
