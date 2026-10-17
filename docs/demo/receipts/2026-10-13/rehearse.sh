#!/usr/bin/env bash
# Re-rehearsal after the listener2 SO_RCVBUF fix: two-arm 150 s, then union alone 60 s, each bracketed by nstat.
set -u; R=/data/scratch/demo-rehearsal; B=$R/blockcast-shreds; cd $R
$B selftest --fixture > selftest.txt
nstat -saz UdpInDatagrams UdpRcvbufErrors > n0
timeout -s TERM 150 $B --feed 'prod=ssm://69.25.95.197@232.0.0.1:5001?iface=eth0' --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?iface=eth0' --report-interval 5s --http-addr 127.0.0.1:18080 > receipt-2arm.txt 2> err-2arm.txt; echo "2arm exit=$?" > exits.txt
nstat -saz UdpInDatagrams UdpRcvbufErrors > n1
timeout -s TERM 60 $B --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?iface=eth0' --report-interval 5s --http-addr 127.0.0.1:18081 > receipt-union.txt 2> err-union.txt; echo "union exit=$?" >> exits.txt
nstat -saz UdpInDatagrams UdpRcvbufErrors > n2
date -u +%FT%TZ > done
