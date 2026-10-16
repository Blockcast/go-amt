#!/usr/bin/env bash
# Re-rehearsal with receiver buffers raised (devbox rmem_max 16 MiB; 8 MiB SO_RCVBUF on the receiver's :5001 sockets).
set -u; R=/data/scratch/demo-rehearsal; B=$R/blockcast-shreds; cd $R
run() { # name secs feeds...
  local name=$1 secs=$2; shift 2
  nstat -saz UdpInDatagrams UdpRcvbufErrors > n-$name.0
  timeout -s TERM $secs $B "$@" --report-interval 5s > receipt-$name.txt 2> err-$name.txt &
  local pid=$!; sleep 2; sudo -n $R/sock-rcvbuf.py $(pgrep -P $pid -f blockcast-shreds || echo $pid) 8388608 5001 > buf-$name.txt 2>&1
  wait $pid; echo "$name exit=$?" >> exits2.txt
  nstat -saz UdpInDatagrams UdpRcvbufErrors > n-$name.1
}
rm -f exits2.txt
run twoarm 150 --feed 'prod=ssm://69.25.95.197@232.0.0.1:5001?iface=eth0' --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?iface=eth0' --http-addr 127.0.0.1:18080
run union 60 --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?iface=eth0' --http-addr 127.0.0.1:18081
date -u +%FT%TZ > done2
