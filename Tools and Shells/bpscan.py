#!/usr/bin/env python2

import urllib2, urllib, sys, threading
from socket import *

print """
 _                               
| |__  _ __  ___  ___ __ _ _ __  
| '_ \| '_ \/ __|/ __/ _` | '_ \ 
| |_) | |_) \__ \ (_| (_| | | | |
|_.__/| .__/|___/\___\__,_|_| |_|
      |_|                        

Coded by: dotcppfile
Twitter: https://twitter.com/dotcppfile
Blog: http://dotcppfile.worpdress.com
"""

def logPorts(port):
	f = open("bpscan - ports.txt", "a")
	port = "%d\n" % int(port)
	f.write(port)
	f.close()

def logErrors(error):
	f = open("bpscan - errors.txt", "a")
	error = "%s\n" % error
	f.write(error)
	f.close()

url = "http://ports.yougetsignal.com/check-port.php"
http_header = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
}

class mainchecker(threading.Thread):
   	def __init__ (self, port):
        	threading.Thread.__init__(self)
        	self.port = port

    	def run(self):
		print "Trying: %d" % int(self.port)

		try:
			s=socket(AF_INET, SOCK_STREAM)
			s.bind(("0.0.0.0", int(self.port)))
			s.listen(5)
			params = {
  				'portNumber': int(self.port),
				'remoteAddress': '192.168.1.4',
			}

			data = urllib.urlencode(params)
			req = urllib2.Request(url, data, http_header)
			response = urllib2.urlopen(req)
			the_page = response.read()

			if ("is open" in the_page):
				logPorts(int(self.port))

		except Exception, err:
			err = "Port %d: %s" % (int(self.port), err)
			logErrors(err)

		s.close()

ports = []
threads = []
for x in range(1024, 65537):
	ports.append(x)
	if (len(ports) == 10):
		for i in ports:
    			thread = mainchecker(i)
    			thread.start()
   			threads.append(thread)
 
		for thread in threads:
    			thread.join()
		
		del threads[:]
		del ports[:]
