Hello everyone,

![alt tag](http://i.imgur.com/1sJr9Ln.png)

###About

There's multiple things that makes DAws better than every Web Shell out there:

1. Supports CGI by dropping Bash Shells (for Linux) and Batch Shells (for Windows).
1. Bypasses WAFs, Disablers and Protection Systems; DAws isn't just about using a particular function to get the job done, it uses up to 6 functions if needed, for example, if shell_exec was disabled it would automatically use exec or passthru or system or popen or proc_open instead, same for Downloading a File from a Link, if Curl was disabled then file_get_content is used instead and this Feature is widely used in every section and fucntion of the shell.
1. Automatic Encoding; DAws randomly and automatically encodes most of your GET and POST data using XOR(Randomized key for every session) + Base64(We created our own Base64 encoding functions instead of using the PHP ones to bypass Disablers) which will allow your shell to Bypass pretty much every WAF out there.
1. Advanced File Manager; DAws's File Manager contains everything a File Manager needs and even more but the main Feature is that everything is dynamically printed; the permissions of every File and Folder are checked, now, the functions that can be used will be available based on these permissions, this will save time and make life much easier.
1. Tools: DAws holds bunch of useful tools such as "bpscan" which can identify useable and unblocked ports on the server within few minutes which can later on allow you to go for a bind shell for example.
1. Everything that can't be used at all will be simply removed so Users do not have to waste their time. We're for example mentioning the execution of c++ scripts when there's no c++ compilers on the server(DAws would have checked for multiple compilers in the first place) in this case, the function would be automatically removed and the User would know.
1. Supports Windows and Linux.
1. Openned Source.

######Extra Info
<ul>
	<li>Directory Romaing:</li>
	<ul>
		<li>DAws checks, within the `web` directory, for a Writable and Readable Directory which will then be used to Drop and Execute needed scripts which will guarantee their success.</li>
	</ul>
	<li>Eval Form:</li>
	<ul>
		<li>`include`, `include_once`, `require` or `require_once` are being used instead PHP `eval` to bypass Protection Systems.</li>
	</ul>
	<li>Download from Link - Methods:</li>
	<ul>
		<li>PHP Curl</li>
		<li>File_put_content</li>
	</ul>
	<li>Zip - Methods:</li>
	<ul>
		<li>Linux:</li>	
		<ul>
			<li>Zip</li>
		</ul>
		<li>Windows:</li>
		<ul>
			<li>Vbs Script</li>
		</ul>
	</ul>
	<li>Shells and Tools:</li>
	<ul>
		<li>Extra:</li>
		<ul>
			<li>`nohup`, if installed, is automatically used for background processing.</li>
		</ul>
	</ul>
</ul>

###Updates:
DAws is always getting updated, I guess that's enough for this part Lol.

###Credits:
1. [dotcppfile](https://twitter.com/dotcppfile)
2. [Aces](https://twitter.com/__A_C_E_S__)
