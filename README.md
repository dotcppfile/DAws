Hello everyone,

![alt tag](http://i.imgur.com/wxAH9kO.jpg)

### About

There's multiple things that makes DAws better than every Web Shell out there:

1. Bypasses Security Systems(IPS, WAFs,etc) like Suhosin(uses up to 20 php functions just to get a command executed).
1. Drops CGI Shells and communicate with them to bypass Security Systems.
1. Uses the SSH Authorized Keys method to bypass Security Systems.
1. Uses Shellshock in 2 methods to bypass Security Systems.
1. Is completely Post Based and uses a XOR Encryption based on a random key that gets generated with every new session + private base64 functions to bypass Security Systems.
1. Supports Windows and Linux.
1. Finds a writeable and readable directory and moves there if it's a web directory; DAws will output everything in that found directory.
1. Drops a php.ini and a .htaccess file that clears all disablers incase "suphp" was installed.
1. Has an advanced File Manager.
1. Everything is done automatically so there's nothing for the user to worry about.
1. Open Source.
1. and much more (check the source for more information; everything is well commented)

### Credits:
1. [dotcppfile](https://twitter.com/dotcppfile)
1. Aces who helped me code the old version of DAws
1. Vedu for checking and reporting bugs.

### Blog:
1. https://dotcppfile.wordpress.com/
