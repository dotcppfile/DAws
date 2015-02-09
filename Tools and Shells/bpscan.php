<?php

echo "
 _                               
| |__  _ __  ___  ___ __ _ _ __  
| '_ \| '_ \/ __|/ __/ _` | '_ \ 
| |_) | |_) \__ \ (_| (_| | | | |
|_.__/| .__/|___/\___\__,_|_| |_|
      |_|                        

Coded by: dotcppfile & Aces
Twitter: https://twitter.com/dotcppfile
Blog: http://dotcppfile.worpdress.com
Twitter: https://twitter.com/__A_C_E_S__
";

$base64ids = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/");

function binToDec($string)
{
	$decimal = "";
	for($i = 0; $i<strlen($string); $i++)
	{
		$dec = intval($string{(strlen($string))-$i-1})*pow(2, $i);
		$decimal+=$dec;
	}
	
	return intval($decimal);
}

function decToBin($dec)
{
	$binary = "";
	$current = intval($dec);

	if ($current == 0)
	{
		return "0";
	}
	
	while (1)
	{
		if ($current == 1)
		{
			$binary="1".$binary;
			break;
		}
		$binary = ($current%2).$binary;
		$current = intval($current/2);
	}
	
	return $binary;
}

function base64encoding($string)
{
	global $base64ids;

	$binary = "";
	for ($i = 0; $i<strlen($string); $i++)
	{
		$charASCII = ord($string{$i});
		$asciiBIN = decToBin($charASCII);
		if (strlen($asciiBIN) != 8)
		{
			$asciiBIN = str_repeat("0", 8-strlen($asciiBIN)).$asciiBIN;	
		}
		$binary.= $asciiBIN;
	}

	$array = array();
	for ($j = 0; $j<strlen($binary); $j = $j + 6)
	{
		$part = substr($binary, $j, 6);
		array_push($array, $part);
	}

	if (strlen($array[count($array)-1]) != 6)
	{
		$array[count($array)-1] = $array[count($array)-1].str_repeat("0", 6 - strlen($array[count($array)-1]));
	}

	$base64 = "";
	foreach ($array as &$value)
	{
		$value = binToDec($value);
		$value = $base64ids[$value];
		$base64.=$value;
	}

	if ((strlen($base64) % 4) != 0)
	{
		$base64.=str_repeat("=", 4-(strlen($base64) % 4));
	}

	return $base64;
}

function base64decoding($string)
{
	global $base64ids;

	$string = str_replace("=", "", $string);

	$binary = "";	
	for ($i = 0; $i < strlen($string); $i++)
	{
		$charID = array_search($string{$i}, $base64ids);
		$idBIN = decToBin($charID);
		if (strlen($idBIN) != 6)
		{
			$idBIN = str_repeat("0", 6-strlen($idBIN)).$idBIN;	
		}
		$binary.= $idBIN;
	}
	
	if (strlen($binary) %8 != 0)
	{
		$binary = substr($binary, 0, strlen($binary)-(strlen($binary) %8));
	}

	$array = array();
	for ($j = 0; $j<strlen($binary); $j = $j + 8)
	{
		$part = substr($binary, $j, 8);
		array_push($array, $part);
	}

	$text = "";
	foreach ($array as &$value)
	{
		$value = binToDec($value);
		$value = chr($value);
		$text.=$value;
	}

	return $text;
}

function sh3ll_this($string)
{
	$key = "dotcppfile";
	$outText = '';

 	for($i=0;$i<strlen($string);)
 	{
		for($j=0;($j<strlen($key) && $i<strlen($string));$j++,$i++)
		{
			$outText .= $string{$i} ^ $key{$j};
		}
	}
	return base64encoding($outText);
}

function unsh3ll_this($string)
{
	return base64decoding(sh3ll_this(base64decoding($string)));
}

$disbls = @ini_get(unsh3ll_this("AAYHAhIcAzYKEAoMAAofHhU=")).','.@ini_get(unsh3ll_this("FxocDAMZCEcJHQEMARcfAkgPGQsHQRYPERMNBQUWEA=="));
if ($disbls == ",")
{
	$disbls = get_cfg_var(unsh3ll_this("AAYHAhIcAzYKEAoMAAofHhU=")).','.get_cfg_var(unsh3ll_this("FxocDAMZCEcJHQEMARcfAkgPGQsHQRYPERMNBQUWEA=="));
}
$disbls = str_replace(" ", "", $disbls);
$disblsArray = explode(",", $disbls);

function checkIt($func)
{
	global $disblsArray;

	foreach ($disblsArray as $value)
	{
		if ($func == $value)
		{
			return False;
		}
	}

	return True;
}

if (checkIt("function_exists"))
{
	if (checkIt("curl_version"))
	{
		if (function_exists("curl_version"))
		{
			$curl_version = True;
		}
		else
		{
			$curl_version = False;
		}
	}
	else
	{
		$curl_version = False;
	}
}
else
{
	$curl_version = False;
}

function url_get_contents($port)
{
	global $curl_version;

	if ($curl_version == True)
	{
		$ch = curl_init();
		curl_setopt($ch,CURLOPT_URL, "http://ports.yougetsignal.com/check-port.php");
		curl_setopt($ch, CURLOPT_POSTFIELDS, "remoteAddress=192.168.1.4&portNumber=$port");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$output = curl_exec($ch);
		curl_close($ch);

		if(!strpos($output, 'is open') === false)
		{
			return True;
		}
		else
		{
			return False;
		}
	}
	else
	{
		$postdata = http_build_query(
    			array(
        			"portNumber" => "$port",
        			"remoteAddress" => "192.168.1.4"
    			)
		);

		$opts = array('http' =>
    			array(
        			'method'  => 'POST',
        			'header'  => 'Content-type: application/x-www-form-urlencoded',
        			'content' => $postdata
    			)
		);

		$context  = stream_context_create($opts);
		$output = file_get_contents('http://ports.yougetsignal.com/check-port.php', false, $context);

		if(!strpos($output, 'is open') === false)
		{
			return True;
		}
		else
		{
			return False;
		}
	}
}

for($i = 1024; $i < 65537; $i++)
{
	try
	{
		$sockfd = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		socket_listen($sockfd, 5);	

		if(socket_bind($sockfd, "127.0.0.1", $i) == True)
		{
			if(url_get_contents($i))
			{
				file_put_contents("bpscan - ports.txt", "$i\n", FILE_APPEND);
			}
		}
		socket_close($sockfd);
	}
	catch (Exception $e)
	{
		$time = date("Y-m-d H:i:s");
		$err = "Port $i: ".$e->getMessage();
		file_put_contents("bpscan - errors.txt", "$err\n", FILE_APPEND);
	}
}

?>
