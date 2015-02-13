@echo off

echo Content-type: text/html
echo.

if NOT "%QUERY_STRING%" == ""
(
	if exist decode.txt del decode.txt
	(echo %QUERY_STRING:~8%) > encoded.txt
	certutil -decode "encoded.txt" "decode.txt"
	if exist decode.txt
	(
		type decode.txt 
	)
)
