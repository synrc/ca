rem PS C:\Users\maxim\Downloads> ./p10cr-win.ps1 2>null

c:\Progra~1\OpenSSL-Win64\bin\openssl.exe ecparam -name secp384r1 -genkey | Out-File -Encoding utf8 "1.txt"
c:\Progra~1\OpenSSL-Win64\bin\openssl.exe req -passout pass:0 -new -key 1.txt -keyout dima.key.enc -out dima.csr -subj "/C=FI/ST=Helsinki/O=AR.VO/CN=Dima"
c:\Progra~1\OpenSSL-Win64/bin/openssl.exe cmp -cmd p10cr -server http://ca.synrc.com:8829/ -secret pass:0000 -ref cmptestp10cr -certout dima.pem -csr dima.csr
