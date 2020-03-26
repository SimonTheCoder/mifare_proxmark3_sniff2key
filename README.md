Calculate the card key using  <UID> <TAG CHALLENGE> <READER CHALLENGE> 
<READERRESPONSE> <TAG RESPONSE> from sniff tracing. 
All sources are copied from repos
below.

Source files are from:
1: http://www.proxmark.org/files/Various%20Software/MIFARE%20Classic/mifarecrack/
2: https://github.com/nfc-tools/mfcuk/tree/master/src


build:
make

Tips:
1: generate trace file:
proxmark3> hf list 14a -s ./trace.txt

Refs:
http://www.proxmark.org/
https://github.com/Proxmark/proxmark3
https://github.com/nfc-tools/mfcuk
