all: mifarecrack

.PONHY: clean

clean:
	rm mifarecrack
mifarecrack: crapto1.c crypto1.c mifarecrack.c
	gcc -O3 -o mifarecrack crapto1.c crypto1.c mifarecrack.c
