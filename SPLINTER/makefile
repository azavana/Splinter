Main.exe: Functions.o Main.o
		gcc Main.o Functions.o -o Main.exe -I. -lcrypto
Main.o: Main.c Header.h
		gcc -c -I. Main.c -lcrypto
Functions.o: Functions.c
		gcc -c -I. Functions.c -lcrypto
