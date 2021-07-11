all: clean pwm_crypto.o pwordman.o pwordman

.PHONY: clean 
clean: cryptoclean pwordmanclean 

.PHONY: cryptoclean 
cryptoclean:
	-rm -f pwm_crypto.o 

.PHONY: pwordmanclean
pwordmanclean: 
	-rm -f pwordman.o pwordman

pwordman: pwordman.o 
	gcc -lssl -lcrypto -lm -o pwordman pwordman.o pwm_crypto.o

pwordman.o:
	gcc -lssl -lcrypto -lm -Wall -pedantic -std=gnu99 -g -c pwordman.c 

pwm_crypto.p:
	gcc -lssl -lcrypto -lm -Wall -pedantic -std=gnu99 -g -c pwm_crypto.c 
