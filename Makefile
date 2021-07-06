all: clean pwordman

.PHONY: clean
clean: pwordman.c pwordman.h
	rm -rf pwordman *.o 

.PHONY: pwordman
pwordman: pwordman.c pwordman.h
	gcc pwordman.c -lssl -lcrypto -o pwordman