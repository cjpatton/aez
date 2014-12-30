CC_FLAGS=-std=c99 -O3 -Wall
AES_NI_FLAGS=-maes -mssse3

bm: bm.c aez.o
	gcc $(CC_FLAGS) $(AES_NI_FLAGS) bm.c aez.o rijndael-alg-fst.o -o bm

aez.o: rijndael-alg-fst.o aez.h aez.c
	gcc $(CC_FLAGS) $(AES_NI_FLAGS) -c aez.c 

rijndael-alg-fst.o: rijndael-alg-fst.h rijndael-alg-fst.c
	gcc $(CC_FLAGS) -c rijndael-alg-fst.c

clean: 
	rm -fr *.o bm
