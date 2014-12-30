CC_FLAGS=-std=c99 -O3 -Wall
AES_NI=-maes -mssse3 -D__USE_AES_NI
x64=-D__ARCH_64
LINK_AES=rijndael-alg-fst.o 
NOLINK_AES=

MODDE=
LINK=$(LINK_AES)

ifeq ($(arch), aes-ni)
  MODE=$(AES_NI)
  LINK=$(NOLINK_AES)
endif

ifeq ($(arch), x64)
  MODE=$(x64)
endif

bm: bm.c aez.o
	gcc $(CC_FLAGS) $(MODE) bm.c aez.o $(LINK)-o bm

aez.o: rijndael-alg-fst.o aez.h aez.c
	gcc $(CC_FLAGS) $(MODE) -c aez.c 

libaez.so: rijndael-alg-fst.o aez.h aez.c
	gcc $(CC_FLAGS) $(MODE) -fpic -c aez.c 
	gcc -shared -o libaez.so aez.o $(LINK)

rijndael-alg-fst.o: rijndael-alg-fst.h rijndael-alg-fst.c
	gcc $(CC_FLAGS) -fpic -c rijndael-alg-fst.c

clean: 
	rm -fr *.o *.so bm
