# Last modified 29 Dec 2014. 

CC_FLAGS=-std=c99 -O3 -Wall
AES_NI=-maes -mssse3 -D__USE_AES_NI
x64=-D__ARCH_64
LINK_AES=rijndael-alg-fst.o 
NOLINK_AES=

MODE=
LINK=$(LINK_AES)

ifeq ($(arch), aes-ni)
  MODE=$(AES_NI)
  LINK=$(NOLINK_AES)
endif

ifeq ($(arch), x64)
  MODE=$(x64)
endif

lib: $(LINK) aez.h aez.c
	gcc $(CC_FLAGS) $(MODE) -fpic -c aez.c 
	gcc -shared -o libaez.so aez.o $(LINK)

bm: bm.c aez.o
	gcc $(CC_FLAGS) $(MODE) bm.c aez.o $(LINK)-o bm

aez.o: $(LINK) aez.h aez.c
	gcc $(CC_FLAGS) $(MODE) -c aez.c 

rijndael-alg-fst.o: rijndael-alg-fst.h rijndael-alg-fst.c
	gcc $(CC_FLAGS) -fpic -c rijndael-alg-fst.c

clean: 
	rm -fr *.o *.so bm build/ *.pyc
