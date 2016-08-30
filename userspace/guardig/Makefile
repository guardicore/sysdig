.PHONY: all clean

SRC_BASE = ../../../userspace
SRC_PATH = ${SRC_BASE}/guardig
INCLUDE = ${SRC_BASE}/libscap
SCAP_PATH = ../libscap
ZLIB_PATH = ../../zlib-prefix/src/zlib
FLAGS = -g -std=c++11

all: guardig
	@echo done

guardig:
	g++ ${FLAGS} -I${INCLUDE} ${SRC_PATH}/*.cpp -L${SCAP_PATH} -L${ZLIB_PATH} -lscap -lz -o guardig 

#guardig.o: guardig.c
#g++ -c -I${INCLUDE} ${SRC_PATH}/$< -o $@

clean:
	rm guardig