SRCS=machhelper.c
DYLIB=machhelper.dylib

all:
	gcc -dynamiclib -arch i386 -arch x86_64 ${SRCS} -o ${DYLIB}

clean:
	rm -rf ${DYLIB}
