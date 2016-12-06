#created by ljk<ljk@xdja.com>
ifndef CC
CC = gcc
endif
CFLAGS += -g -O0 -Wall -fPIC
CFLAGS += -D_DEBUG
CFLAGS += -I./
LDFLAGS += -L./ -lssl -lcrypto
LIBS += -ldl

SRCS += prf_hmac.c test.c

OBJS = $(SRCS:.c=.o)

TARGET = test

all : ${TARGET}
.PHONY : all

${TARGET} : ${OBJS}
	${CC} -o $@ $^ ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

.PHONY : clean
clean :
	rm -rf ${OBJS} ${TARGET}
