FILES = main.c

MAIN = SuricataC
CC = gcc
CFLAGS = -ggdb -O0 -Wall
LFLAGS = 
INCLUDES = 
LIBS =
OBJS = $(FILES:.c=.o)

SuricataC: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@
