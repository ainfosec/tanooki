CC=gcc
CFLAGS=-I. -g -Wall

SRCDIR  = src
LIB = ./$(SRCDIR)/lib
LINK = -lelf -lbele

SRC  := $(wildcard $(SRCDIR)/*.c)
OBJ  := $(patsubst $(SRCDIR)/%.c, $(SRCDIR)/%.o, $(SRC))

TARGET = spy 

default: $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) -L $(LIB) $(LINK)

lib: 
	cd $(SRCDIR)/lib && make 

.PHONY: clean lib libclean libnuke libclean remove

remove: 
	rm -f $(TARGET)

libclean: 
	cd $(LIB) && make clean 

libnuke: 
	cd $(LIB) && make nuke 

clean: 
	cd $(SRCDIR) && rm -f *.o

cleanall:clean libclean

nuke: clean libnuke
