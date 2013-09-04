CC=gcc
CFLAGS=-O2 -Wall

.PHONY: all
all: caretaker

caretaker: caretaker.o syscall_listener.o
	$(CC) $(CFLAGS) caretaker.o syscall_listener.o -o caretaker

caretaker.o: caretaker.c exit_code.h syscall_listener.h
	$(CC) $(CFLAGS) -c caretaker.c

syscall_listener.o: syscall_listener.c exit_code.h syscall_listener.h
	$(CC) $(CFLAGS) -c syscall_listener.c

.PHONY: clean
clean:
	rm *.o caretaker
