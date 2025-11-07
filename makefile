CC = gcc
CFLAGS = -Iinclude -Wall
LDFLAGS = -lssl -lcrypto

SRC = ledger.c monitor.c
OBJ = $(SRC:.c=.o)
TARGET = secureledger

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del $(OBJ) $(TARGET).exe

