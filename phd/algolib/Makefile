# Nome dell'eseguibile
TARGET = programma

# Compilatore
CC = gcc

# Flag di compilazione
CFLAGS = -Wall -Wextra 

# File oggetto
OBJ = main.o libac.o

# Regola principale
all: $(TARGET)

# Link finale
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

# Compilazione dei singoli file
main.o: main.c algo-ac.h
	$(CC) $(CFLAGS) -c main.c

libac.o: algo-ac.c algo-ac.h
	$(CC) $(CFLAGS) -c algo-ac.c -o libac.o

# Pulizia
clean:
	rm -f $(OBJ) $(TARGET)
