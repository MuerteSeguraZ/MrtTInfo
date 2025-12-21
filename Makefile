GCC := gcc
CFLAGS := -std=c11 -Wall -O2 -mconsole -lntdll
SOURCES := MrtTInfo.c main.c
OUTPUT := MrtTInfoTest.exe
.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	$(GCC) $(CFLAGS) $(SOURCES) -o $(OUTPUT) 

clean:
	del /Q *.exe *.o