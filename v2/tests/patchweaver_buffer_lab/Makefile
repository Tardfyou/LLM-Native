CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -g -I./include
OBJDIR := build
BINDIR := bin
TARGET := $(BINDIR)/buffer_lab

SRCS := src/main.c src/request_parser.c src/cache_serializer.c
OBJS := $(OBJDIR)/main.o $(OBJDIR)/request_parser.o $(OBJDIR)/cache_serializer.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

$(OBJDIR)/main.o: src/main.c include/request_parser.h include/cache_serializer.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/main.c -o $(OBJDIR)/main.o

$(OBJDIR)/request_parser.o: src/request_parser.c include/request_parser.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/request_parser.c -o $(OBJDIR)/request_parser.o

$(OBJDIR)/cache_serializer.o: src/cache_serializer.c include/cache_serializer.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/cache_serializer.c -o $(OBJDIR)/cache_serializer.o

clean:
	rm -rf $(OBJDIR) $(BINDIR)
