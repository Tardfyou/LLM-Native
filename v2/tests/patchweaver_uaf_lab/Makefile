CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -g -I./include
OBJDIR := build
BINDIR := bin
TARGET := $(BINDIR)/uaf_lab

SRCS := src/main.c src/session_store.c src/request_router.c src/audit_log.c src/report_cache.c
OBJS := $(OBJDIR)/main.o $(OBJDIR)/session_store.o $(OBJDIR)/request_router.o $(OBJDIR)/audit_log.o $(OBJDIR)/report_cache.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

$(OBJDIR)/main.o: src/main.c include/request_router.h include/session_store.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/main.c -o $(OBJDIR)/main.o

$(OBJDIR)/session_store.o: src/session_store.c include/session_store.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/session_store.c -o $(OBJDIR)/session_store.o

$(OBJDIR)/request_router.o: src/request_router.c include/request_router.h include/session_store.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/request_router.c -o $(OBJDIR)/request_router.o

$(OBJDIR)/audit_log.o: src/audit_log.c include/request_router.h include/session_store.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/audit_log.c -o $(OBJDIR)/audit_log.o

$(OBJDIR)/report_cache.o: src/report_cache.c include/request_router.h include/session_store.h
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c src/report_cache.c -o $(OBJDIR)/report_cache.o

clean:
	rm -rf $(OBJDIR) $(BINDIR)
