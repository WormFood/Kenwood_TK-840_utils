CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

PROGRAMS = tk840download tk840upload tk941patch

.PHONY: all clean

all: $(PROGRAMS)

tk840download: tk840download.c
	$(CC) $(CFLAGS) -o $@ $<

tk840upload: tk840upload.c
	$(CC) $(CFLAGS) -o $@ $<

tk941patch: tk941patch.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)
