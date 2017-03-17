#------------------------------------------------------------------------
# Project Names
#------------------------------------------------------------------------
PROJ := Cache Leak Detector - Target Program
EXECNAME := target

#------------------------------------------------------------------------
# Compiler Flags
#------------------------------------------------------------------------
CC := gcc
CFLAGS := -g -O2 -Wall -Werror -std=gnu11
INCLUDE := -I.
LIBS := -lpthread -lcrypto

#------------------------------------------------------------------------
# Files/Directories
#------------------------------------------------------------------------
BINDIR := bin
OBJECTS := $(patsubst %.c,$(BINDIR)/%.o,$(wildcard *.c))

#------------------------------------------------------------------------
# Main Targets
#------------------------------------------------------------------------
.PHONY: all 

all: output $(OBJECTS) $(BINDIR)/$(EXECNAME)

output:
	mkdir -p $(BINDIR)

clean:
	-$(RM) -r $(BINDIR)

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Compile the project."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up the project."
	@echo

#------------------------------------------------------------------------
# Sub-Targets
#------------------------------------------------------------------------

# build objects
$(BINDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

# build executable
$(BINDIR)/$(EXECNAME): $(OBJECTS)
	$(CC) -o $(BINDIR)/$(EXECNAME) $(OBJECTS) $(LIBS)

