# makefile for pwnedCheck
#
# set these to reflect your setup
#
PWNED_DATA = ./pwned-passwords-ordered-by-hash.txt

ifndef C_SRC
C_SRC=.
endif

ifndef INST_BIN
INST_BIN=/usr/local/bin
endif

ifndef TEST_BIN
TEST_BIN=./
endif

#
CC      = cc
CFLAGS  = $(DCFLAGS) -std=c99 -Wall -I. -DINFOMSGS -D_FILE_OFFSET_BITS=64
#
LD=cc 
LDFLAGS += -lc $(DLDFLAGS)
LOPTS= -lm
O=o

.SUFFIXES:
.SUFFIXES: .c .o

%.$O : %.c
	$(CC) $(CFLAGS) -c $<

% : %.$O
	$(LD) $(LDFLAGS) -o $@ $^

C_PGMS  := pwnedCheck 

# ########################################################################

all: $(C_PGMS)

# Compile ################################################################

pwnedCheck.$O: pwnedCheck.c pwnedCheck.h sha1.c sha1.h

sha1.$O:  sha1.c sha1.h

# Link ################################################################

pwnedCheck: pwnedCheck.$O sha1.$O

# Install ################################################################

install: 
	@for file in $(C_PGMS); do      \
	    if [[ $(C_SRC)/$$file -nt $(INST_BIN)/$$file ]]; then sudo cp $(C_SRC)/$$file $(INST_BIN); fi  \
	done;

# Tests   ################################################################
define unit_test
	@printf "Testng %s.... " "$(2)"
	@if [ `$(TEST_BIN)/pwnedCheck $(1) $(2)` == $(3) ]; then echo "Pass"; else echo "Fail"; fi
endef

tests:
	$(call unit_test,-t -p $(PWNED_DATA),'#8&24',0)
	$(call unit_test,-t -p $(PWNED_DATA),cto,85)
	$(call unit_test,-t -p $(PWNED_DATA),123456,22390492)
	$(call unit_test,-t -p $(PWNED_DATA),-s "7C4A8D09CA3762AF61E59520943DC26494F8941B",22390492)
	$(call unit_test,-t -p $(PWNED_DATA),password,3533661)
	$(call unit_test,-t -p $(PWNED_DATA),-s 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8,3533661)
	# first record
	$(call unit_test,-t -p $(PWNED_DATA),-s 000000005AD76BD555C1D6D771DE417A4B87E4B4,4)
	# second record
	$(call unit_test,-t -p $(PWNED_DATA),-s 00000000A8DAE4228F821FB418F59826079BF368,2)
	# penultimate record
	$(call unit_test,-t -p $(PWNED_DATA),-s FFFFFFF8A0382AA9C8D9536EFBA77F261815334D,10)
	# last record
	$(call unit_test,-t -p $(PWNED_DATA),-s FFFFFFFEE791CBAC0F6305CAF0CEE06BBE131160,2)
	@printf "Testing password from stdin...."
	@if [ `printf "password" | $(TEST_BIN)/pwnedCheck -t -p $(PWNED_DATA)` == 3533661 ]; then echo "Pass"; else echo "Fail"; fi
	@printf "Testing hash from stdin...."
	@if [ `printf "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8" | $(TEST_BIN)/pwnedCheck -t -p $(PWNED_DATA) -s` == 3533661 ]; then echo "Pass"; else echo "Fail"; fi
	@printf "Testing invalid pwned filespec...."
	@$(TEST_BIN)/pwnedCheck -t -p /dev/null cto 2>/dev/null; if [ "$$?" != 0 ]; then echo "Pass"; else echo "Fail"; fi
	@printf "Testing invalid argument...."
	@$(TEST_BIN)/pwnedCheck -q -p $(PWNED_DATA) cto 2>/dev/null ; if [ "$$?" != 0 ]; then echo "Pass"; else echo "Fail"; fi
	@printf "Testing help message....\n\n"
	@$(TEST_BIN)/pwnedCheck -h -p $(PWNED_DATA) cto ; if [ "$$?" != 0 ]; then echo "Pass"; else echo "Fail"; fi


# Utils   ################################################################

clean:
	rm -f  *.$O 
	rm -f  *~
	rm -fR *.dSYM

spotless:
	rm -f $(C_PGMS)
	rm -f .\#*
	rm -f \#*\#
	rm -f .DS_Store
	make clean

dumpVars:
	echo "C_PGMS: $(C_PGMS)"

