#
# Makefile
#
# Description:
# 	Script for code compilation. 
#

EXEC_NAME=packet_injector

REMOTE_PATH=injector/

CC_FILES=packet_injector.c 

CC_FLAGS=-Wall -Wextra -Werror 

LD_LIBS_PATH= -L.
LD_LIBS= -lpcap

all: main debug 
main: $(CC_FILES)
	gcc $(CC_FLAGS) -o $(EXEC_NAME) $(CC_FILES) $(LD_LIBS_PATH) $(LD_LIBS) 

debug: $(CC_FILES)
	gcc $(CC_FLAGS) -D__DEBUG__ -o $(EXEC_NAME)_debug $(CC_FILES) $(LD_LIBS_PATH) $(LD_LIBS)  
