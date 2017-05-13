##
## This is a sample makefile for building Pin tools outside
## of the Pin environment.  This makefile is suitable for
## building with the Pin kit, not a Pin source development tree.
##
## To build the tool, execute the make command:
##
##      make
## or
##      make PIN_HOME=<top-level directory where Pin was installed>
##
## After building your tool, you would invoke Pin like this:
## 
##      $PIN_HOME/pin -t MyPinTool -- /bin/ls
##
##############################################################
#
# User-specific configuration
#
##############################################################

#
# 1. Change PIN_HOME to point to the top-level directory where
#    Pin was installed. This can also be set on the command line,
#    or as an environment variable.
#
PIN_HOME ?= ../../..


##############################################################
#
# set up and include *.config files
#
##############################################################

PIN_KIT=$(PIN_HOME)
KIT=1
TESTAPP=$(OBJDIR)cp-pin.exe

TARGET_COMPILER?=gnu
ifdef OS
    ifeq (${OS},Windows_NT)
        TARGET_COMPILER=ms
    endif
endif

ifeq ($(TARGET_COMPILER),gnu)
    include $(PIN_HOME)/source/tools/makefile.gnu.config
    CXXFLAGS ?= -Wall -Wno-unknown-pragmas $(DBG) $(OPT)
    PIN=$(PIN_HOME)/pin
endif

ifeq ($(TARGET_COMPILER),ms)
    include $(PIN_HOME)/source/tools/makefile.ms.config
    DBG?=
    PIN=$(PIN_HOME)/pin.bat
endif


##############################################################
#
# Tools - you may wish to add your tool name to TOOL_ROOTS
#
##############################################################


TOOL_ROOTS = Sjudge

TOOLS = $(TOOL_ROOTS:%=$(OBJDIR)%$(PINTOOL_SUFFIX))
$(info $$LINK_OUT is [${LINK_OUT}])
HEADERS = CacheSimulation.h Handlers.h InsCounter.h Sjudge.h supervisor.h
CPPSRC = $(wildcard *.cpp)
CSRC = $(wildcard *.c)

##############################################################
#
# build rules
#
##############################################################

all: tools
tools: $(OBJDIR) $(TOOLS) $(OBJDIR)cp-pin.exe
test: $(OBJDIR) $(TOOL_ROOTS:%=%.test)

MyPinTool.test: $(OBJDIR)cp-pin.exe
	$(MAKE) -k PIN_HOME=$(PIN_HOME)

$(OBJDIR)cp-pin.exe:
	$(CXX) $(PIN_HOME)/source/tools/Tests/cp-pin.cpp $(APP_CXXFLAGS) -o $(OBJDIR)cp-pin.exe
$(OBJDIR)%.h:
    $(test)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)%.o : %.cpp
	$(CXX) -c $(CXXFLAGS) -I./ $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(OBJDIR)%.o : %.c
	$(CC) -c $(CXXFLAGS) -I./ $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(TOOLS): $(PIN_LIBNAMES)

$(TOOLS): $(CPPSRC:%.cpp=$(OBJDIR)%.o) $(CSRC:%.c=$(OBJDIR)%.o) $(HEADERS)
	${PIN_LD} $(PIN_LDFLAGS) -Wl,--no-undefined $(LINK_DEBUG) ${LINK_OUT}$@ $(CPPSRC:%.cpp=$(OBJDIR)%.o) $(CSRC:%.c=$(OBJDIR)%.o) ${PIN_LPATHS} $(PIN_LIBS) $(DBG)


## cleaning
clean:
	-rm -rf $(OBJDIR)*.o
