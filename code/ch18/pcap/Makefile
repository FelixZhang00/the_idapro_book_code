#Set this variable to point to your SDK directory
IDA=../../

#Set this variable to the desired name of your compiled loader
PROC=pcap_loader

ifndef __LINUX__
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -mno-cygwin
PLATFORM_LDFLAGS=--dll -mno-cygwin
IDALIB=$(IDA)libgcc.w32/ida.a
LOADER_EXT=.ldw
else
PLATFORM_CFLAGS=-D__LINUX__
IDALIB=$(IDA)libgcc32.lnx/pro.a
LOADER_EXT=.llx
endif

#Platform specific compiler flags
CFLAGS=-Wextra $(PLATFORM_CFLAGS)

#Platform specific ld flags
LDFLAGS=-Wl -shared -s $(PLATFORM_LDFLAGS) 

#specify any additional libraries that you may need
EXTRALIBS=

# Destination directory for compiled plugins
OUTDIR=$(IDA)bin/loaders/

#list out the object files in your project here
OBJS=pcap_loader.o

BINARY=$(OUTDIR)$(PROC)$(LOADER_EXT)

all: $(OUTDIR) $(BINARY)

clean:
	-@rm *.o
	-@rm $(BINARY)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

CC=g++
INC=-I$(IDA)include/

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

LD=g++

$(BINARY): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(IDALIB) $(EXTRALIBS) 

#change pcap_loader below to the name of your loader, make sure to add any 
#additional files that your loader is dependent on
pcap_loader.o: pcap_loader.cpp
