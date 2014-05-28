
SERVER_OBJS=server.o proj_info.o utils.o buffer.o db_support.o client.o cli_mgr.o basic_mgr.o clientset.o projectmap.o mgr_helper.o
MGR_OBJS=server_mgr.o proj_info.o utils.o buffer.o

CC=g++
LD=g++

CFLAGS = -fno-rtti

#Print error messages
#CFLAGS += -DDEBUG
#NDEBUG=-D DEBUG

#need the following when using threads
EXTRALIBS=-lpthread -lpq -lcrypto

#use the following to strip your binary
#LDFLAGS=-s

all: collab collab_mgr

collab: $(SERVER_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(EXTRALIBS) 

collab_mgr: $(MGR_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(MGR_OBJS) $(EXTRALIBS) 

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean:
	-@rm *.o

