
SERVER_OBJS=server.o proj_info.o utils.o db_mgr.o client.o cli_mgr.o basic_mgr.o clientset.o projectmap.o mgr_helper.o
MGR_OBJS=server_mgr.o proj_info.o utils.o

CC=g++
LD=g++

CFLAGS = -fno-rtti -g

#Print error messages
CFLAGS += -DDEBUG
#NDEBUG=-D DEBUG

#need the following when using threads
EXTRALIBS=-lpthread -lpq -lcrypto -ljson-c

INC=-I/usr/include/json-c -I/usr/include/postgresql -I/usr/local/include/json-c

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
