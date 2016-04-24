CC = gcc
CFLAGS = -pthread
all: WDSServer

WDSServer: clean config Main.o WDS.o WDS_FileIO.o WDS_Request.o WDS_NTLM.o WDS_Socket.o WDS_RIS.o
	$(CC) $(CFLAGS) Main.o WDS.o WDS_RIS.o WDS_FileIO.o WDS_Request.o WDS_NTLM.o WDS_Socket.o -o WDSServer

main.o: Main.c
	$(CC) $(CFLAGS) -c Main.c

WDS.o: WDS.c
	$(CC) $(CFLAGS) -c WDS.c

WDS_FileIO.o: WDS_FileIO.c
	$(CC) $(CFLAGS) -c WDS_FileIO.c

WDS_RIS.o: WDS_RIS.c
	$(CC) $(CFLAGS) -c WDS_RIS.c

WDS_Request.o: WDS_Request.c
	$(CC) $(CFLAGS) -c WDS_Request.c

WDS_NTLM.o: WDS_NTLM.c
	$(CC) $(CFLAGS) -c WDS_NTLM.c

WDS_Socket.o: WDS_Socket.c
	$(CC) $(CFLAGS) -c WDS_Socket.c

clean:
	rm -rf *.o WDSServer

config:
	cp cfg/*.txt ./
