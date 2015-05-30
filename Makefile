CC = gcc
CFLAGS = -static
all: WDSServer

WDSServer: clean Main.o WDS.o WDS_FileIO.o WDS_Request.o WDS_Socket.o WDS_RIS.o
	$(CC) Main.o WDS.o WDS_RIS.o WDS_FileIO.o WDS_Request.o WDS_Socket.o -o WDSServer
	cp cfg/*.txt ./

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

WDS_Socket.o: WDS_Socket.c
	$(CC) $(CFLAGS) -c WDS_Socket.c

clean:
	rm -rf *.o WDSServer
