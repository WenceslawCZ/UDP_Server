#ifndef HEADER_FILE
#define HEADER_FILE

#define CLIENT_DATA_PORT 55550
#define CLIENT_ACK_PORT 55551
#define SERVER_DATA_PORT 55555
#define SERVER_ACK_PORT 55556

#define CLIENT_ADDRESS "192.168.0.101"
#define SERVER_ADDRESS "192.168.0.103"

#define STR(x)   #x
#define SHOW_DEFINE(x) printf("%s=%s\n", #x, STR(x))
#define MAX_LEN 1024

#define DATA_LEN 1000
#define ID_LEN 4		// MAX num of data packets is 10^6, which can be easily expressed in 4 Bytes
#define IDS_LEN 1		// ID of individual clients
#define CRC_LEN 8

#define SIZE_LEN 5		// MAX size 1GB
#define PATH_SENT_LEN 22	
#define PATH_REC_LEN 21

#define PACK_REC_LEN 16
#define PACK_CORR_LEN 17

#define NUM_OF_CLIENTS 3

#define BUFLEN 944  // 1024B - 8B is the size of UDP header, - 64B is the size of CRC val, - 8B ID

typedef unsigned char U_CHAR;

typedef struct packets_info {
	unsigned int num_whole_Packets;
	unsigned int bytes_in_last_Packet;
}PACKETS_INFO;

typedef struct sockets {
	SOCKET data;
	SOCKET ack;
}sockets_t;

typedef struct sockets_info {
	SOCKADDR_IN data;
	SOCKADDR_IN ack;
}sockets_info_t;


#endif