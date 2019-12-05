#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#include <openssl/sha.h>
#include <checksum.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <custom_structs.h>
#include <stdint.h>

#pragma warning(disable:4996) 

unsigned int curr_seq_ID = 0;
U_CHAR client_ID = 0;

PACKETS_INFO  get_info_client(unsigned int size) {
	PACKETS_INFO  pack;
	pack.num_whole_Packets = size / DATA_LEN;
	pack.bytes_in_last_Packet = size % DATA_LEN;
	return pack;
}


void mirror_buffer(U_CHAR* buf, size_t len_buf) {
	char tmp_buf[4];
	memcpy(tmp_buf, buf, len_buf);

	for (int i = 0; i < len_buf; ++i) {
		buf[i] = tmp_buf[(len_buf-1) - i];
	}
}

void get_dec_in_256base(unsigned int num, U_CHAR* buf, unsigned int len_buf){
	memset(buf, 0, len_buf);
	int i = 0;
	while (num) {
		buf[i++] = num % 256;
		num = num / 256;
	}
	mirror_buffer(buf, len_buf);
}


// calc CRC of the given buffer
void get_CRC(U_CHAR* buf, size_t len_buf, U_CHAR* ret_buf) {
	memset(ret_buf, 0, CRC_LEN);
	uint64_t crc_val = crc_64_ecma(buf, len_buf + ID_LEN + IDS_LEN);	// involves ID
	U_CHAR* p = &crc_val;
	memcpy(ret_buf, p, CRC_LEN);
	mirror_buffer(ret_buf, CRC_LEN);
}

// len_buf is here the whole length of the UDP data packet, so even ID and CRC
bool check_CRC(U_CHAR* buf, size_t len_buf) {
	bool ret = false;
	uint64_t crc_val = crc_64_ecma(buf, len_buf - CRC_LEN);
	if (!crc_val) {
		ret = true;
	}
	return ret;
}

void append_comps(U_CHAR* buf, size_t len_buf){
	// append ID of the current packet sent
	U_CHAR ID_buf[ID_LEN];
	get_dec_in_256base(curr_seq_ID++, ID_buf, ID_LEN);
	memcpy(&buf[len_buf], ID_buf, ID_LEN);

	// append ID of the client
	buf[len_buf + ID_LEN] = client_ID;

	// append CRC of the packet
	U_CHAR CRC_buf[CRC_LEN];
	get_CRC(buf, len_buf,CRC_buf);
	memcpy(&buf[len_buf + ID_LEN + IDS_LEN], CRC_buf, CRC_LEN);
}


//-----------------------------------------------------------------------------------------------------------------------
// sizeof_buf is here only the length of the data in the UDP data packet, so no ID, IDS or CRC
void send_packet(sockets_t client_sock, U_CHAR* buf, int sizeof_buf, sockets_info_t *client_info, sockets_info_t *server_info){
	int ret = sendto(client_sock.data, buf, sizeof_buf + ID_LEN + IDS_LEN + CRC_LEN, 0, (SOCKADDR*)&(server_info->data), sizeof(SOCKADDR_IN));	// send the packet 1st time
	if (ret < 0) {
		return false;
	}

	fd_set rset;
	int nready, nBytesRecv = 0, nClient_ack = sizeof(SOCKADDR_IN);
	U_CHAR Buffer_Rec[512] = "";
	bool CRC_check = false;
	bool ID_check = false;
	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	FD_ZERO(&rset);
	FD_SET(client_sock.ack, &rset);
	while (1) {
		nready = select(client_sock.ack, &rset, NULL, NULL, &timeout);	// wait till receive or timeout
		if(FD_ISSET(client_sock.ack, &rset)){	// if received
			nBytesRecv = recvfrom(client_sock.ack, Buffer_Rec, sizeof(Buffer_Rec), 0, (SOCKADDR*)&(client_info->ack), &nClient_ack);
			int iSocketError = WSAGetLastError();	
			if(iSocketError == 10054){
				printf("Port unreachable!\n");
				exit(1);
			}
			CRC_check = check_CRC(Buffer_Rec, nBytesRecv);
			if ((!CRC_check) && (!memcmp(Buffer_Rec, "Packet received!", PACK_REC_LEN))) {
				curr_seq_ID++;
				break;
			}
			// else send again
		}
		printf("Timeout\n");	// if timeout happened, send packet again
		sendto(client_sock.data, buf, sizeof_buf + ID_LEN + IDS_LEN + CRC_LEN, 0, (SOCKADDR*) & (server_info->data), sizeof(SOCKADDR_IN));
		FD_ZERO(&rset);
		FD_SET(client_sock.ack, &rset);
	}
}



int main() {
	printf("UDP Client started up\n");
	// Initialize WSADATA
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		printf("WSAStartup failed: %d\n", res);
		return 1;
	}
	printf("WSAStartup succeeded\n");

	sockets_t client_sock;

	// Create sockets
	client_sock.data = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	client_sock.ack = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	// Check to see if we have a valid socket
	if ((client_sock.data == INVALID_SOCKET) || (client_sock.ack == INVALID_SOCKET)) {
		int iSocketError = WSAGetLastError();
		printf("WSALastError: %d\n", iSocketError);
		WSACleanup();
		return 100;
	}

	// Create structure for handling internet address
	sockets_info_t client_info;
	sockets_info_t server_info;

	memset(&client_info.data, 0, sizeof(SOCKADDR_IN));
	memset(&client_info.ack, 0, sizeof(SOCKADDR_IN));
	memset(&server_info.data, 0, sizeof(SOCKADDR_IN));
	memset(&server_info.ack, 0, sizeof(SOCKADDR_IN));

	client_info.data.sin_family = AF_INET;
	client_info.data.sin_port = htons(CLIENT_DATA_PORT);
	inet_pton(AF_INET, "192.168.43.208", &client_info.data.sin_addr);
	printf("Address family: %d\nIP address of server: %d\nServer port number: %d\n", client_info.data.sin_family, htonl(client_info.data.sin_addr.s_addr), htons(client_info.data.sin_port));

	client_info.ack.sin_family = AF_INET;
	client_info.ack.sin_port = htons(CLIENT_ACK_PORT);
	inet_pton(AF_INET, "127.0.0.1", &client_info.ack.sin_addr);
	printf("Address family: %d\nIP address of server: %d\nServer port number: %d\n", client_info.ack.sin_family, htonl(client_info.ack.sin_addr.s_addr), htons(client_info.ack.sin_port));

	server_info.data.sin_family = AF_INET;
	server_info.data.sin_port = htons(SERVER_DATA_PORT);
	inet_pton(AF_INET, "127.0.0.1", &server_info.data.sin_addr);
	printf("Address family: %d\nIP address of server: %d\nServer port number: %d\n", server_info.data.sin_family, htonl(server_info.data.sin_addr.s_addr), htons(server_info.data.sin_port));

	server_info.ack.sin_family = AF_INET;
	server_info.ack.sin_port = htons(SERVER_ACK_PORT);
	inet_pton(AF_INET, "127.0.0.1", &server_info.ack.sin_addr);
	printf("Address family: %d\nIP address of server: %d\nServer port number: %d\n", server_info.ack.sin_family, htonl(server_info.ack.sin_addr.s_addr), htons(server_info.ack.sin_port));


	// Define buffers
	U_CHAR Buffer_Name[DATA_LEN] = "";	// the size of the name + file type will never exceed 952B
	U_CHAR digest[SHA512_DIGEST_LENGTH] = { 0 };
	U_CHAR Buffer_Path[PATH_SENT_LEN + DATA_LEN] = "C:\\KDS\\KDS\\Sent_files\\";
	U_CHAR* Buffer_Send;

	// Define number vals
	int sizeof_name = 0;
	int sizeof_size = 0;
	char c = 0;
	PACKETS_INFO p_info;
	int i;

	SHA512_CTX ctx;
	SHA512_Init(&ctx);

	FILE* fptr, *wptr;

	while (1) {
		c = getc(stdin);
		if (c == 's') {
			printf("Write source file\n");
			scanf("%s", Buffer_Name);
			printf("%s\n", Buffer_Name);
			memcpy(&Buffer_Path[PATH_SENT_LEN], Buffer_Name, strlen(Buffer_Name));
			printf("%s\n", Buffer_Path);
			fptr = fopen(Buffer_Path, "rb");
			if (fptr == NULL) {
				printf("Couldn't open the file, error is: %s\n", strerror(errno));
			}

			fseek(fptr, 0, SEEK_END);
			unsigned int length = ftell(fptr);
			rewind(fptr);
			char* file_data = (char*)malloc((length) * sizeof(char));
			length = fread(file_data, 1, length, fptr);

			// calc hash
			SHA512_Update(&ctx, file_data, length);
			SHA512_Final(digest, &ctx);
			
			// send packet with the name
			Buffer_Send = calloc(sizeof_name + ID_LEN + IDS_LEN + CRC_LEN, sizeof(U_CHAR));
			append_comps(Buffer_Send, sizeof_name);
			send_packet(client_sock, Buffer_Send, sizeof_name, &client_info, &server_info);
			free(Buffer_Send);

			// send packet with the size (num of bytes)
			Buffer_Send = calloc(SIZE_LEN + ID_LEN + IDS_LEN + CRC_LEN, sizeof(U_CHAR));
			get_dec_in_256base(length, Buffer_Send, SIZE_LEN);
			append_comps(Buffer_Send, SIZE_LEN);
			send_packet(client_sock, Buffer_Send, SIZE_LEN, &client_info, &server_info);
			free(Buffer_Send);

			p_info = get_info_client(length);

			// send packets with the data
			for (i = 0; i < p_info.num_whole_Packets; ++i) {
				Buffer_Send = calloc(DATA_LEN + ID_LEN + IDS_LEN + CRC_LEN, sizeof(U_CHAR));
				memcpy(Buffer_Send, &file_data[i * DATA_LEN], DATA_LEN);
				append_comps(Buffer_Send, DATA_LEN);
				send_packet(client_sock, Buffer_Send, DATA_LEN, &client_info, &server_info);
				free(Buffer_Send);
			}
			if(p_info.bytes_in_last_Packet > 0){
				Buffer_Send = calloc(p_info.bytes_in_last_Packet + ID_LEN + IDS_LEN + CRC_LEN, sizeof(U_CHAR));
				memcpy(Buffer_Send, &file_data[i * DATA_LEN], p_info.bytes_in_last_Packet);
				append_comps(Buffer_Send, p_info.bytes_in_last_Packet);
				send_packet(client_sock, Buffer_Send, p_info.bytes_in_last_Packet, &client_info, &server_info);
				free(Buffer_Send);
			}

			// send packet with hash
			Buffer_Send = calloc(SHA512_DIGEST_LENGTH + ID_LEN + IDS_LEN + CRC_LEN, sizeof(U_CHAR));
			memcpy(Buffer_Send, digest, SHA512_DIGEST_LENGTH);
			append_comps(Buffer_Send, SHA512_DIGEST_LENGTH);
			send_packet(client_sock, Buffer_Send, SHA512_DIGEST_LENGTH, &client_info, &server_info);
			free(Buffer_Send);
			curr_seq_ID = 0;
		}
	}
	
	fclose(fptr);
	// Close the socket
	closesocket(client_sock.data);
	closesocket(client_sock.ack);
	WSACleanup();
	return 0;
}
