#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#include <custom_structs.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <checksum.h>
#include <stdint.h>
#include <math.h>
#pragma warning(disable:4996) 

//unsigned int curr_seq_ID = 0;
U_CHAR server_ID = 255;

unsigned int get_info_server(unsigned int size) {
	int val;
	val = size / DATA_LEN;
	if (size % DATA_LEN) {
		val++;
	}
	return val;
}

void mirror_buffer(U_CHAR* buf, unsigned int len_buf) {
	U_CHAR* tmp_buf = calloc(len_buf, sizeof(U_CHAR));
	memcpy(tmp_buf, buf, len_buf);

	for (int i = 0; i < len_buf; ++i) {
		buf[i] = tmp_buf[(len_buf - 1) - i];
	}
	free(tmp_buf);
}

void get_dec_in_256base(unsigned int num, U_CHAR* buf, unsigned int len_buf) {
	memset(buf, 0, len_buf);
	int i = 0;
	while (num) {
		buf[i++] = num % 256;
		num = num / 256;
	}
	mirror_buffer(buf, len_buf);
}

unsigned int get_256base_in_dec(U_CHAR* buf, unsigned int len_buf) {
	unsigned int num = 0;
	for(int i = len_buf-1; i >= 0; --i){
		num = num + pow(256, i) * buf[(len_buf - 1) - i];
	}
	return num;
}


// convert ID from int to base 256
void get_ID(U_CHAR* buf) {
	memset(buf, 0, ID_LEN);
	int num = 0, i = 0;
	while (num) {
		buf[i++] = num % 256;
		num = num / 256;
	}
	mirror_buffer(buf, ID_LEN);
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
	uint64_t crc_val = crc_64_ecma(buf, len_buf);
	if (!crc_val) {
		ret = true;
	}
	return ret;
}

void append_comps(U_CHAR* buf, size_t len_buf) {
	// append ID of the current packet sent
	U_CHAR ID_buf[ID_LEN];
	get_dec_in_256base(0, ID_buf, ID_LEN);
	memcpy(&buf[len_buf], ID_buf, ID_LEN);

	// append ID of the client
	buf[len_buf + ID_LEN] = server_ID;

	// append CRC of the packet
	U_CHAR CRC_buf[CRC_LEN];
	get_CRC(buf, len_buf, CRC_buf);
	memcpy(&buf[len_buf + ID_LEN + IDS_LEN], CRC_buf, CRC_LEN);
}



int main() {
	printf("UDP Server started up\n");
	// Initialize WSADATA
	WSADATA wsaData;
	int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (res != 0) {
		printf("WSAStartup failed: %d\n", res);
		return 1;
	}
	printf("WSAStartup succeeded\n");

	sockets_t server_sock;

	// Create sockets
	server_sock.data = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	server_sock.ack = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	// Check to see if we have a valid socket
	if ((server_sock.data == INVALID_SOCKET) || (server_sock.ack == INVALID_SOCKET)) {
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
	inet_pton(AF_INET, "127.0.0.1", &client_info.data.sin_addr);
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

	// Bind sockets
	int err1 = bind(server_sock.data, &server_info.data, sizeof(SOCKADDR_IN));
	int err2 = bind(server_sock.ack, &server_info.ack, sizeof(SOCKADDR_IN));
	if ((err1 == SOCKET_ERROR) || (err2 == SOCKET_ERROR)) {
		int iSocketError = WSAGetLastError();
		printf("WSALastError: %d\n", iSocketError);
		WSACleanup();
		return 100;
	}

	// Define buffer and etc.
	U_CHAR Buffer_Name[DATA_LEN] = "";
	U_CHAR Buffer_Path[PATH_REC_LEN + DATA_LEN] = "C:\\KDS\\KDS\\Rec_files\\";
	U_CHAR Buffer_Rec[DATA_LEN + ID_LEN + IDS_LEN + CRC_LEN] = "";
	U_CHAR Buffer_Send[40] = "";
	int ID_from_packet = 0;
	int nBytesRecv = 0;
	int nServer_data = sizeof(SOCKADDR_IN);

	// Define file descriptors and timeout
	U_CHAR buf_OK[] = "Packet received!";
	U_CHAR buf_NOK[] = "Packet corrupted!";
	bool crc_check = false;
	bool crc_ID = false;

	U_CHAR name_state[NUM_OF_CLIENTS] = "";
	U_CHAR size_state[NUM_OF_CLIENTS] = "";
	U_CHAR hash_state[NUM_OF_CLIENTS] = "";
	unsigned int sizeof_file_dec[NUM_OF_CLIENTS] = { 0 };
	unsigned int hash_ID[NUM_OF_CLIENTS] = { 0 };
	unsigned int last_curr_recv_seq_ID[NUM_OF_CLIENTS] = { 0 };
	bool already_came = false;
	U_CHAR *file_data[NUM_OF_CLIENTS];

	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(server_sock.data, &rset);
	int nready, num_rec_Packets;
	struct timeval timeout;
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	int num_of_packets = 0;
	FILE *wptr;
	int i;
	U_CHAR digest[SHA512_DIGEST_LENGTH] = { 0 };
	SHA512_CTX ctx;
	SHA512_Init(&ctx);


	while (1) {
		nready = select(server_sock.data +1, &rset, NULL, NULL, &timeout);
		if (FD_ISSET(server_sock.data, &rset)) {		// if UDP packet was received
			// receive packet with the name
			nBytesRecv = recvfrom(server_sock.data, Buffer_Rec, sizeof(Buffer_Rec), 0, (SOCKADDR*)&server_info.data, &nServer_data);
			crc_check = check_CRC(Buffer_Rec, nBytesRecv);
			if (!crc_check) {	//packet corrupted
				memcpy(Buffer_Send, buf_NOK, PACK_CORR_LEN);
				append_comps(Buffer_Send, PACK_CORR_LEN);
				sendto(server_sock.ack, Buffer_Send, PACK_CORR_LEN + ID_LEN + IDS_LEN + CRC_LEN, 0, (SOCKADDR*) & (client_info.ack), sizeof(SOCKADDR_IN));
			}else {	// packet received uncorrupted
				memcpy(Buffer_Send, buf_OK, PACK_REC_LEN);
				append_comps(Buffer_Send, PACK_REC_LEN);
				sendto(server_sock.ack, Buffer_Send, PACK_REC_LEN + ID_LEN + IDS_LEN + CRC_LEN, 0, (SOCKADDR*) & (client_info.ack), sizeof(SOCKADDR_IN));

				unsigned int curr_recv_seq_ID_idx = nBytesRecv - (CRC_LEN + IDS_LEN + ID_LEN);
				unsigned int curr_recv_seq_ID = get_256base_in_dec(&Buffer_Rec[curr_recv_seq_ID_idx], ID_LEN);
				unsigned int curr_client_ID_idx = nBytesRecv - (CRC_LEN + IDS_LEN);
				U_CHAR curr_client_ID = Buffer_Rec[curr_client_ID_idx];
				if(curr_recv_seq_ID > last_curr_recv_seq_ID[curr_client_ID]){
					++last_curr_recv_seq_ID[curr_client_ID];
					already_came = false;
				}

				if(curr_recv_seq_ID == 0 && !already_came){
					memcpy(Buffer_Name, Buffer_Rec, curr_recv_seq_ID_idx);
					printf("%s\n", Buffer_Name);
					already_came = true;

				}else if (curr_recv_seq_ID == 1 && !already_came) {
					sizeof_file_dec[curr_client_ID] = get_256base_in_dec(Buffer_Rec, SIZE_LEN);
					file_data[curr_client_ID] = calloc(sizeof_file_dec[curr_client_ID], sizeof(U_CHAR));
					hash_ID[curr_client_ID] = get_info_server(sizeof_file_dec[curr_client_ID]) + 2;
					already_came = true;

				}else if (curr_recv_seq_ID == hash_ID[curr_client_ID] && !already_came) {
					// calc hash
					SHA512_Update(&ctx, file_data[curr_client_ID], sizeof_file_dec[curr_client_ID]);
					SHA512_Final(digest, &ctx);

					if (!memcmp(digest, Buffer_Rec, SHA512_DIGEST_LENGTH)) {	//hash is the same
						memcpy(&Buffer_Path[PATH_REC_LEN], Buffer_Name, strlen(Buffer_Name));
						printf("%s\n", Buffer_Path);
						wptr = fopen(Buffer_Path, "wb");
						if (wptr == NULL) {
							printf("Couldn't open the file, error is: %s\n", strerror(errno));
						}
						fwrite(file_data[curr_client_ID], sizeof(U_CHAR), sizeof_file_dec[curr_client_ID], wptr);
						fclose(wptr);
						free(file_data[curr_client_ID]);
						last_curr_recv_seq_ID[curr_client_ID] = 0;
						printf("File received!\n");
						already_came = false;
					}
				}else if (!already_came) {
					unsigned int idx = DATA_LEN * (curr_recv_seq_ID - 2);
					memcpy(&file_data[curr_client_ID][idx], Buffer_Rec, curr_recv_seq_ID_idx);
					already_came = true;
				}
			}
		}
		FD_ZERO(&rset);
		FD_SET(server_sock.data, &rset);
	}
	
	// Close the socket
	closesocket(server_sock.data);
	closesocket(server_sock.ack);
	WSACleanup();
	return 0;
}
