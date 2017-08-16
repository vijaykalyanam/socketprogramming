#include "headers.h"

// This is client.

int main(int argc, char **argp) {

	int client,peer, ret;
	struct sockaddr_in server_addr4 ={0};
	struct sockaddr peer_addr={0};
	struct sockaddr_in peer_addr4={0};
	socklen_t addr_len=0;
	char buf[64] = {0};

	//CREATE SOCKET
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client == -1) {
		printf("socket creation failed\n");
		ret -1;
	}
	//Server address
	server_addr4.sin_family = AF_INET;
	server_addr4.sin_port   = htons(12345);
	server_addr4.sin_addr.s_addr   = inet_addr("193.168.1.111");
#if 0
	memcpy(buf, "vijayakumarkalyanam", 19);
	sendto(client, buf, 64, 0,
			(struct sockaddr *) &server_addr4, sizeof(server_addr4));
	printf("exit");
	return 0;

	// assigning name to a socket
	ret = bind(client, (const struct sockaddr *)&server_addr4, sizeof (server_addr4));
	if (ret) {
		printf("Socket bind failed\n");
		return -1;
	}
	// A willingness to accept incoming connections and a queue limit for incoming connections are specified with listen()
	if (listen(client, 1)) {
		printf("listen call failed for socket :%d\n", client);
		return -1;
	} 

	printf("Server is listening on socket :%d\n", client);
	if (peer = accept(client, (struct sockaddr *)&peer_addr, &peer_addr_len)) {
		printf("New connection has been made with peer:\n");
		printf("peer Socket : %d peer addr len :%d Client Addr :%s\n",
				peer, peer_addr_len, inet_ntoa(peer_addr4.sin_addr)
		      );
	}
#else 
	if(!connect(client, (struct sockaddr *) &server_addr4, sizeof(server_addr4))) {
		printf(" Connection established Client sock :%d port no :%d\n", client, ntohs(server_addr4.sin_port));
	} else {
		printf(" Connection establish Failed sock :%d port no :%d\n", client, ntohs(server_addr4.sin_port));
	}
memcpy(buf, "vijayakumarkalyanam", 19);
// We can use SEND here, as our connection is TCP(connection oriented)
sendto(client, buf, 64, 0,
(struct sockaddr *) &server_addr4, sizeof(server_addr4));

#endif
	while(1) {
//our socket is connected socket, so no need of recvfrom system call
		ret = recv(client, buf, sizeof(buf), 0);
		if (ret > 0) {
			printf("Data received of length :%d\n", ret);
			printf("%s\n", buf);
			bzero(buf, sizeof(buf));
		}
	}
	return 0;
}
