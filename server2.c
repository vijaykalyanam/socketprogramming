#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

// This is server.

int main(int argc, char **argp) {

	int server,peer, ret;
	struct sockaddr_in server_addr4 ={0};
	struct sockaddr_in peer_addr4={0};
	socklen_t peer_addr_len=0;
	char buf[2048] = {0};

	//CREATE SOCKET   --> Create ADDRESS space
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == -1) {
		printf("socket creation failed\n");
		ret -1;
	}

	//BIND address to socket     Assigning address space to server socket
	server_addr4.sin_family = AF_INET;
	server_addr4.sin_port   = htons(10001);
	server_addr4.sin_addr.s_addr   = inet_addr("192.168.1.123");

	// assigning name to a socket
	ret = bind(server, (const struct sockaddr *)&server_addr4, sizeof (server_addr4));
	if (ret) {
		printf("Socket bind failed\n");
//shutdown(server, RDWR);
close(server);
		return -1;
	}

	// A willingness to accept incoming connections and a queue limit for incoming connections are specified with listen()
	if (listen(server, 2)) {
		printf("listen call failed for socket :%d\n", server);
		return -1;
	} 

	printf("Server is listening on socket :%d\n", server);
	printf("server socket :%d port :%d binded to address :%s\n",
			server, ntohs(server_addr4.sin_port), inet_ntoa(server_addr4.sin_addr));
	peer_addr_len = sizeof(struct sockaddr_in);
	if (peer = accept(server, (struct sockaddr *)&peer_addr4, &peer_addr_len)) {
		printf("New connection has been made with peer:\n");
		printf("peer Socket : %d peer addr len :%d Client Addr :%s\n",
				peer, peer_addr_len, inet_ntoa(peer_addr4.sin_addr)
		      );
	}

	static unsigned int i = 'A';
	int j;
	char wbuf[64];
	while(1) {
		//ret = read(peer, buf, sizeof(buf)); This also works
		ret = recv(peer, buf, sizeof(buf), MSG_DONTWAIT);
		if (ret > 0) {
			printf("Data received of length :%d\n", ret);
			printf("%s\n", buf);
			bzero(buf, sizeof(buf));
		}
		sleep(5);
		printf("Data send:\n");
		i++;
		bzero(wbuf, sizeof(wbuf));
		for(j = 0; j < sizeof(wbuf)-1; j++)
			wbuf[j] = i;
		write(peer, wbuf, sizeof(wbuf)-1);
		if (i == 'Z')
			break;
	}

	return 0;
}
