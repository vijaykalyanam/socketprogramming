#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <libgen.h>
#include <errno.h>            // errno, perror()
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <netdb.h>            // struct addrinfo
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/ip.h> 
#include <linux/udp.h>
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */
#define ARPOP_InREQUEST 8               /* InARP request                */
#define ARPOP_InREPLY   9               /* InARP reply                  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK                 */

/*
 *      This structure defines an ethernet arp header.
 */

struct arphdr {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */

	/* This section is commented out in default header file */
#if 1 
         /*
          *      Ethernet looks like this : This bit is variable sized however...
          */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address            */
#endif
} __attribute__((packed));

struct arp_packet {
	/* ETHHDR */
	struct ethhdr ethh;
	/*ARP HDR */
	struct arphdr arph;
	unsigned char padding[32];
} __attribute__((packed));

#if 0
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
struct ethhdr {
        unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
        unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
        __be16          h_proto;                /* packet type ID field */
} __attribute__((packed));

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __be16  tot_len;
        __be16  id;
        __be16  frag_off;
        __u8    ttl;
        __u8    protocol;
        __sum16 check;
        __be32  saddr;
        __be32  daddr;
        /*The options start here. */
};

struct udphdr {
        __be16  source;
        __be16  dest;
        __be16  len;
        __sum16 check;
};
#endif

static const char *dst_addr = "";
static const char *if_name = "";
#define ARP_PACKET_LEN	64

static struct option long_options[] = {
	{"dst-ip", required_argument, 0, 'd'},
	{"interface", required_argument, 0, 'i'},
	{"interval", required_argument, 0, 'n'},
	{"zero-copy", no_argument, 0, 'z'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -d, --dst-ip		destination ip address\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
		"  -z, --zero-copy      Force zero-copy mode.\n"
		"\n";
	fprintf(stderr, str, prog, 1024);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;
	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "dinz",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			dst_addr = optarg;
			printf("DST_addr: %s\n", dst_addr);
			break;
		case 'i':
			if_name = optarg;
			printf("if_name: %s\n", if_name);
			break;
		case 'n':
			break;
		case 'z':
			break;
		default:
			usage(basename(argv[0]));
		}
	}

	if (!dst_addr || !if_name)
		usage(basename(argv[0]));
}

static int prepare_apr_header(struct arp_packet *p,
		struct sockaddr_in *src, struct sockaddr_in *dst)
{
	struct ethhdr *ethh; 
	struct arphdr *arph;

	if (!p)
		return -EINVAL;

	ethh = &p->ethh;
	arph = &p->arph;

	for (int i=0; i<ETH_ALEN; i++)
		ethh->h_dest[i] = 0xff;
	ethh->h_proto = htons(ETH_P_ARP);

	arph->ar_hrd = htons(1);
	arph->ar_pro = htons(ETH_P_IP);
	arph->ar_hln = ETH_ALEN;
	arph->ar_pln = 4;
	arph->ar_op = htons(ARPOP_REQUEST);

	for (int i=0; i<ETH_ALEN; i++) {
		arph->ar_sha[i] = ethh->h_source[i];
		arph->ar_tha[i] = 0; 
	}

	*(struct in_addr *)arph->ar_sip = src->sin_addr; 
	*(struct in_addr *)arph->ar_tip = dst->sin_addr; 

	return 0;
}

static int waitforresponse(int s, int no_of_secs) {
	int ret, max_sd;
	fd_set rx_set;
	struct timeval timeout;

	FD_ZERO(&rx_set);
	FD_SET(s, &rx_set);
	max_sd = s+1;

	timeout.tv_sec = no_of_secs;
	timeout.tv_usec = 20000;

	ret = select(max_sd, &rx_set, NULL, NULL, &timeout);
	return ret;
}

static int process_arp_request(struct sockaddr_ll *dev, 
		struct arp_packet *req, struct arp_packet *resp)
{
	unsigned int sip;
	unsigned char *data;
	struct ethhdr *ethh; 
	struct arphdr *arph;
	int attempts;
	int sock;
	int rc;
	
	if (!resp)
		return -EINVAL;
	else
		data = (unsigned char *)resp;
	attempts = 0;
	arph = &req->arph;
	sip = *(unsigned int *)arph->ar_sip;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror ("socket creation with AF_INET SOCK_RAW ETH_P_ARP failed ");
		return sock;
	}

	arph = &resp->arph;
	ethh = &resp->ethh;

	while(1) {	
		rc = sendto(sock, (const void *)req, sizeof(struct arp_packet), 0,
				(struct sockaddr *)dev, sizeof(struct sockaddr_ll));
		if (rc < 0) {
			perror ("sendto failed\n");
			return rc;
		}

		do {
			rc = waitforresponse(sock, 2);
			if (rc) {
				rc = read(sock, resp, sizeof(struct arp_packet));
				if (rc < 0) {
					attempts = -1;
					break;
				}
#if 0
				for (int i = 0; i < 48; i++)
					printf("%02x:", *((unsigned char *)resp + i));
				printf("\n");
#endif
				if ((ethh->h_proto != htons(ETH_P_ARP)) ||
						(arph->ar_op != ntohs(ARPOP_REPLY))
				   ) {
					printf("Not an ARP PACKET, retry...\n");
					attempts++;
				} else if ( sip == *(unsigned int *)arph->ar_tip) {
					printf("Target MAC :");
					for (int i = 0; i < ETH_ALEN; i++)
						printf("%2x:", arph->ar_sha[i]);
					printf("\n");
					rc = 0;
					attempts = -1;
				}
			} else
				attempts++;
			if (attempts == 5)
				printf("Max Attempts reached, could not get response\n");
			if (attempts < 0)
				break;
		} while(attempts <= 5);

		if (attempts < 0 || attempts == 5) {
			rc = -1;
			break;
		}
	}

	close(sock);
	
	return rc;
}

int main(int argc, char **argv)
{
	struct arp_packet *req; 
	struct arp_packet *resp; 
	struct arphdr *arph;
	struct ethhdr *ethh; 
	struct iphdr *iph; 
	struct ifreq ifr;
	struct sockaddr *saddr;
	struct sockaddr_in *sin;
	struct sockaddr_in src_ip; 
	struct sockaddr_in dst_ip; 
  	struct sockaddr_ll dev;
	int sock;
	int rc;

	parse_command_line(argc, argv);

	req = malloc(ARP_PACKET_LEN);
	resp = malloc(ARP_PACKET_LEN);
	
	sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_name);
	rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (rc < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}

	ethh = &req->ethh;
	memcpy(ethh->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN * sizeof (uint8_t));
	printf("MAC address for interface %s is ", if_name);
	for (int i=0; i<ETH_ALEN; i++) {
		printf ("%02x:", ethh->h_source[i]);
	}
	printf("\n");
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", if_name);
	rc = ioctl(sock, SIOCGIFADDR, &ifr);
	if (rc < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close(sock);
	src_ip.sin_family = AF_INET;
	src_ip.sin_port = htons(0);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	src_ip.sin_addr = sin->sin_addr; 

	printf("SRC IP ADDR: [%s]\n", inet_ntoa(src_ip.sin_addr));

	dst_ip.sin_family = AF_INET;
	dst_ip.sin_port = htons(0);
	rc = inet_aton(dst_addr, &dst_ip.sin_addr);
	if (rc < 0) {
		perror ("inet_aton failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	printf("DST IP ADDR: [%s]\n", inet_ntoa(dst_ip.sin_addr));

	rc = prepare_apr_header(req, &src_ip, &dst_ip);
	if (rc < 0) {
		perror ("inet_aton failed to get source MAC address ");
		goto failure;	
	}

	memset(&dev, 0, sizeof(struct sockaddr_ll));
	dev.sll_ifindex = if_nametoindex(if_name);
	if (dev.sll_ifindex < 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		goto failure;	
	}

	dev.sll_family = AF_PACKET;
	memcpy(dev.sll_addr, ethh->h_source, ETH_ALEN);
	dev.sll_halen = ETH_ALEN;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror ("socket creation with AF_INET SOCK_RAW ETH_P_ARP failed ");
		exit (EXIT_FAILURE);
	}

#if 0
  	rc = sendto(sock, req, sizeof(*req), 0,
			(struct sockaddr *)&dev, sizeof(struct sockaddr_ll));
	if (rc <= 0) {
		printf("RETURN :%d\n", rc);
		perror ("sendto failed\n");
		exit (EXIT_FAILURE);
	}

	close(sock);
	
#else
	rc = process_arp_request(&dev, req, resp);
	if (!rc) {
		arph = &resp->arph;
		printf("MAC Address of NIC with IP: %s is :", inet_ntoa(dst_ip.sin_addr));
		for (int i = 0; i < ETH_ALEN; i++)
			printf("%02X%c", arph->ar_sha[i], (i + 1 == ETH_ALEN) ? '\0' : (':'));
		printf("\n");
	}
#endif
failure:
	free(req);
	free(resp);

	return rc;
}
