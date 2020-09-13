// YA HOSSEIN
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <syslog.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
		u_short th_len;					/* length */
		u_short th_sum;                 /* checksum */
};

struct sniff_dns {
        u_short th_id;     				/* Transaction ID */
		u_short flags;					/* Flags */
        u_short question;              	/* Questions */
		u_short answer;					/* Answer RRs */
		u_short authority;             	/* Authority RRs */
		u_short additional;				/* Additional RRs */
};


char *http_packet(const u_char *packet, int size_ip, int size_tcp, struct sniff_ip *ip, char *log)	{
	const char *payload;
	int size_payload;
	char temp [50];

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/* print payload data, if it is a HTTP packet */
	if (size_payload > 0) {
		sprintf(temp, "   Payload (%d bytes):\n", size_payload);
		strcat(log, temp);
		int i;
		const u_char *ch = payload;
		for(i = 0; i < size_payload; i++) {
			if (isprint(*ch))	{
				sprintf(temp, "%c", *ch);
				strcat(log, temp);
			}	else	{	
				sprintf(temp, "\n");
				strcat(log, temp);
			}
			ch++;
		}
		sprintf(temp, "\n");
		strcat(log, temp);
	} else	{
		return NULL;
	}

	if(strstr(log, "HTTP") != NULL) {
		return log;
	}	else	{
		return NULL;
	}
}


char *trimDOT(char *str) {
	char *end;
	while((unsigned char)* str == '.')
		str++;
  	end = str + strlen(str) - 1;
  	while(end > str && (unsigned char)* end == '.')
  		end--;
  	end[1] = '\0';
  	return str;
}


char *dns_packet(const u_char *packet, int size_ip, struct sniff_udp *udp, char *log)	{
	const struct sniff_dns *dns;			/* DNS */
	const char *query;						/* QUERY part of DNS packet */

	int size_query;
	char temp[150];

	/* treat UDP payload like DNS packet - print packet ID */
	dns = (struct sniff_dns*) (packet + SIZE_ETHERNET + size_ip + 8);
	unsigned short flags = ntohs(dns->flags);
	sprintf(temp, "\tID: 0x%x\n", ntohs(dns->th_id));
	strcat(log, temp);

	/* print info got from packet FLAGS */
    char info [100] = {'\0'};
	if (flags & 0x8000) {
		strcat(info, "message is RESPONSE\t");
	}	else	{
		strcat(info, "message is QUERY\t");
	}
	if (!(flags & 0x7800)) {
		strcat(info, "STANDARD query\t");
	}
	if (flags & 0x0002) {
		strcat(info, "server failure.");
	}
	sprintf(temp, "\tInfo: %s\n", info);
	strcat(log, temp);

	/* print DNS query */
	query = (u_char *) (packet + SIZE_ETHERNET + size_ip + 8 + 12);
	size_query = ntohs(udp->th_len) - 20;
	if (size_query > 0) {
		sprintf(temp, "\tQuery (%d bytes):\n", size_query);
		strcat(log, temp);

		/* determine query data */
		char name [100] = {'\0'};
		int i;
		const u_char *ch = query;
		for (i = 0; i < size_query - 4; i++) {
			if (isprint(*ch))	{
				name[i] = *ch;
			}	else	{
				name[i] = '.';
			}
			ch++;
		}
		sprintf(temp, "\t\tName: %s", trimDOT(name));
		strcat(log, temp);

		/* determine type */
		unsigned short *t = (unsigned short *) (packet + SIZE_ETHERNET + size_ip + 8 + 12 + size_query - 4);
		unsigned short type = ntohs(*t);
		if (type == 1) {
			sprintf(temp, "\n\t\ttype:  A\n");
			strcat(log, temp);
			
		} else if (type == 28) {
			sprintf(temp, "\n\t\ttype:  AAAA\n");
			strcat(log, temp);
		}
	}
	return log;
}


#define sess_period	30
time_t sess_timer;
struct Session {
	int protocol;
	char *s_ip;
	char *d_ip;
	int s_port;
	int d_port;
	int packet_count;
};
/* nodes of linked list used for storing SESSIONs */
struct Node {
    struct Session sess;
    struct Node *next;
	struct Node *previous;
};


struct Node* head = NULL;						/* head of linked list */
struct Node* current;							/* current node of linked list */

int same_session(int protocol, char *src_ip, char *dest_ip, int src_p, int dest_p)	{
	if (current->sess.protocol != protocol) {
		return 0;
	}
	int flag1 = 1, flag2 = 1;
	while (strcmp(current->sess.s_ip, src_ip) != 0)
		flag1 = 0;
	while (strcmp(current->sess.d_ip, dest_ip) != 0)
		flag2 = 0;
	int result = flag1 && flag2 && current->sess.s_port == src_p && current->sess.d_port == dest_p;
	if (result) {
		return 1;
	}

	flag1 = 1, flag2 = 1;
	while (strcmp(current->sess.s_ip, dest_ip) != 0)
		flag1 = 0;
	while (strcmp(current->sess.d_ip, src_ip) != 0)
		flag2 = 0;
	return flag1 && flag2 && current->sess.s_port == dest_p && current->sess.d_port == src_p;;
}


void session_hijacking(int protocol, char *src_ip, char *dest_ip, int src_p, int dest_p)	{
	static int sess_count = 1;					/* session counter */

	static int udp_sess_per = 0;				/* number of udp sessions in this period */
	static int tcp_sess_per = 0;				/* number of tcp sessions in this period */

	/* first packet */
	if (head == NULL) {
    	head = (struct Node*) malloc( sizeof(struct Node) );
		current = head;
		head->previous = NULL;
		head->sess.protocol = protocol;
		head->sess.s_ip = src_ip;
		head->sess.d_ip = dest_ip;
		head->sess.s_port = src_p;
		head->sess.d_port = dest_p;
		head->sess.packet_count = 1;
		return;
	}

	// char log[10000] = {'\0'};
	// char temp[100];

	/* check if current packet is in same session with CURRENT */
	if (same_session(protocol, src_ip, dest_ip, src_p, dest_p)) {
		current->sess.packet_count++;
		return;
	}

	/* first packet of new session recieved */

}


// 	printf("%s", log);
// 	syslog(LOG_DEBUG, "%s", log);

// 	/* first packet of new session recieved */
// 	pkt_count = 1;
// 	sess_count++;
// 	curr_ip = ip;

// 	/* periodical report */
// 	time_t now = time(NULL);
// 	if (now - sess_timer > sess_period) {
// 		sess_timer = now;
// 		printf("\n** there were %d UDP Sessions and %d TCP Sessions in last %d seconds. **\n", udp_sess_per, tcp_sess_per, 
// 				sess_period);
// 		syslog(LOG_INFO, " there were %d UDP Sessions and %d TCP Sessions in last %d seconds. ", udp_sess_per, tcp_sess_per,
// 				 sess_period);
// 		tcp_sess_per = 0;
// 		udp_sess_per = 0;
// 	}
// }


#define ip_period 	60
time_t ip_timer;
void ip_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)	{
	static int count = 1;						/* packet counter */

	static int tcp_count = 0;
	static int udp_count = 0;
	static int new_count = 0;

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  	/* The ethernet header */
	struct sniff_ip *ip;             		 	/* The IP header */

	int size_ip;
	char log [10000];							/* log message which would generated for this packet */
	char temp [500];

	sprintf(temp, "\nPacket number %d:\n", count);
	strcat(log, temp);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*) (packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("\t* Invalid IP header length: %u bytes\n", size_ip);
    	syslog(LOG_ERR, "\t* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	char *s_ip = inet_ntoa(ip->ip_src);
	char *d_ip = inet_ntoa(ip->ip_dst);
	int s_port, d_port;
	sprintf(temp, "\tFrom: %s\n", s_ip);
	strcat(log, temp);
	sprintf(temp, "\tTo: %s\n", d_ip);
	strcat(log, temp);

	/* determine protocol, detect source and destination ports */
	if (ip->ip_p == IPPROTO_TCP) {
		sprintf(temp, "\tProtocol: TCP\n");
		strcat(log, temp);
		struct sniff_tcp *tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
		int size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			printf("\t* Invalid TCP header length: %u bytes\n", size_tcp);
    		syslog(LOG_ERR, "\t* Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		s_port = ntohs(tcp->th_sport);
		d_port = ntohs(tcp->th_dport);
		sprintf(temp, "\tSrc port: %d\n", s_port);
		strcat(log, temp);
		sprintf(temp, "\tDst port: %d\n", d_port);
		strcat(log, temp);
		tcp_count++;

		session_hijacking(ip->ip_p, s_ip, d_ip, s_port, d_port);

		/* check whether TCP packet is http or not, add http payload to "log" */
		char payload[10000];
		char *http = http_packet(packet, size_ip, size_tcp, ip, payload);
		if (http != NULL)	{
			strcat(log, http);
		}
		memset(payload, '\0', strlen(payload));


	}	else if (ip->ip_p == IPPROTO_UDP)	{
		sprintf(temp, "\tProtocol: UDP\n");
		strcat(log, temp);
		struct sniff_udp *udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
		int size_udp = udp->th_len;
		if (size_udp < 8) {
			printf("\t* Invalid UDP header length: %u bytes\n", size_udp);
			syslog(LOG_ERR, "\t* Invalid TCP header length: %u bytes\n", size_udp);
			return;
		}
		s_port = ntohs(udp->th_sport);
		d_port = ntohs(udp->th_dport);
		sprintf(temp, "\tSrc port: %d\n", s_port);
		strcat(log, temp);
		sprintf(temp, "\tDst port: %d\n", d_port);
		strcat(log, temp);
		udp_count++;

		session_hijacking(ip->ip_p, s_ip, d_ip, s_port, d_port);

		/* check whether UDP packet is DNS or not, add DNS payload to "log" */
		if (s_port == 53 || d_port == 53) {
			char payload[1000];
			char *dns = dns_packet(packet, size_ip, udp, payload);
			strcat(log, dns);
			memset(payload, '\0', strlen(payload));
		}


	}	else	{
		sprintf(temp, "new protocol: %d\n", ip->ip_p);
		strcat(log, temp);
		syslog(LOG_WARNING, "new protocol: %d\n", ip->ip_p);
		new_count++;
	}

	printf("%s", log);
	syslog(LOG_INFO, "%s", log);
	memset(log, '\0', strlen(log));

	/* periodical report */
	time_t now = time(NULL);
	if (now - ip_timer > ip_period) {
		ip_timer = now;
		printf("\n** there were %d UDP Packets and %d TCP Packets and %d NEW Packets in last %d seconds. **\n", udp_count,
		 		tcp_count, new_count, ip_period);
		syslog(LOG_DEBUG, "there were %d UDP Packets and %d TCP Packets and %d NEW Packets in last %d seconds.", udp_count, 
				tcp_count, new_count, ip_period);
		tcp_count = 0;
		udp_count = 0;
		new_count = 0;
	}
}


int main(int argc, char **argv) {
	char *dev = NULL;											/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];								/* error buffer */
	pcap_t *handle;												/* packet capture handle */

	char filter_exp[] = "ip";									/* filter expression */
	struct bpf_program fp;										/* compiled filter program (expression) */
	bpf_u_int32 mask;											/* subnet mask */
	bpf_u_int32 net;											/* ip */
	struct in_addr net_addr;									/* IPV4 representation for ip(net) */
	struct in_addr mask_addr;									/* IPV4 representation for mask */

	pcap_if_t *alldevsp , *device;
	char devs[50][50];
	int count = 1 , n;
	
	/* first get the list of available devices */
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )	{
		fprintf(stderr, "Error finding devices : %s" , errbuf);
		exit(EXIT_FAILURE);
	}
	printf("Done");

	/* print the available devices */
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL) {
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	/* ask user which device to sniff */
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	dev = devs[n];
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print IP, IP class and mask of selected device */
  	net_addr.s_addr = net;
	mask_addr.s_addr = mask;
	char class;
	switch (mask) {
	case 16777215:
		class = 'C';
		break;
	case 65535:
		class = 'B';
	default:
		class = 'A';
	}
  	printf("IP Address: %s\nIP class: %c\n", inet_ntoa(net_addr), class);
  	printf("Mask: %s\n", inet_ntoa(mask_addr));

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	printf("Filter set successfully\n");

	/* now we can set our callback function */
	openlog("packet sniffer: ", 0, LOG_LOCAL0);
	sess_timer = time(NULL);
	ip_timer = time(NULL);

	pcap_loop(handle, -1, ip_packet, NULL);

	/* cleanup */
    closelog();
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
