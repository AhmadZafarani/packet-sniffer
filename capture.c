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


void http_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)	{
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	char log [10000];
	char temp [500];

	int size_ip;
	int size_tcp;
	int size_payload;
	
	sprintf(temp, "\nPacket number %d:\n", count);
	strcat(log, temp);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*) (packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		sprintf(temp, "   * Invalid IP header length: %u bytes\n", size_ip);
		strcat(log, temp);
		return;
	}

	/* print source and destination IP addresses */
	sprintf(temp, "       From: %s\n", inet_ntoa(ip->ip_src));
	strcat(log, temp);
	sprintf(temp, "         To: %s\n", inet_ntoa(ip->ip_dst));
	strcat(log, temp);
	
	/* determine protocol */
	if (ip->ip_p == IPPROTO_TCP)	{
		sprintf(temp, "   Protocol: TCP\n");
		strcat(log, temp);
	} else	{
		sprintf(temp, "   Protocol: not TCP\n");
		strcat(log, temp);
		return;
	}
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		sprintf(temp, "   * Invalid TCP header length: %u bytes\n", size_tcp);
		strcat(log, temp);
		return;
	}
	
	sprintf(temp, "   Src port: %d\n", ntohs(tcp->th_sport));
	strcat(log, temp);
	sprintf(temp, "   Dst port: %d\n", ntohs(tcp->th_dport));
	strcat(log, temp);
	
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
		memset(log, '\0', strlen(log));
		count--;
		return;
	}
	
	if(strstr(log, "HTTP") != NULL) {
		printf("%s", log);
	}	else	{
		memset(log, '\0', strlen(log));
		count--;
	}
}


char *trimDOT(char *str) {
  char *end;

  // Trim leading space
  while((unsigned char)* str == '.')
  	str++;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && (unsigned char)* end == '.')
  	end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}


void dns_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)	{
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const struct sniff_dns *dns;			/* DNS */
	const char *query;						/* QUERY part of DNS packet */

	int size_ip;
	int size_udp;
	int size_query;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*) (packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
	printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	if (ip->ip_p == IPPROTO_UDP)	{
		printf("\tProtocol: UDP\n");
	}	else	{
		printf("\tProtocol: not UDP\n");
		return;
	}
	
	/* define/compute tcp header offset */
	udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
	size_udp = udp->th_len;
	if (size_udp < 8) {
		printf("   * Invalid UDP header length: %u bytes\n", size_udp);
		return;
	}
	
	printf("\tSrc port: %d\n", ntohs(udp->th_sport));
	printf("\tDst port: %d\n", ntohs(udp->th_dport));
	
	/* treat UDP payload like DNS packet - print packet ID */
	dns = (struct sniff_dns*) (packet + SIZE_ETHERNET + size_ip + 8);
	unsigned short flags = ntohs(dns->flags);
	printf("\tID: 0x%x\n", ntohs(dns->th_id));
	
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
	printf("\tInfo: %s\n", info);

	/* print DNS query */
	query = (u_char *) (packet + SIZE_ETHERNET + size_ip + 8 + 12);
	size_query = ntohs(udp->th_len) - 20;
	if (size_query > 0) {
		printf("\tQuery (%d bytes):\n", size_query);

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
		printf("\t\tName: %s", trimDOT(name));

		/* determine type */
		unsigned short *t = (unsigned short *) (packet + SIZE_ETHERNET + size_ip + 8 + 12 + size_query - 4);
		unsigned short type = ntohs(*t);
		if (type == 1) {
			printf("\n\t\ttype:  A\n");
		} else if (type == 28) {
			printf("\n\t\ttype:  AAAA\n");
		}
	}
}


int same_session_ip(const struct sniff_ip *curr, const struct sniff_ip *pkt)	{
	if (curr->ip_p != pkt->ip_p) {
		return 0;
	}
	int flag1 = 1, flag2 = 1;
	const char* pkt_s = inet_ntoa(pkt->ip_src);
	const char* pkt_d = inet_ntoa(pkt->ip_dst);
	const char* curr_s = inet_ntoa(curr->ip_src);
	const char* curr_d = inet_ntoa(curr->ip_dst);

	while (strcmp(pkt_s, curr_s) != 0)
		flag1 = 0;
	while (strcmp(pkt_d, curr_d) != 0)
		flag2 = 0;
	if (flag1 && flag2) {
		return 1;
	}
	flag1 = 1, flag2 = 1;
	while (strcmp(pkt_s, curr_d) != 0)
		flag1 = 0;
	while (strcmp(pkt_d, curr_s) != 0)
		flag2 = 0;
	return flag1 && flag2;
}


int same_session_port(int curr_s, int curr_d, int pkt_s, int pkt_d) {
	return (curr_s == pkt_s && curr_d == pkt_d) || (curr_s == pkt_d && curr_d == pkt_s);
}


void session_hijacking(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)	{
	static int pkt_count = 1;                   /* current session packet counter */
	static int sess_count = 1;					/* session counter */

	static struct sniff_ip *curr_ip = NULL;		/* current session ip */
	static struct sniff_tcp *curr_tcp = NULL;	/* current session protocol */
	static struct sniff_udp *curr_udp = NULL;
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header */
	struct sniff_ip *ip;              /* The IP header */
	int size_ip;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*) (packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("\t* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* first packet */
	if (curr_ip == NULL)
		curr_ip = ip;
	
	/* determine protocol */
	if (ip->ip_p == IPPROTO_TCP)	{
		struct sniff_tcp *tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
		int size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			printf("\t* Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		
		/* check if current packet is in same session with last packets */
		if (same_session_ip(curr_ip, ip) && curr_tcp != NULL &&
			same_session_port(ntohs(curr_tcp->th_sport), ntohs(curr_tcp->th_dport), ntohs(tcp->th_sport), ntohs(tcp->th_dport))) {
			pkt_count++;
			return;
		}

		curr_tcp = tcp;
		curr_udp = NULL;

	}	else if (ip->ip_p == IPPROTO_UDP)	{
		struct sniff_udp *udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
		int size_udp = udp->th_len;
		if (size_udp < 8) {
			printf("\t* Invalid UDP header length: %u bytes\n", size_udp);
			return;
		}

		/* check if current packet is in same session with last packets */
		if (same_session_ip(curr_ip, ip) && curr_udp != NULL &&
			same_session_port(ntohs(curr_udp->th_sport), ntohs(curr_udp->th_dport), ntohs(udp->th_sport), ntohs(udp->th_dport))) {
			pkt_count++;
			return;
		}
		
		curr_udp = udp;
		curr_tcp = NULL;

	}	else	{
		printf("new protocol\n");
		return;
	}

	/* first packet of new session recieved */
	printf("\nSession number %d:\n", sess_count);
	printf("\tthere are %d packets in this Session\n", pkt_count);
	if (ip->ip_p == IPPROTO_TCP) {
		printf("\tprotocol: TCP\n");
		printf("\tdata communication was between these sockets:\n\t\tip: %s\tport: %d\n\t\tip: %s\tport: %d", 
				inet_ntoa(curr_ip->ip_src), ntohs(curr_tcp->th_sport), inet_ntoa(curr_ip->ip_dst), ntohs(curr_tcp->th_dport));
	}	else	{
		printf("\tprotocol: UDP\n");
		printf("\tdata communication was between these sockets:\n\t\tip: %s\tport: %d\n\t\tip: %s\tport: %d", 
				inet_ntoa(curr_ip->ip_src), ntohs(curr_udp->th_sport), inet_ntoa(curr_ip->ip_dst), ntohs(curr_udp->th_dport));
	}
	pkt_count = 1;
	sess_count++;
	curr_ip = ip;
}


int main(int argc, char **argv) {
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	// char filter_exp[] = "host 127.0.0.1 and port 8000";		/* filter expression */
	// char filter_exp[] = "udp port 53";		/* filter expression */
	char filter_exp[] = "";		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

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
		if(device->name != NULL)
		{
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
	// pcap_loop(handle, -1, http_packet, NULL);
	// pcap_loop(handle, -1, dns_packet, NULL);
	pcap_loop(handle, -1, session_hijacking, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
