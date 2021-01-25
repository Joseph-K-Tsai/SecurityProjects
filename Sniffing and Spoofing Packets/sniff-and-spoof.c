#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* default snap length (maximum bytes per packet to capture)*/
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1]*/
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes*/
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
        #define IP_DF 0x4000            /* don't fragment flag */
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

// This function was provided in the reference code on this website:http://www.tcpdump.org/pcap.htm
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

// Function to print the payload, provided by: http://www.tcpdump.org/pcap.htm
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


// Create structure for icmpheader
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};



/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

// Calculates the checksum given a buffer and packet length. 
// This was also provided in the reference code.
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}



// Function invoked by pcap for each captured packet.
void got_packet(u_char *args, const struct pcap_pkthdr *header,
	const u_char *packet)

{
	printf("Got a packet\n");

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct icmpheader *captured_icmphdr; /*ICMP header*/
	int size_ip;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	// Check if the ip header length is an appropriate size (also given by reference code)
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));


	// Define icmpheader to obtain information regarding captured ICMP packet
	captured_icmphdr = (struct icmpheader*)(packet + SIZE_ETHERNET + size_ip);

	/****** Begin construction of the spoofed ICMP packet *********/
	int sd;
        struct sockaddr_in sin;
        char buffer[1550]; // You can change the buffer size
        /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
        * tells the sytem that the IP header is already included;
        * this prevents the OS from adding another IP header. */
        sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(sd < 0) {
                perror("socket() error");
                exit(-1);
        }

        //Set the internet protocol to AF_INET (internet protocol)
        sin.sin_family = AF_INET;

        /** Change this line here to be the right MAC address **/
		// Set the address to be that of the source address of which was captured
		sin.sin_addr.s_addr = ip->ip_dst.s_addr;

        memset(buffer, 0, 1550);

        // Create spoofed icmp header
        struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));

        /*Set relevant fields to spoof the icmp header*/
        icmp->icmp_type = 0;
        icmp->icmp_id = captured_icmphdr->icmp_id;

        // Use the same sequence number as the captured packet
        icmp->icmp_seq = captured_icmphdr -> icmp_seq;

        // Calculate the checksum for integrity
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

        /********** Create IPheader ********/

        // create ipheader
        struct ipheader *ipspoof = (struct ipheader *) buffer;
        ipspoof->iph_ver = 4;
        ipspoof->iph_ihl = 5;
        ipspoof->iph_ttl = 64;
		ipspoof->iph_sourceip = ip->ip_dst;
	

		// Send the packet back to the requestor	
        //ipspoof->iph_destip.s_addr = inet_addr("1.1.1.1");
		ipspoof->iph_destip = ip->ip_src;
        ipspoof->iph_protocol = IPPROTO_ICMP;
        ipspoof->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader)
                       + sizeof(struct sniff_ethernet));

        // Calculate the data to add to the packet
        char *data = (u_char *)packet + 
        					sizeof(struct sniff_ethernet) + 
        					sizeof(struct ipheader) + 
        					sizeof(struct sniff_tcp);

        // Create a corresponding pointer that's within the buffer, at the end of the buffer
        char *data_pointer = (u_char *)buffer + 
        						sizeof(struct sniff_ethernet) + 
        						sizeof(struct ipheader) + 
        						sizeof(struct sniff_tcp);


        /****Construct data for spoofed packet***/
        // Understand how large the data is so that we can understand how long to loop for
		int size_data = ntohs(ip->ip_len) - (sizeof(struct ipheader));
        if (size_data > 0) {

        	// Iterate through the data and make it the same as what is within the request packet
        	for (int i = 0; i < size_data; i++) {

        		*data_pointer = *data;
        		data++;
        		data_pointer++;
        	}
        }

        // Documentation regarding https://pubs.opengroup.org/onlinepubs/009695399/functions/sendto.html
        // how to use the sendto() function.
        // First parameter = "socket"
        // Second parameter = "message", which is defined as "A buffer containing the message to be sent"
        if(sendto(sd, buffer, 64, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto() error");
            exit(-1);
        }
		printf("SPOOFED PACKET HAS BEEN SENT");

		// Close the socket
		close(sd);
}


int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp[icmptype] == icmp-echo";
	bpf_u_int32 net;

	// Step 1: Open live pcp session on NIC with name "enp0s3"
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);

	pcap_setfilter(handle, &fp);

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close handle
	return 0;

	//Compilation command: gcc -o sniffer sniff.c -lcap
}
