#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <WinSock2.h>
#include <stdint.h>
#include <time.h>

#pragma comment(lib, "ws2_32")

#ifdef _WIN32

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif


#define _CRT_SECURE_NO_WARNINGS

#define ETHER_ADDR_LEN 6

#define IP_ADDR_LEN 4

#define IPv4_HEADER	0x0800
#define IPv6_HEADER 0x86DD
#define ARP_HEADER	0x0806
#define RARP_HEADER 0x0835

//protocol type
#define ICMP		1
#define IGMP		2
#define TCP			6
#define EGP			8
#define UDP			17
#define OSPF		89

//ethernet type
#define SYN			0x02
#define PUSH		0x08
#define ACK			0x10
#define FIN_ACK		0x11
#define SYN_ACK		0x12
#define PUSH_ACK	0x18

//record content type
#define CHANGE_CIPHER_SPEC 0x14
#define ALERT			   0x15
#define HANDSHAKE		   0x16
#define APPLICATION_DATA   0x17

//tls 1.2 handshake type
#define HELLO_REQUEST		0x00
#define CLIENT_HELLO		0x01
#define SERVER_HELLO		0x02
#define NEW_SESSION_TICKET	0x04
#define CERTIFICATE			0x0B
#define SERVER_KEY_EXCHANGE	0x0C
#define CERTIFICATE_REQUEST	0x0D
#define SERVER_HELLO_DONE	0x0E
#define CERTIFICATE_VERIFY	0x0F
#define CLIENT_KEY_EXCHANGE	0x10
#define FINISHED			0x14

//tls 1.3 handshake type
#define NEW_SESSION_TICKET		0x04
#define END_OF_EARLY_DATA		0x05
#define ENCRYPTED_EXTENSIONS	0x08
#define KEY_UPDATE				0x18
#define MESSAGE_HASH			0xFE

//TLS version
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303

//alert protocol 신호
#define CLOSE_NOTIFY		 0x00
#define NO_RENEGOTIATION	 0x64
#define UNEXPECTED_MESSAGE	 0x0A
#define BAD_RECORD_MAC		 0x14
#define DECRYPTION_FAILED	 0x15
#define HANDSHAKE_FAILURE	 0x28
#define BAD_CERTIFICATE		 0x2A
#define UNSUPPORTED_CERTIFICATE 0x2B
#define CERTIFICATE_REVOKE		0x2C
#define CERTIFICATE_EXPIRED		0x2D

#pragma pack(push, 1)
typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}ether_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ip_header {
	u_char		ip_leng : 4;
	u_char		ip_version : 4;
	u_char		tos;
	u_short		tlen;
	u_short		identification;
	u_short		flags_fo;
	u_char		ttl;
	u_char		proto;
	u_short		crc;
	ip_address	saddr;
	ip_address	daddr;
	u_int		op_pad;
}ip_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}tcp_header;
#pragma pack(pop)	

#pragma pack(push, 1)
typedef struct tls_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}tls_header;
#pragma pack(pop)

typedef struct udp_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}udp_header;
#pragma pack(pop)	

#pragma pack(push, 1)
typedef struct arp_header {
	u_short		arp_hwtype;
	u_short		arp_ptype;
	u_char		arp_hwlen;
	u_char		arp_plen;
	u_short		arp_opcode;
	u_char		arp_shost[ETHER_ADDR_LEN];
	ip_address	saddr;
	u_char		arp_dhost[ETHER_ADDR_LEN];
	ip_address	daddr;
}arp_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_header {
	u_short		arp_hwtype;
	u_short		arp_ptype;
	u_char		arp_hwlen;
	u_char		arp_plen;
	u_short		arp_opcode;
	u_char		arp_shost[ETHER_ADDR_LEN];
	ip_address	saddr;
	u_char		arp_dhost[ETHER_ADDR_LEN];
	ip_address	daddr;
}dns_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct record_layer {
	u_char		rl_type;
	u_short		rl_version;
	u_short		rl_length;
}record_layer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ccs_proto {
	u_char		ccs_type;
	u_short		ccs_version;
	u_short		ccs_leng;
	u_char		ccs_message;
}ccs_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct alert_proto {
	u_char		alert_type;
	u_short		alert_version;
	u_short		alert_leng;
	u_char		alert_level;
	u_char		alert_descl;
}alert_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct application_proto {
	u_char		app_type;
	u_short		app_version;
	u_short		app_leng;
	u_char		app_enc_data[];
}application_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct handshake_protocol {
	u_int		handshake_type_leng;
	u_short		handshake_version;
}handshake_protocol;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct hello_request {

}hello_request;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello {
	u_int		ch_gmt;
	u_char		ch_random_bytes[28];
}client_hello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello {

}server_hello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct new_session_ticket {

}new_session_ticket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate {

}certificate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_key_exchange {

}server_key_exchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_request {

}certificate_request;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello_done {

}server_hello_done;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_verify {

}certificate_verify;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_key_exchange {

}client_key_exchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct finished {

}finished;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct packet {
	ether_header* eh;
	arp_header* ah;
	ip_header* ip;
	tcp_header* tcp;
	udp_header* udp;
	dns_header* dns;
	tls_header* tls;
	const unsigned char* app;
	int tcpCheck;
	int udpCheck;
}packet;
#pragma pack(pop)

void print_ether_header(ether_header* eh);
void print_ip(ip_header* ip);
void print_tcp(tcp_header* tcp, ip_header* ih);
void print_tls(record_layer* rl);


struct packet* pk = (packet*)malloc(sizeof(struct packet));

int main()
{

	tcp_header* tcp = NULL;
	udp_header* udp = NULL;
	int tcpCheck = 0;
	int udpCheck = 0;

	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum, inum1, inum2;
	int i = 0;
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	const char* packet_filter = "";
	struct bpf_program fcode;

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\n\n--------------------------------------------------------\n");
	printf("어떤 패킷을 캡처할지 고르세요.\n");
	printf("--------------------------------------------------------\n");
	printf("1:TCP(HTTP, FTP, TELNET, SSH, SMTP, POP3, IMAP, P2P)\n");
	printf("2:UDP(DNS, DHCP)\n");
	printf("3.ARP\n");
	printf("3:RARP\n");
	printf("5:ALL\n");
	printf("--------------------------------------------------------\n");
	printf("번호 : (1-4) : ");

	scanf("%d", &inum1);

	if (inum1 == 1) {
		packet_filter = "tcp";
		printf("\n\n--------------------------------------------------------\n");
		printf("어떤 패킷을 캡처할지 고르세요.\n");
		printf("--------------------------------------------------------\n");
		printf("1:HTTP\n");
		printf("2:FTP\n");
		printf("3:TELNET\n");
		printf("4:SSH\n");
		printf("5:SMTP\n");
		printf("6:POP3\n");
		printf("7:IMAP\n");
		printf("8:P2P\n");
		printf("9:ALL(TCP)\n");
		printf("--------------------------------------------------------\n");
		printf("번호 : (1-9) : ");

		scanf("%d", &inum2);
	}
	else if (inum1 == 2) {
		packet_filter = "udp";
		printf("\n\n--------------------------------------------------------\n");
		printf("어떤 패킷을 캡처할지 고르세요.\n");
		printf("--------------------------------------------------------\n");
		printf("1:DNS\n");
		printf("2:DHCP\n");
		printf("3:ALL(UDP)\n");
		printf("--------------------------------------------------------\n");
		printf("번호 : (1-9) : ");
		scanf("%d", &inum2);
	}
	else if (inum1 == 3) {
		packet_filter = "arp";
		inum2 = 0;
	}
	else if (inum1 == 4) {
		packet_filter = "eth.type == 0x0835";
		inum2 = 0;
	}
	else if (inum1 == 5) {
		inum2 = 0;
	}
	else {
		return 0;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;

	else
		/* If the interface is without an address
		 * we suppose to be in a C class network */
		netmask = 0xffffff;

	if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(fp, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);

	struct pcap_pkthdr* header;

	const unsigned char* pkt_data;
	const unsigned char* ether_data;
	int res;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;

		ether_data = pkt_data;
		if (pkt_data[13] == 0x00) {
			pk->eh = (struct ether_header*)pkt_data;
			pkt_data = pkt_data + 14;

			struct ip_header* ih;
			ih = (ip_header*)pkt_data;

			int iplen = ih->ip_leng * 4;
			pk->ip = ih;

			pkt_data = pkt_data + iplen;
			struct tcp_header* th;
			th = (tcp_header*)pkt_data;

			pk->tcp = th;

			int tcplen = ((ntohs(th->thl_flags) >> 12) & 0xf) * 4;
			pkt_data = pkt_data + tcplen;
			struct record_layer* rl;
			rl = (record_layer*)pkt_data;



			int udplen;


			print_tls(rl);
		}
	}
}
void print_ether_header(ether_header* data) {
	struct ether_header* eh;
	mac* srcmac;
	mac* destmac;
	u_short ptype;
	eh = data;

	destmac = (mac*)eh;
	srcmac = (mac*)(eh + 6);
	ptype = ntohs(eh->ether_type);

	printf("******************** Ethernet Frame Header ********************\n"); //Ethernet Frame Header
	printf("\n");
	printf("\n");
	printf("Destination : %02x.%02x.%02x.%02x.%02x.%02x \n",
		destmac->byte1,
		destmac->byte2,
		destmac->byte3,
		destmac->byte4,
		destmac->byte5,
		destmac->byte6);
	printf("\n");
	printf("Source : %02x.%02x.%02x.%02x.%02x.%02x \n",
		srcmac->byte1,
		srcmac->byte2,
		srcmac->byte3,
		srcmac->byte4,
		srcmac->byte5,
		srcmac->byte6);
	printf("\n");

	if (ntohs(eh->ether_type) == IPv4_HEADER)
	{
		printf("Type: IPv4 (0x%04x)\n", ptype);
	}
	else if (ntohs(eh->ether_type) == IPv6_HEADER) {
		printf("Type: IPv6(0x%04x)\n", ptype);
	}
	else if (ntohs(eh->ether_type) == ARP_HEADER) {
		printf("Type: ARP(0x%04x)\n", ptype);
	}
	else if (ntohs(eh->ether_type) == RARP_HEADER) {
		printf("Type: RARP(0x%04x)\n", ptype);
	}
	else {
		printf("Type: Unknown(0x%04x)\n", ptype);
	}
	printf("\n");
}

void print_ip(ip_header* ip) {
	print_ether_header(pk->eh);
	printf("************************** IP Header **************************\n");
	printf("\n");
	printf("\n");
	printf("version: %d\n", ip->ip_version);
	printf("\n");
	printf("Header Length: %d bytes (%d)\n", (ip->ip_leng) * 4, ip->ip_leng);
	printf("\n");
	printf("Differentiated Services Field: 0x%02x\n", ip->tos);
	printf("\n");
	printf("Total Length: %d\n", ntohs(ip->tlen));
	printf("\n");
	printf("Identification: 0x%04x (%d)\n", ntohs(ip->identification), ntohs(ip->identification));
	printf("\n");
	if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 0) {
		printf("Flags: 0x0\n");
	}
	else if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 1) {
		printf("Flags: 0x1, More fragment\n");
	}
	else if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 2) {
		printf("Flags: 0x2, Don't fragment\n");
	}
	printf("\n");
	printf("Fragment Offset: %d\n", ntohs(ip->flags_fo) & 0x1FFF);
	printf("\n");
	printf("Time To Live: %d\n", ip->ttl);
	printf("\n");
	if (ip->proto == ICMP) {
		printf("Protocol: ICMP (%d)\n", ip->proto);
	}
	else if (ip->proto == IGMP) {
		printf("Protocol: IGMP (%d)\n", ip->proto);
	}
	else if (ip->proto == TCP) {
		printf("Protocol: TCP (%d)\n", ip->proto);
	}
	else if (ip->proto == EGP) {
		printf("Protocol: EGP (%d)\n", ip->proto);
	}
	else if (ip->proto == UDP) {
		printf("Protocol: UDP (%d)\n", ip->proto);
	}
	else if (ip->proto == OSPF) {
		printf("Protocol: OSPF (%d)\n", ip->proto);
	}
	else {
		printf("Protocol is Unknown (%d)\n", ip->proto);
	}
	printf("\n");
	printf("Header Checksum: 0x%04x\n", ntohs(ip->crc));
	printf("\n");
	printf("Source IP Address : %d.%d.%d.%d \n",
		ip->saddr.byte1,
		ip->saddr.byte2,
		ip->saddr.byte3,
		ip->saddr.byte4);
	printf("\n");
	printf("Destination IP Address : %d.%d.%d.%d \n",
		ip->daddr.byte1,
		ip->daddr.byte2,
		ip->daddr.byte3,
		ip->daddr.byte4);
	printf("\n");
}

void print_tcp(tcp_header* tcp, ip_header* ip) {
	print_ip(ip);
	printf("************************* TCP Header *************************\n");
	printf("\n");
	printf("\n");
	printf("Source Port: %d\n", ntohs(tcp->sport));
	printf("\n");
	printf("Destination Port: %d\n", ntohs(tcp->dport));
	printf("\n");
	printf("Sequence Number: %u 	(relative sequence number)\n", ntohl(tcp->seqnum));
	printf("\n");
	printf("Acknowledgement Number: %u		(relative ack number)\n", ntohl(tcp->acknum));
	printf("\n");
	printf("Header Length: %d bytes (%d)\n", ((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4, ((ntohs(tcp->thl_flags) >> 12) & 0xf));
	printf("\n");
	if ((ntohs(tcp->thl_flags) & 0x3F) == SYN) {
		printf("Flags: 0x%03x (SYN)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == PUSH) {
		printf("Flags: 0x%03x (PUSH)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == ACK) {
		printf("Flags: 0x%03x (ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == FIN_ACK) {
		printf("Flags: 0x%03x (FIN, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == SYN_ACK) {
		printf("Flags: 0x%03x (SYN, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == PUSH_ACK) {
		printf("Flags: 0x%03x (PUSH, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	printf("Window: %d\n", ntohs(tcp->win));
	printf("\n");
	printf("Checksum: 0x%04x\n", ntohs(tcp->crc));
	printf("\n");
	printf("Urgent Pointer: %d\n", tcp->urgptr);
	printf("\n");
}

void print_tls(record_layer* rl) {
	print_tcp(pk->tcp, pk->ip);
	printf("****************** TLSv1.2 Record Layer *****************\n");
	printf("\n");
	if (rl->rl_type == CHANGE_CIPHER_SPEC) {
		ccs_proto* cp;
		cp = (ccs_proto*)rl;
		printf("Content Type: Change Cipher Spec (%d)\n", CHANGE_CIPHER_SPEC);
	}
	else if (rl->rl_type == ALERT) {
		alert_proto* ap;
		ap = (alert_proto*)rl;
		printf("Content Type: Alert (%d)\n", ALERT);
	}
	else if (rl->rl_type == HANDSHAKE) {
		printf("Content Type: Handshake (%d)\n", HANDSHAKE);
	}
	else if (rl->rl_type == APPLICATION_DATA) {
		application_proto* appli = (application_proto*)malloc(ntohs(rl->rl_length) * sizeof(char));
		appli = (application_proto*)rl;
		printf("Content Type: Application data (%d)\n", APPLICATION_DATA);
	}

	printf("\n");
	if (ntohs(rl->rl_version) == TLS_1_0) {
		printf("Version: TLS 1.0 (0x%04x)\n", ntohs(rl->rl_version));
	}
	else if (ntohs(rl->rl_version) == TLS_1_1) {
		printf("Version: TLS 1.1 (0x%04x)\n", ntohs(rl->rl_version));
	}
	else if (ntohs(rl->rl_version) == TLS_1_2) {
		printf("Version: TLS 1.2 (0x%04x)\n", ntohs(rl->rl_version));
	}

	printf("\n");
	printf("Length: %d\n", ntohs(rl->rl_length));
	printf("\n");
	if (rl->rl_type == CHANGE_CIPHER_SPEC) {
		printf("Change Cipher Spec Message\n");
	}
	else if (rl->rl_type == ALERT) {
		printf("Alert Message: Encrypted Alert\n");
		/*if (ap->alert_level == 0x01) {
			printf("WARNING\n");
		}
		else if (ap->alert_level == 0x02) {
			printf("FATAL\n");
		}

		if (ap->alert_descl == 0x00) {
			printf("CLOSE_NOTIFY");
		}
		else if (ap->alert_descl == 0x64) {
			printf("NO_RENEGOTIATION\n");
		}
		else if (ap->alert_descl == 0x0A) {
			printf("UNEXPECTED_MESSAGE\n");
		}
		else if (ap->alert_descl == 0x14) {
			printf("BAD_RECORD_MAC\n");
		}
		else if (ap->alert_descl == 0x15) {
			printf("DECRYPTION_FAILED\n");
		}
		else if (ap->alert_descl == 0x28) {
			printf("HANDSHAKE_FAILURE\n");
		}
		else if (ap->alert_descl == 0x2A) {
			printf("BAD_CERTIFICATE\n");
		}
		else if (ap->alert_descl == 0x2B) {
			printf("UNSUPPORTED_CERTIFICATE\n");
		}
		else if (ap->alert_descl == 0x2C) {
			printf("CERTIFICATE_REVOKE\n");
		}
		else if (ap->alert_descl == 0x2D) {
			printf("CERTIFICATE_EXPIRED\n");
		}
		else {
			printf("UNKNOWN ALERT\n");
		}*/
	}
	else if (rl->rl_type == APPLICATION_DATA) {
		application_proto* appli = (application_proto*)malloc(ntohs(rl->rl_length) * sizeof(char));
		appli = (application_proto*)rl;
		printf("Encrypted Application Data: ");
		for (int i = 0; i < ntohs(appli->app_leng); i++) {
			printf("%02x", appli->app_enc_data[i]);
		}
	}
	else if (rl->rl_type == HANDSHAKE) {
		handshake_protocol* hp;
		hp = (handshake_protocol*)((u_char*)rl + 5);
		printf("****************** Handshake Type *****************\n");
		printf("\n");
		if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == HELLO_REQUEST) {
			printf("Handshake Type: Hello Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_HELLO) {
			client_hello* ch;
			ch = (client_hello*)((u_char*)hp + 6);
			printf("Handshake Type: Client Hello (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}

			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO) {
			printf("Handshake Type: Server Hello (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == NEW_SESSION_TICKET) {
			printf("Handshake Type: New Session Ticket (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE) {
			printf("Handshake Type: Certificate (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_KEY_EXCHANGE) {
			printf("Handshake Type: Server Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_REQUEST) {
			printf("Handshake Type: Certificate Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO_DONE) {
			printf("Handshake Type: Server Hello Done (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_VERIFY) {
			printf("Handshake Type: Certificate Verify (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_KEY_EXCHANGE) {
			printf("Handshake Type: Client Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == FINISHED) {
			printf("Handshake Type: Finished (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
			printf("\n");
			printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
			printf("\n");
			if (ntohs(hp->handshake_version) == TLS_1_0) {
				printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_1) {
				printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			else if (ntohs(hp->handshake_version) == TLS_1_2) {
				printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
				printf("\n");
			}
			_sleep(10000);
		}
	}
	printf("\n");
}

