#include "ether_header.h"
#include "ip_header.h"
#include "tcp_header.h"
#include "tls_header.h"
#include "struct.h"
#include "include.h"
#include "define.h"


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

int main()
{
	extern packet* pk;
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
			pk->app = pkt_data;

			struct ether_header* eh;
			eh = (ether_header*)pk->app;
			pk->eth = eh;

			struct ip_header* ih;
			ih = (ip_header*)(pk->app + ETHER_LENGTH);
			pk->ip = ih;

			struct tcp_header* th;
			th = (tcp_header*)(pk->app + ETHER_LENGTH + (pk->ip->ip_leng * 4));
			pk->tcp = th;

			header = (pcap_pkthdr*)header;
			pk->header = header;

			int udplen;
			
			
			print_tls(ether_data);
		}
	}
}
