int change;
extern char srcip[16];
extern int port;
extern unsigned long int pkt_count;
extern int check_helper;
extern int soc;

struct pseudoHeader    //needed for checksum calculation
{
    unsigned int sourceAddress;
    unsigned int destAddress;
    unsigned char placeHolder;
    unsigned char protocol;
    unsigned short tcpLength;

    struct tcphdr tcp;
};


unsigned short checkSum(unsigned short * buf, int nwords);
int strtoint_n(char* str, int n);
int strtoint(char* str);
int randomPort();
int getRand();
char* spoof();
void myHandler(int signal);
int validIP(char *ipv4);
