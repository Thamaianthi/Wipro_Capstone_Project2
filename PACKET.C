#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>   // For standard things
#include <stdlib.h>  // malloc
#include <string.h>  // strlen

#include <netinet/ip_icmp.h>  // Provides declarations for icmp header
#include <netinet/udp.h>      // Provides declarations for udp header
#include <netinet/tcp.h>      // Provides declarations for tcp header
#include <netinet/ip.h>       // Provides declarations for ip header
#include <netinet/if_ether.h> // For ETH_P_ALL
#include <net/ethernet.h>     // For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include<pthread.h>

#define MAX_LINES 200
#define LINE_LENGTH 256
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define RESET "\x1b[0m"

int type=0;
void ProcessPacket(unsigned char *, int, int[]);
void print_tcp_packet(unsigned char *, int, FILE *);
void print_udp_packet(unsigned char *, int, FILE *);
void PrintData(unsigned char *, int);
void* readPacket(void* arg);

typedef struct 
{
    char source_ip[16];
    char destination_ip[16];
    int packet_size;
    char protocol_type[8];
    int source_port;
    int destination_port;
}Packet;


Packet packets[MAX_LINES];

FILE *udpFile;
FILE *tcpFile;
struct sockaddr_in source, dest,saddr;
int tcpCount = 0, udpCount = 0, icmpCount = 0, igmpCount = 0, othersCount = 0, total = 0, i, j;

void processProtocol(int protocol) 
{
    switch(protocol) 
    {
        case 1:printf("TCP protocol selected.\n");
               break;
        case 2:printf("UDP protocol selected.\n");
               break;
        default:printf("Invalid protocol selection.\n");
                break;
    }
}
void read_tcp_packets(const char *file_path, Packet packets[], int max_lines) 
{
   FILE *file;
    char line[LINE_LENGTH];
    int packet_index = 0;
    Packet current_packet;

    file = fopen(file_path, "r");
    if (file == NULL) 
    {
        fprintf(stderr, "Could not open file\n");
        return;
    }

    while (fgets(line, sizeof(line), file) && packet_index < 30) 
    {
        if (strncmp(line, "Source IP:", 10) == 0) 
        {
            sscanf(line, "Source IP: %15s", current_packet.source_ip);
        } 
        else if (strncmp(line, "Destination IP:", 15) == 0) 
        {
            sscanf(line, "Destination IP: %15s", current_packet.destination_ip);
        } 
        else if (strncmp(line, "Packet Size:", 12) == 0) 
        {
            sscanf(line, "Packet Size: %d", &current_packet.packet_size);
        }
        else if (strncmp(line, "Protocol Type:", 14) == 0) 
        {
            sscanf(line, "Protocol Type: %7s", current_packet.protocol_type);
        } 
        else if (strncmp(line, "Source Port:", 12) == 0) 
        {
            sscanf(line, "Source Port: %d", &current_packet.source_port);
        } 
        else if (strncmp(line, "Destination Port:", 17) == 0) 
        {
            sscanf(line, "Destination Port: %d", &current_packet.destination_port);
        } 
        else if (strncmp(line, "TCP Packet", 10) == 0) 
        {
            packets[packet_index++] = current_packet;
        }
    }
    fclose(file);
}

void read_udp_packets(const char *file_path, Packet packets[], int max_lines) 
{
    FILE *file;
    char line[LINE_LENGTH];
    int packet_index = 0;
    Packet current_packet;

    file = fopen(file_path, "r");
    if (file == NULL) 
    {
        fprintf(stderr, "Could not open file\n");
        return;
    }
    while (fgets(line, sizeof(line), file) && packet_index < 30) 
    {
        if (strncmp(line, "Source IP:", 10) == 0)
        {
            sscanf(line, "Source IP: %15s", current_packet.source_ip);
        }
        else if (strncmp(line, "Destination IP:", 15) == 0) 
        {
            sscanf(line, "Destination IP: %15s", current_packet.destination_ip);
        } 
        else if (strncmp(line, "Packet Size:", 12) == 0) 
        {
            sscanf(line, "Packet Size: %d", &current_packet.packet_size);
        } 
        else if (strncmp(line, "Protocol Type:", 14) == 0) 
        {
            sscanf(line, "Protocol Type: %7s", current_packet.protocol_type);
        } 
        else if (strncmp(line, "Source Port:", 12) == 0) 
        {
            sscanf(line, "Source Port: %d", &current_packet.source_port);
        }
        else if (strncmp(line, "Destination Port:", 17) == 0)
        {
            sscanf(line, "Destination Port: %d", &current_packet.destination_port);
        } 
        else if (strncmp(line, "UDP Packet", 10) == 0) 
        {
            packets[packet_index++] = current_packet;
        }
    }
    fclose(file);
}

void readFile(int fileNumber) 
{
    pthread_t read;
    switch(fileNumber) 
    {
        case 1:type=1;
               printf("Reading TCP file...\n");
               // read_tcp_packets("tcp.txt", packets, MAX_LINES);
               pthread_create(&read,NULL,readPacket,NULL);
               break;
        case 2:type=2;
               printf("Reading UDP file...\n");
               pthread_create(&read,NULL,readPacket,NULL);
               // read_udp_packets("udp.txt", packets,MAX_LINES);
               break;
        default:printf("Invalid file number.\n");
                break;
    }
}

void print_packets(Packet packets[], int count) 
{
    
    printf("%-15s %-15s %-12s %-15s %-12s %-15s\n", "Source IP", "Destination IP", "Packet Size", "Protocol Type", "Source Port", "Destination Port");
    printf("----------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < 28; i++) 
    {
        printf("%-15s %-15s %-12d %-15s %-12d %-15d\n",
               packets[i].source_ip,
               packets[i].destination_ip,
               packets[i].packet_size,
               packets[i].protocol_type,
               packets[i].source_port,
               packets[i].destination_port);
    }
}

void print_graph(Packet packets[], int count)
{
    printf("Packet Sizes Bar Graph\n");
    printf("-----------------------\n");

    int max_size = 0;
    for (int i = 0; i < 30; i++) 
    {
        if (packets[i].packet_size > max_size) 
        {
            max_size = packets[i].packet_size;
        }
    }

    // Print the bar graph
    for (int i = 0; i <30; i++) 
    {
      
        const char* color;
        if (strcmp(packets[i].protocol_type, "TCP") == 0) 
        {
            color = BLUE;
        } 
        else if (strcmp(packets[i].protocol_type, "UDP") == 0)
        {
            color = GREEN;
        } 
        else 
        {
            color = RESET; 
        }
        printf("%-15s -> %-15s [%s%-4s%s] | ", packets[i].source_ip, packets[i].destination_ip, color, packets[i].protocol_type, RESET);
        for (int j = 0; j < packets[i].packet_size * 20 / max_size; j++) 
        {
            printf("%s*%s", color, RESET);
        }
        printf(" %d bytes [%s%d%s -> %s%d%s]\n", packets[i].packet_size, CYAN, packets[i].source_port, RESET, CYAN, packets[i].destination_port, RESET);
    }
}

void printData(int choice) 
{
    switch(choice) 
    {
        case 1:printf("Printing data as Text based histogram...\n");
               print_graph(packets, MAX_LINES);
               break;
        case 2:printf("Printing data as table...\n");
               print_packets(packets, MAX_LINES);
               break;
        default:printf("Invalid choice.\n");
                break;
    }
}

void* readPacket(void* arg)
{
    if(type==1)
    {
        read_tcp_packets("tcp.txt", packets, MAX_LINES);
    }
    else if(type==2)
    {
        read_udp_packets("udp.txt", packets, MAX_LINES);
    }

}
int main(int argc, char *argv[])
{
    // pthread_t tid1;
    int protocol;
    int fileNumber;
    int choice;
    int saddr_size, data_size;
    unsigned char *buffer = (unsigned char *)malloc(65536); // It's Big!

    udpFile = fopen("udp.txt", "a");
    tcpFile = fopen("tcp.txt", "a");
    

    if (udpFile == NULL || tcpFile == NULL )
    {
        printf("Unable to create log files.");
        return 1;
    }

    printf("Starting...\n");

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        // Print the error with proper message
        perror("Socket Error");
        return 1;
    }

    int protocols[4] = {0}; // Index represents protocol: 0-TCP, 1-UDP, 2-ICMP, 3-IGMP
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            int protocol = atoi(argv[i]);
            if (protocol >= 1 && protocol <= 4)
            {
                protocols[protocol - 1] = 1;
            }
        }
    }
    else
    {
        int c;
        printf("No command line arguments entered. Entering interactive shell.\n");
        printf("Select the protocols and choose 4 to read the file :\n");
        printf("1. TCP\n");
        printf("2. UDP\n");
        printf("3. Showfile\n");
        scanf("%d",&c);
        if (c == 3) 
        {
            // Ask user which file to read
            printf("Which file do you want to read?\n");
            printf("1. TCP file\n");
            printf("2. UDP file\n");
            printf("Enter file number (1-3): ");

            scanf("%d", &fileNumber);

            readFile(fileNumber);

            // Ask user how to print data
            printf("How do you want to print the data?\n");
            printf("1. Histogram\n");
            printf("2. Table\n");
            printf("Enter choice (1 or 2): ");
            scanf("%d", &choice);
            printData(choice);
        } 
        else if (c >= 1 && c <= 3)
        {
            protocols[c - 1] = 1;
        }
        char input[256];
        fgets(input, sizeof(input), stdin);
        char *token = strtok(input, " ");
        while (token != NULL)
        {
            int protocol = atoi(token);
            if (protocol >= 1 && protocol <= 4)
            {
                protocols[protocol - 1] = 1;
            }
            token = strtok(NULL, " ");
        }
    }
    printf("Listening for selected protocols...\n");
    while (1)
    {
        saddr_size = sizeof saddr;
        // Receive a packet
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0)
        {
            printf("Recvfrom error, failed to get packets\n");
            return 1;
        }
        // Now process the packet based on selected protocols
        ProcessPacket(buffer, data_size, protocols);
    }
    close(sock_raw);
    fclose(tcpFile);
    fclose(udpFile);
    printf("Finished\n");
    return 0;
}

void ProcessPacket(unsigned char *buffer, int size, int protocols[])
{
    // Get the IP Header part of this packet, excluding the ethernet header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) // Check the Protocol and do accordingly...
    {
        case 1: // TCP Protocol
                if (protocols[0])
                {
                    ++tcpCount;
                    print_tcp_packet(buffer, size, tcpFile);
                }
                break;
        case 2: // UDP Protocol
                if (protocols[1])
                {
                    ++udpCount;
                    print_udp_packet(buffer, size, udpFile);
                }
                break;
        default:++othersCount;
                break;
    }
    printf("TCP : %d   UDP : %d      Others : %d   Total : %d\r", tcpCount, udpCount, othersCount, total);
}

void print_tcp_packet(unsigned char *Buffer, int Size, FILE *tcpLogFile) 
{
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(Buffer + iph->ihl * 4 + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(tcpLogFile, "TCP Packet\n");
    fprintf(tcpLogFile, "Source IP: %s\n", inet_ntoa(source.sin_addr));
    fprintf(tcpLogFile, "Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    fprintf(tcpLogFile, "Packet Size: %d bytes\n", Size);
    fprintf(tcpLogFile, "Protocol Type: TCP\n");
    fprintf(tcpLogFile, "Source Port: %u\n", ntohs(tcph->source));
    fprintf(tcpLogFile, "Destination Port: %u\n", ntohs(tcph->dest));
    fprintf(tcpLogFile, "\n");
}

void print_udp_packet(unsigned char *Buffer, int Size, FILE *udpLogFile) 
{
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    struct udphdr *udph = (struct udphdr *)(Buffer + iph->ihl * 4 + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(udpLogFile, "UDP Packet\n");
    fprintf(udpLogFile, "Source IP: %s\n", inet_ntoa(source.sin_addr));
    fprintf(udpLogFile, "Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    fprintf(udpLogFile, "Packet Size: %d bytes\n", Size);
    fprintf(udpLogFile, "Protocol Type: UDP\n");
    fprintf(udpLogFile, "Source Port: %u\n", ntohs(udph->source));
    fprintf(udpLogFile, "Destination Port: %u\n", ntohs(udph->dest));
    fprintf(udpLogFile, "\n");
}


void PrintData(unsigned char *data, int Size)
{
    int i, j;
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0) //if one line of hex printing is complete...
        {
            printf("         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    printf("%c", (unsigned char)data[j]); //if it's a number or alphabet
                else
                    printf("."); //otherwise print a dot
            }
            printf("\n");
        }
        if (i % 16 == 0)
            printf("   ");
        printf(" %02X", (unsigned int)data[i]);
        if (i == Size - 1) //print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                printf("   "); //extra spaces
            }
            printf("         ");
            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    printf("%c", (unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}
