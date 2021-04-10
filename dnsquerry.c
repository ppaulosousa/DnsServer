#include<stdio.h> 
#include<string.h>   
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>    
#include <assert.h>
#include <inttypes.h>
#include <time.h>

#define MAX_LENGTH 1024

typedef struct dns_header_st {
    uint16_t xid;
    uint16_t flags; 
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount; 
    uint16_t arcount; 
} dns_header_t;

typedef struct dns_question_st {
    uint16_t dnstype;
    uint16_t dnsclass;
} dns_question_t;

typedef struct {
    uint16_t compression;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    struct in_addr addr;
} __attribute__((packed)) dns_record_a;


int encode_hostname(char *dest, char *hostname) {
    // www.google.com
    //  3www
    //  6google
    //  3com 
    //  0
    int len = strlen(hostname);
    int j = 1; // index for destination
    int prev = 0;
    int word_len = 0;
    for (int i = 0; i < len; i++) {
        if ((hostname[i] != '\0') && (hostname[i] != '.')) {
            dest[j] = hostname[i];
            word_len++;
            j++;
        } else {
            dest[prev] = word_len;
            prev += word_len + 1;
            word_len = 0;
            j++;
        }
    }
    dest[prev] = word_len;
    dest[j] = 0;
    return j+1;
}

int main(int argc, char *argv[]){
	if (argc != 3) {
		printf("Wrong arguments\n");
		return 0;
	}

	char *dns_server = argv[1];
	char *hostname = argv[2];

	// Create udp socket
	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in address;
    address.sin_addr.s_addr = inet_addr(dns_server);    // Convert IPv4 address string to binary representation
	address.sin_family = AF_INET;
    address.sin_port = htons(53);

    dns_header_t dns_header;
    dns_header.xid = htons(0x1234);
    dns_header.flags = htons(0x0100);   // 01 - Read, 00 - Question
    dns_header.qdcount = htons(1);      // argv[2] is only one hostname to resolve, so only one question

    dns_question_t dns_question;
    dns_question.dnsclass = htons(1);   // Type A
    dns_question.dnstype = htons(1);    // Class Internet

    char *udp_payload = calloc(MAX_LENGTH, sizeof(char));   // Allocate and set to 0
    
    int i = 0;
    memcpy(udp_payload + i, &dns_header, sizeof(dns_header_t)); // Copy dns header to payload
    i += sizeof(dns_header_t);  // Offset for name
    i += encode_hostname(udp_payload + i, hostname);            //  Encode hostname
    memcpy(udp_payload + i, &dns_question, sizeof(dns_question_t));
    i += sizeof(dns_question_t);


    
    ssize_t len = sendto(sock_fd, udp_payload, i, 0, (struct sockaddr*) &address, sizeof(struct sockaddr_in));
    socklen_t src_addr_len = 0;
    memset(udp_payload, 0, MAX_LENGTH);        // Set payload to 0
    len = recvfrom(sock_fd, udp_payload, MAX_LENGTH, 0, (struct sockaddr *) &address, (socklen_t*) &src_addr_len);
    printf("Received payload:");
    for (int i = 0; i < len; i++) {
        if ((i % 8) == 0) printf("\t");
        if ((i % 16) == 0) printf("\n");
        printf(" %02X", (unsigned char)udp_payload[i]);
    }
    printf("\n\n");


    // A bruta
    // printf("Type:");
    // for (int i = 34; i < 36; i++) {
    //     printf(" %02X", (unsigned char)udp_payload[i]);
    // }
    // printf("\n");
    // printf("Class:");
    // for (int i = 34; i < 36; i++) {
    //     printf(" %02X", (unsigned char)udp_payload[i]);
    // }
    // printf("\n");
    // printf("TTL:");
    // for (int i = 38; i < 42; i++) {
    //     printf(" %02X", (unsigned char)udp_payload[i]);
    // }
    // printf("\n");
    // printf("Address:");
    // for (int i = 44; i < len; i++) {
        
    //     printf(" %02X", (unsigned char)udp_payload[i]);
    // }
    // printf("\n\n");

    uint8_t response[512];
    memset (&response, 0, 512);

    dns_header_t *response_header = (dns_header_t *)udp_payload;
    assert ((ntohs (response_header->flags) & 0xf) == 0);

    uint8_t *start_of_name = (uint8_t *) (udp_payload + sizeof (dns_header_t));
    uint8_t total = 0;
    uint8_t *field_length = start_of_name;
    
    /* Separar string do ponto */
    while (*field_length != 0)
    {
      total += *field_length + 1;
      *field_length = '.';
      field_length = start_of_name + total;
    }
  *field_length = '\0';

  dns_record_a *records = (dns_record_a *) (field_length + 5);
  for (int i = 0; i < ntohs (response_header->ancount); i++)
    {
      printf ("TYPE: %d\n", ntohs (records[i].type));
      printf ("CLASS: %d\n", ntohs (records[i].class));
      printf ("TTL: %d\n", ntohl (records[i].ttl));
      printf ("IPv4: %s\n", inet_ntoa (records[i].addr));
    }
  return 0;
}
