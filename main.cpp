#include <pcap.h>
#include <stdio.h>
#include <stdint.h>


#define MAC_ADR_LEN 6
#define IP_ADR_LEN 4
#define PORT_LEN 2
#define ETHERNET_LENGTH 14
#define TCP_DATA_LENGTH 10

struct ethernet_header {
    uint8_t dmac[MAC_ADR_LEN];
    uint8_t smac[MAC_ADR_LEN];
    uint16_t type;
};

struct ip_header {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identifier;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[IP_ADR_LEN];
    uint8_t dip[IP_ADR_LEN];
};

struct tcp_header {
    uint8_t sport[PORT_LEN];
    uint8_t dport[PORT_LEN];
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t header_length;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct tcp_data {
    uint8_t data[10];
};

uint16_t my_ntohs(uint16_t n) {
    return n << 8 | n >> 8;
}

uint32_t my_ntohl(uint32_t n) {
    return (n & 0xFF000000) >> 24 |
           (n & 0x00FF0000) >> 8 |
           (n & 0x0000FF00) << 8 |
           (n & 0x000000FF) << 24;
}

typedef struct ethernet_header ethernet;
typedef struct ip_header ip;
typedef struct tcp_header tcp;
typedef struct tcp_data data;


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void smac_print(uint8_t *smac) {
    printf("source mac address : ");
    for(int i = 0; i < MAC_ADR_LEN; i++) {
        if(i == MAC_ADR_LEN -1){
            printf("%02X\n",smac[i]);
        }
        else {
        printf("%02X:",smac[i]);
        }
    }
}
void dmac_print(uint8_t *dmac) {
    printf("destination mac address : ");
    for(int i = 0; i < MAC_ADR_LEN; i++) {
        if(i == MAC_ADR_LEN -1){
            printf("%02X\n",dmac[i]);
        }
        else {
        printf("%02X:",dmac[i]);
        }
    }
}

void sip_print(uint8_t *sip) {
     printf("source IP address : ");
     for(int i = 0; i < IP_ADR_LEN; i++){
         if(i == IP_ADR_LEN - 1) {
             printf("%u\n",sip[i]);
         }
         else {
             printf("%u.",sip[i]);
         }
     }
}
void dip_print(uint8_t *dip) {
     printf("destination IP address : ");
     for(int i = 0; i < IP_ADR_LEN; i++){
         if(i == IP_ADR_LEN - 1) {
             printf("%u\n",dip[i]);
         }
         else {
             printf("%u.",dip[i]);
         }
     }
}

void sport_print(uint16_t sport) {
    printf("source port : ");
    printf("%d\n", my_ntohs(sport));

}

void dport_print(uint16_t dport) {
    printf("destination port : ");
    printf("%d\n", my_ntohs(dport));

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
      usage();
      return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);


   ethernet_header *ethernet = (ethernet_header *)packet;
   ip_header *ip = (ip_header *)(packet + ETHERNET_LENGTH);
   uint8_t ip_header_length = ((ip->vhl) & 0x0F) * 4;
   tcp_header *tcp = (tcp_header *)(packet + ETHERNET_LENGTH + ip_header_length);
   uint8_t tcp_header_length = (((tcp->header_length & 0xF0) >> 4) * 4);
   tcp_data *data = (tcp_data *)(packet + ETHERNET_LENGTH + ip_header_length + tcp_header_length);

   uint16_t *sp = reinterpret_cast<uint16_t*>(tcp->sport);
   uint16_t sport = *sp;
   uint16_t *dp = reinterpret_cast<uint16_t*>(tcp->dport);
   uint16_t dport = *dp;

   if(my_ntohs(ethernet->type) == 0x0800) {
       if(ip->protocol == 0x06) {
            printf("--------------------------------------\n");
            smac_print(ethernet->smac);
            dmac_print(ethernet->dmac);
            sip_print(ip->sip);
            dip_print(ip->dip);
            sport_print(sport);
            dport_print(dport);

            if((ip->total_length) - ip_header_length - tcp_header_length == 0) {
                printf("No Data\n");
            }
            else {
                for(int i = 0; i < 10; i++) {
                    printf("%02X ",data->data[i]);
                }
            }
            printf("\n");
           }
       }
   }

  pcap_close(handle);
  return 0;
}
