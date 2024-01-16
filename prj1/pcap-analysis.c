///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////
//  CIS 549: Wireless Mobile Communications
//  Project #1: Network Packet Manipulation and Packet Trace Analysis
///////////////////////////////////////////
//
// Detailed information is available at the link below
//    https://wiki.wireshark.org/Development/LibpcapFileFormat
//
// Modify TCPDUMP file 
// TCPDUMP file format is 
//
// Global Header < -- The pcap file contains this structure at the beginning.
//
// struct pcap_file_header {
//  unsigned int magic;            4 bytes  //  magic number 
//  unsigned short version_major;  2 bytes  //  major version number 
//  unsigned short version_minor;  2 bytes  //  minor version number
//  unsigned int thiszone;         4 bytes  //  GMT to local correction
//  unsigned int sigfigs;          4 bytes  //  accuracy of timestamps
//  unsigned int snaplen;          4 bytes  //  max length of captured packets, in octets
//  unsigned int linktype;         4 bytes  //  data link type
//  };
//
//
// And then One packet per line in the pcap file
//
// Record (Packet) Header <-- this is not a protocol header
//
// struct pcap_pkthdr{
//  unsigned int time_sec;            4 bytes   //  timestamp seconds
//  unsigned int time_usec;           4 bytes   //  timestamp microseconds
//  unsigned int captured_len;        4 bytes   //  number of octets of packet saved in file
//  unsigned int off_wire_pkt_length; 4 bytes   //  actual length of packet
//  };
//
// Wireshark displays following information only in the Frame View
// struct captured_packet {     Total size of this structure is same as captured_len above.
//    source MAC address                 6 bytes
//    Destination MAC address            6 bytes
//    Packet type (IP packet = 8)        2 bytes
//    IP header length(if pkt type is IP)1 bytes
//     ........
//
// REPEAT "pacp_pkthdr" and "captured_packet" structures until the end of the captured file.
//
////////////////////////////////////////////////////////////////////////////////////////////////

#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

#define TCP_TYPE_NUM 6
#define LEFT 0
#define RIGHT 1
#define YES 1
#define NO 0

#define MAX_TCP_SESSION_CONNECTION_STORAGE 100

/*Packet Information Array Location assuming VLAN (802.1q) Tag is not included in the Ethernet frame*/
/* If VLAN tag is in the Ethernet frame, then the following protocol field location must be shifted by the length of the VLAN Tag field */
#define IP_HDR_LEN_LOC 14 /*IP Packet header Length */
#define TCP_TYPE_LOC 23 /*TCP packet type */
#define TCP_SRC_PORT 34 /*2 bytes */
#define TCP_DST_PORT 36 /*2 bytes */
#define SEQ_NUM 38 /*4 Bytes */
#define ACK_NUM 42 /*4 Bytes */
#define IP_ADDR_START_LOC_VLAN_TYPE 30
#define IP_ADDR_START_LOC_IP_TYPE 26
#define IP_PKT_SIZE_LOC_VLAN_TYPE 20 /*2 bytes from this location*/
#define IP_PKT_SIZE_LOC_IP_TYPE 16 /*2 bytes from this location*/

// EtherType value
// 0x0800 : IPv4 datagram
// 0x0806 : ARP frame
// 0x8100 : IEEE 802.1Q frame
// 0x86DD : IPv6 frame
#define ETHER_PROTOCOL_TYPE_LOC 12
#define IP_PAYLOAD_TYPE_LOC 23 /*ICMP type, size:1 Byte, value: 0X01 */
#define ICMP_TYPE_LOC 34 /*1 byte */

/*packet information */
#define IP_PAYLOAD_ICMP 1
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define VLAN_TYPE 129 /*HEX=81 00*/
#define IP_TYPE 8 /*packet type */
#define NUM_PKT 1000 /*number of packets in a tcpdump file */
#define MAX_PKT_LEN 1700


#if defined(_WIN32)
typedef unsigned int u_int;
#endif

unsigned int pkt_header[4];
unsigned char one_pkt[MAX_PKT_LEN];

struct packet {
    unsigned int src_ip_first;
    unsigned int src_ip_second;
    unsigned int src_ip_third;
    unsigned int src_ip_fourth;

    unsigned int dst_ip_first;
    unsigned int dst_ip_second;
    unsigned int dst_ip_third;
    unsigned int dst_ip_fourth;

    unsigned int src_port;
    unsigned int dst_port;
    unsigned int ethertype;
    unsigned int ip_protocol;
    unsigned int ip_total_len;
    unsigned int ip_header_len;
    unsigned int tcp_header_len;
    unsigned int flag;
};

 // 0: serverIP, 1: clientIP, 2: serverPort, 3: clientPort, 4: num_of_packetSent(server->client), 5: totalIPtrafficBytesSent(server->client),  
        // 6: TotaluserTrafficBytesSent(server->client), 7: sessionDuration, 8: bits/s_IPlayerThroughput(server->client), 9: bits/s_Goodput(server->client)
struct tcp_session {
    unsigned int server_ip_first;
    unsigned int server_ip_second;
    unsigned int server_ip_third;
    unsigned int server_ip_fourth;

    unsigned int client_ip_first;
    unsigned int client_ip_second;
    unsigned int client_ip_third;
    unsigned int client_ip_fourth;

    unsigned int server_port;
    unsigned int client_port;
    int num_packets;
    unsigned int total_bytes_sent;
    unsigned int user_bytes_sent;
    double session_duration;
    double throughput;
    double goodput;
};

unsigned int bits_to_ui(char* x, int byte_count, int order)
/*********************************************/
/* Convert bits to unsigned int  */
/*********************************************/
{
    unsigned int displayMask = 1;
    int i, j, location = 0;
    unsigned int result = 0;

    if (order == 0) {
        for (j = byte_count - 1; j >= 0; j--) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask) {
                    result = result + pow(2, location);
                    //printf("1");
                }
                else {
                    //printf("0");
                }

                location++;
                x[j] >>= 1;
            }
        }

        //printf("\n");
    }
    else {
        for (j = 0; j < byte_count; j++) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask)
                    result = result + pow(2, location);
                location++;
                x[j] >>= 1;
            }
        }
    }

    return result;
}

void ping_response_time_finder(char* in_filename)
{
    FILE* fd;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    int k = 0;
    double start_time, end_time;
    int looking_for_start;

    fd = fopen(in_filename, "rb");
    if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd) == 0) {
        perror("File header Error");
        exit(1);
    }

    looking_for_start = YES;

    while (!feof(fd)) {
        for (k = 0; k < MAX_PKT_LEN; k++)
            one_pkt[k] = '\0';

        fread(pkt_header, sizeof(unsigned int), 4, fd);
        captured_len = pkt_header[2];
        if (captured_len == 0) {
            // do nothing
        }
        else {
            if (looking_for_start == YES) {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REQUEST) {
                    looking_for_start = NO;
                }
            }
            else {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REPLY) {
                    looking_for_start = YES;

                    printf("%d.%d.%d.%d %d %f\n", (unsigned int)one_pkt[26], (unsigned int)one_pkt[27],
                        (unsigned int)one_pkt[28], (unsigned int)one_pkt[29], captured_len, end_time - start_time);
                }
            }
        }
    }

    fclose(fd);

} /*end func */

void fix_frame_len(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        if (captured_len > 0) {
            fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);
            if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x08) // 0x0800 : IPv4 datagram.
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 1] + 14;
            else if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x81) // 0x8100 : IEEE 802.1Q frame
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 4] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 5] + 18;

            if (!feof(fd_in)) {
                fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
                fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
            }
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

void ip_address_change(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int dst_ip_1st_digit, dst_ip_2nd_digit, dst_ip_3rd_digit, dst_ip_4th_digit;
    unsigned int src_port_num, dst_port_num;
    unsigned int seq_n = 0, ack_n = 0;

    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);

        src_ip_1st_digit = (unsigned int)one_pkt[26];
        src_ip_2nd_digit = (unsigned int)one_pkt[27];
        src_ip_3rd_digit = (unsigned int)one_pkt[28];
        src_ip_4th_digit = (unsigned int)one_pkt[29];
        dst_ip_1st_digit = (unsigned int)one_pkt[30];
        dst_ip_2nd_digit = (unsigned int)one_pkt[31];
        dst_ip_3rd_digit = (unsigned int)one_pkt[32];
        dst_ip_4th_digit = (unsigned int)one_pkt[33];

        if (dst_ip_1st_digit == 192 && dst_ip_2nd_digit == 11 && dst_ip_3rd_digit == 68 && dst_ip_4th_digit == 196) {
            one_pkt[30] = 192;
            one_pkt[31] = 11;
            one_pkt[32] = 68;
            one_pkt[33] = 1;
        }

        if (src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) {
            one_pkt[26] = 192;
            one_pkt[27] = 11;
            one_pkt[28] = 68;
            one_pkt[29] = 1;
        }

        if (!feof(fd_in)) {
            fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
            fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

void tcp_analysis(char *in_filename, char *out_filename)
{
    FILE *fd_in, *fd_out; // open the input & output file
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    
    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(out_filename, "w");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    int total_sessions = 0; // used to keep track of how many total TCP sessions we have actually seen
    struct tcp_session tcp_sessions[100]; // array of tcp sessions seen

    while (!feof(fd_in))
    {
        
        fread(pkt_header, sizeof(unsigned int), 4, fd_in); // read one packet header
        captured_len = pkt_header[2]; // extract capture_length info
        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in); // read one packet

        struct packet p;
        p.ethertype = (unsigned int)one_pkt[12];
        p.ethertype = p.ethertype << 8;
        p.ethertype += (unsigned int)one_pkt[13];
        int vlan = 0; // for EC: if there is vlan tag, shift everything by 4 bytes
                
        if (p.ethertype == 2048 || p.ethertype == 33024) // if this is an IP packet or VLAN packet
        {
            if (p.ethertype == 33024) {
                vlan = 4; // set vlan tag for shifting
            }
            p.ip_protocol = (unsigned int)one_pkt[23 + vlan];
            
            if (p.ip_protocol == 6) // if this is a TCP packet
            {
                p.flag = (unsigned int)one_pkt[47 + vlan]; // keeps track of SYN or FIN bit

                // SRC IP
                p.src_ip_first = (unsigned int)one_pkt[26 + vlan];
                p.src_ip_second = (unsigned int)one_pkt[27 + vlan];
                p.src_ip_third = (unsigned int)one_pkt[28 + vlan];
                p.src_ip_fourth = (unsigned int)one_pkt[29 + vlan];
                // DST IP
                p.dst_ip_first = (unsigned int)one_pkt[30 + vlan];
                p.dst_ip_second = (unsigned int)one_pkt[31 + vlan];
                p.dst_ip_third = (unsigned int)one_pkt[32 + vlan];
                p.dst_ip_fourth = (unsigned int)one_pkt[33 + vlan];
                // SRC PORT
                p.src_port = (unsigned int)one_pkt[TCP_SRC_PORT + vlan];
                p.src_port = p.src_port << 8;
                p.src_port += (unsigned int)one_pkt[TCP_SRC_PORT+1+vlan];
                // DST PORT
                p.dst_port = (unsigned int)one_pkt[TCP_DST_PORT+vlan];
                p.dst_port = p.dst_port << 8;
                p.dst_port += (unsigned int)one_pkt[TCP_DST_PORT+1+vlan];
                // TOTAL LENGTH OF IP PACKET
                p.ip_total_len = (unsigned int)one_pkt[16+vlan];
                p.ip_total_len = p.ip_total_len << 8;
                p.ip_total_len += (unsigned int)one_pkt[17+vlan];
                // HEADER LENS
                p.ip_header_len = (unsigned int)(one_pkt[14 + vlan] & 0x0F) * 4; // get only last 4 bits
                p.tcp_header_len = ((unsigned int)((one_pkt[46 + vlan] & 0xF0) >> 4)) * 4; // get first 4 bits
                    
                if (p.flag == 18) // if this is TCP SYN
                {
                    double start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000); // start of duration

                    struct tcp_session s;
                    // TCP session server IP
                    s.server_ip_first = p.src_ip_first;
                    s.server_ip_second = p.src_ip_second;
                    s.server_ip_third = p.src_ip_third;
                    s.server_ip_fourth = p.src_ip_fourth;
                    // TCP session client IP
                    s.client_ip_first = p.dst_ip_first;
                    s.client_ip_second = p.dst_ip_second;
                    s.client_ip_third = p.dst_ip_third;
                    s.client_ip_fourth = p.dst_ip_fourth;
                    // TCP session server port & client port
                    s.server_port = p.src_port;
                    s.client_port = p.dst_port;
                    s.num_packets = 1;
                    s.total_bytes_sent = p.ip_total_len;
                    s.user_bytes_sent = 0;
                    s.session_duration = start_time;
                    s.throughput = 0;
                    s.goodput = 0;
                    tcp_sessions[total_sessions] = s; // add TCP session to array to keep track of it
                    total_sessions++;

                }
                else if (p.flag == 17) // if this is TCP FIN packet
                {
                    
                    // go thru TCP sessions to see which one ended & record final data for that
                    for (int i = 0; i < total_sessions; i++) {
                        if (tcp_sessions[i].server_ip_first == p.src_ip_first && tcp_sessions[i].server_ip_second == p.src_ip_second && tcp_sessions[i].server_ip_third == p.src_ip_third && tcp_sessions[i].server_ip_fourth == p.src_ip_fourth &&
                        tcp_sessions[i].client_ip_first == p.dst_ip_first && tcp_sessions[i].client_ip_second == p.dst_ip_second && tcp_sessions[i].client_ip_third == p.dst_ip_third && tcp_sessions[i].client_ip_fourth == p.dst_ip_fourth &&
                        tcp_sessions[i].server_port == p.src_port && tcp_sessions[i].client_port == p.dst_port) {
                            double end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);
                            double start_time = tcp_sessions[i].session_duration;
                            tcp_sessions[i].session_duration = end_time - start_time;
                            tcp_sessions[i].num_packets += 1;
                            tcp_sessions[i].total_bytes_sent += p.ip_total_len;
                            tcp_sessions[i].user_bytes_sent += p.ip_total_len - (p.ip_header_len + p.tcp_header_len);
                            tcp_sessions[i].throughput = (tcp_sessions[i].total_bytes_sent * 8) / tcp_sessions[i].session_duration;
                            tcp_sessions[i].goodput = (tcp_sessions[i].user_bytes_sent * 8) / tcp_sessions[i].session_duration;
                            break;
                        }  
                    }
                }
                else // is a data packet: record data
                {
                    // go thru TCP sessions to see which one matches with the packet given & record data for that
                    for (int i = 0; i < total_sessions; i++) {
                        if (tcp_sessions[i].server_ip_first == p.src_ip_first && tcp_sessions[i].server_ip_second == p.src_ip_second && tcp_sessions[i].server_ip_third == p.src_ip_third 
                        && tcp_sessions[i].server_ip_fourth == p.src_ip_fourth &&
                        tcp_sessions[i].client_ip_first == p.dst_ip_first && tcp_sessions[i].client_ip_second == p.dst_ip_second && tcp_sessions[i].client_ip_third == p.dst_ip_third 
                        && tcp_sessions[i].client_ip_fourth == p.dst_ip_fourth &&
                        tcp_sessions[i].server_port == p.src_port && tcp_sessions[i].client_port == p.dst_port) {
                            tcp_sessions[i].num_packets += 1;
                            tcp_sessions[i].total_bytes_sent += p.ip_total_len;
                            tcp_sessions[i].user_bytes_sent += p.ip_total_len - (p.ip_header_len + p.tcp_header_len);
                            break;
                        }  
                    }
                }
            }
            else { // this is not TCP packet so ignore
                continue;
            }
        }
        else { // this is not IP packet, so ignore
            continue;
        }
    }   // end of WHILE (keep reading packets until the end of the file)   

    // print out all sessions related to our target client and server IPs
    fprintf(fd_out, "TCP_session_count, serverIP, clientIP, serverPort, clientPort, num_of_packetSent(server->client), TotalIPtrafficBytesSent(server->client), TotaluserTrafficBytesSent(server->client), sessionDuration, bps_IPlayerThroughput(server->client), bps_Goodput(server->client)\n");
    fprintf(fd_out, "=========================================================================================================================\n");
    for (int i = 0; i < total_sessions; i++) {
        if (tcp_sessions[i].server_ip_first == 10 && tcp_sessions[i].client_ip_first == 192 && tcp_sessions[i].client_ip_second == 11 && tcp_sessions[i].client_ip_third == 68 && tcp_sessions[i].client_ip_fourth == 196) {
        fprintf(fd_out, "%d\t %d.%d.%d.%d\t %d.%d.%d.%d\t %d\t %d\t %d\t %d\t %d\t %.3f\t %.3f\t %.3f\t", i + 1, tcp_sessions[i].server_ip_first, tcp_sessions[i].server_ip_second, tcp_sessions[i].server_ip_third, tcp_sessions[i].server_ip_fourth, 
            tcp_sessions[i].client_ip_first, tcp_sessions[i].client_ip_second, tcp_sessions[i].client_ip_third, 
            tcp_sessions[i].client_ip_fourth, tcp_sessions[i].server_port, tcp_sessions[i].client_port, tcp_sessions[i].num_packets, tcp_sessions[i].total_bytes_sent, tcp_sessions[i].user_bytes_sent,
            tcp_sessions[i].session_duration, tcp_sessions[i].throughput, tcp_sessions[i].goodput);
        fprintf(fd_out,"\n");
        }
    }
     
    // close both files here
    fclose(fd_in);
    fclose(fd_out);
}

int main(int argc, char* argv[])
{
    printf("Selected Option: %s\n", argv[1]);

    if (strcmp(argv[1], "ping-delay") == 0) {
        ping_response_time_finder(argv[2]);
    }
    else if (strcmp(argv[1], "fix-length") == 0) {
        fix_frame_len(argv[2], argv[3]);
    }
     else if (strcmp(argv[1], "ip-address-change") == 0) {
        ip_address_change(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "tcp-analysis") == 0) {
        // call your function
        tcp_analysis(argv[2], argv[3]);
    }
    else {
        printf("Four options are available.\n");
        printf("===== Four command line format description =====\n");
        printf("1:  ./pcap-analysis ping-delay input-trace-filename\n");
        printf("2:  ./pcap-analysis fix-length input-trace-filename output-trace-filename\n");
        printf("3:  ./pcap-analysis ip-address-change input-trace-filename output-trace-filename\n");
        printf("4:  ./pcap-analysis tcp-analysis  input-trace-filename  output-filename\n");
        printf("===== END =====\n");
    }
} /*end prog */

