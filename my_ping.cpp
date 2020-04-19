#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <regex>
#include <string>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <chrono>
#include <ctime>

using namespace std;

bool is_hostname(const char* target) {
    // Regex pattern from: https://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
    // This pattern could match ip addresses, so never call this first in a series of if-checks
    regex hostname_ptn(
            R"(^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$)"
    );
    return regex_match(target, hostname_ptn);
}

bool is_ip_addr(const char* target) {
    // This pattern won't match hostnames
    regex ip_addr_ptn ("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
    return regex_match(target, ip_addr_ptn);
}

string get_hostname_addr(const char* hostname) {
    struct addrinfo hints{}, *infoptr;
    hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses

    int result = getaddrinfo(hostname, nullptr, &hints, &infoptr);
    if (result) {
        cerr << "getaddrinfo: " << gai_strerror(result) << endl;
        exit(1);
    }

    char host[256];
    // Just arbitrarily pick the first addr in the addrinfo struct linked list
    getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, host, sizeof (host), nullptr, 0, NI_NUMERICHOST);
    cout << host << endl;
    freeaddrinfo(infoptr);

    return host;
}

short checksum(short* pkt_blocks, int num_blocks) {
    // Adds together every 16-bit block from header + data, then return the ones-compliment of the sum
    int sum = 0;
    short *block = pkt_blocks;
    for (int i = 0; i < num_blocks; i++) {
        sum += *block;
        block++;
    }
    return (short) ~sum;  // Flip the bits of sum for ones-compliment

}

// For now, just pass in arguments via arg parser, later can switch to CLI
// that uses arg flags.
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <HOSTNAME or IP_ADDR>" << endl;
        return 1;  // Improper formatting, exit with error
    }

    cout << argc << " args: " << argv[0] << ", " << argv[1] << endl;

    // Maintain statistics on packet RTTs, lost packets, etc.
    double max_RTT = 0;
    double min_RTT = 0;
    double sum_RTT = 0;
    int lost_pkts = 0;
    int total_reqs = 0;

    // Convert hostname to equivalent IP address if needed
    string target;
    if (is_ip_addr(argv[1])) {
        target = argv[1];
    }
    else if (is_hostname(argv[1])) {
        target = get_hostname_addr(argv[1]);
    }
    else {
        cout << "Invalid input" << endl;
        return 1;
    }

//    struct sockaddr_in address{};  // Initialize address struct
//    memset(&address, 0, sizeof(address));  // Clear address struct
//    address.sin_family = AF_INET;
//    address.sin_addr.s_addr = inet_addr(target);

    // Open the socket, need to connect to target IP addr
    // Need superuser priviledges for raw sockets. Workaround:
    // https://stackoverflow.com/questions/28857941/opening-raw-sockets-in-linux-without-being-superuser
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) {
        perror("socket");
        return 1;
    }

    cout << socket_fd << endl;

    struct icmphdr icmp_hdr{};
    // Besides zeroing out all header bits, sets code and sequence number to 0 as well:
    memset(&icmp_hdr, 0, sizeof icmp_hdr);
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = 6829;  // in the spirit of 6.829, Networking

    cout << " ---------------------- checksum unittests ---------------------------" << endl;
    short sharr[] = {1, 2, 3};
    for (short i : sharr) {
        cout << i << endl;
    }
    cout << checksum(sharr, 3) << endl;  // Should be 0xFFF9, or -7

    short sharr2[] = {0x7133, 0x7FFE, 0x60AB, 0x77CD};
    for (short i : sharr2) {
        cout << i << endl;
    }
    cout << checksum(sharr2, 4) << endl;  // Should be

    cout << "---------------------- regex unittests -------------------------" << endl;
    const char *test = "www.hi.net";
    const char *test2 = "192.1.2.3";
    const char *badtest = "blah.blah,34";
    cout << is_hostname(test) << endl;
    cout << is_ip_addr(test) << endl;
    cout << is_hostname(test2) << endl;
    cout << is_ip_addr(test2) << endl;
    cout << is_hostname(badtest) << endl;
    cout << is_ip_addr(badtest) << endl;

    // Time in seconds since epoch (can also convert to milliseconds duration
    auto start = chrono::system_clock::now();
    cout << "curr time: " << chrono::system_clock::to_time_t(start) << endl;

//    while (true) {
//      - TODO: Use sendto to send the packet
//      - TODO: Blocking call recvfrom; timestamp should be in data section (?? confirm...), set a timeout to a constant
//      - TODO: Update statistics, increment sequence number, print RTT if success, else incr lost_pkts
//    }

    
    return 0;
}
