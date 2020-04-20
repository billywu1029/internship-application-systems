#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <regex>
#include <string>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <chrono>
#include <csignal>
#include <thread>

/*
 * NOTE: Must compile and then run as superuser, ie g++ my_ping.cpp, followed by sudo ./my_ping www.google.com
 * This is for the raw socket with the ICMP protocol to be able to run. Due to linux security vulnerabilities
 * (see: http://squidarth.com/networking/systems/rc/2018/05/28/using-raw-sockets.html),
 * you can't make a raw socket without superuser privileges.
 *
 * Author: Bill Wu
 * Date: 4/20/20
 */

using namespace std;

// Global vars to help keep stats on packets + rtt's etc., all rtt times in milliseconds
double max_rtt = 0;
double min_rtt = pow(10, 10);
double sum_rtt = 0;
int recv_pkts = 0;  // Total number of received packets
int total_pkts = 0;  // Total number of transmitted packets
string destination;
auto program_start = chrono::system_clock::now();

constexpr int ECHO_REPLY_TIMEOUT = 3;  // Timeout in seconds before packet is deemed "lost"
constexpr int ICMP_HDR_ID = 0;  // Default ID in icmp header
constexpr int PING_PACKET_BYTES = 64;
constexpr int PING_REQ_INTERVAL_MS = 2000;  // Default ms for ping to sleep before sending another echo request packet

void post_analysis(int signum) {
    auto program_end = chrono::system_clock::now();
    cout << "--- " << destination << " ping statistics ---" << endl;
    cout << total_pkts << " packets transmitted, " << recv_pkts << " packets received, "
         << (total_pkts - recv_pkts) / recv_pkts * 100 << "% packet loss, time: "
         << chrono::duration_cast<chrono::milliseconds>(program_end - program_start).count() << "ms" << endl;
    if (recv_pkts == 0) {
        cout << "No RTTs to report, since no packets were received." << endl;
    } else {
        cout << "RTT min | avg | max (ms): " << min_rtt << " | " << sum_rtt / recv_pkts << " | " << max_rtt << endl;
    }
    exit(0);
}

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
    // AF_INET means IPv4 only addresses. If handling IPv6, change this to AF_INET6
    hints.ai_family = AF_INET;

    int result = getaddrinfo(hostname, nullptr, &hints, &infoptr);
    if (result) {
        cerr << "getaddrinfo: " << gai_strerror(result) << endl;
        exit(1);
    }

    char host[256];
    // Just arbitrarily pick the first addr in the addrinfo struct linked list
    getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, host, sizeof (host), nullptr, 0, NI_NUMERICHOST);
    freeaddrinfo(infoptr);

    return host;
}

string process_target(const char* target) {
    if (is_ip_addr(target)) {
        return target;
    }
    else if (is_hostname(target)) {
        return get_hostname_addr(target);
    }
    else {
        cout << "Invalid input. Please enter a valid hostname or IP Address." << endl;
        exit(1);
    }
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


// For now, just pass in arguments via arg parser, later can switch to CLI
// that uses arg flags.
int main(int argc, char* argv[]) {
    // Some tests:
    cout << " ---------------------- checksum unittests ---------------------------" << endl;
    uint16_t sharr[] = {1, 2, 3};
    for (uint16_t i : sharr) {
        cout << i << endl;
    }
    cout << checksum(sharr, 3) << endl;  // Should be 0xFFF9, or 65532

    uint16_t sharr2[] = {0x7133, 0x7FFE, 0x60AB, 0x77CD};
    for (uint16_t i : sharr2) {
        cout << i << endl;
    }
    cout << checksum(sharr2, 4) << endl;  // Should be 3790 (decimal)

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

    // ---------------------------------- Actual main function code: ------------------------------
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <HOSTNAME or IP_ADDR>" << endl;
        return 1;  // Improper formatting, exit with error
    }
    destination = argv[1];

    // Catch a SIGINT signal and print out post analysis before my_ping exits
    signal(SIGINT, &post_analysis);

    // Convert hostname to equivalent IP address if needed.
    // Note: If no internet connection, behavior is the same as original ping, DNS lookup fails for input hostnames
    string target = process_target(argv[1]);
    const char* target_cstr = target.c_str();

    // Open the socket, need to connect to target IP addr
    // Need superuser priviledges for raw sockets. Workaround:
    // https://stackoverflow.com/questions/28857941/opening-raw-sockets-in-linux-without-being-superuser
    // Edit: workaround with setcap does not work. Must still run executable as superuser for this raw socket to work
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) {
        perror("socket");
        return 1;
    }

    // Send the actual packets in an infinite loop, while recording statistics

    return 0;
}
