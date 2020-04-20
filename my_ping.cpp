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
 * Compile: g++ my_ping.cpp -o my_ping -std=c++11
 * Run: sudo ./my_ping www.google.com
 * 
 * NOTE: Must compile and then run as superuser, ie g++ my_ping.cpp, followed by sudo ./my_ping www.google.com
 * This is for the raw socket with the ICMP protocol to be able to run. Due to linux security vulnerabilities
 * (see http://squidarth.com/networking/systems/rc/2018/05/28/using-raw-sockets.html),
 * you can't make a raw socket without superuser privileges.
 *
 * NOTE: Reverse DNS lookup sometimes doesn't work. Try again if it shows <Unknown> as the reverse looked up hostname.
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

int32_t checksum(uint16_t* pkt_blocks, int num_blocks) {
    // Adds together every 16-bit block from header + data, then return the ones-compliment of the sum
    // Borrowed from: https://stackoverflow.com/questions/9913661/what-is-the-proper-process-for-icmp-echo-request-reply-on-unreachable-destinatio
    int32_t sum = 0;
    uint16_t *w = pkt_blocks;
    uint16_t answer = 0;

    while(num_blocks > 1) {
        sum += *w++;
        num_blocks -= 2;
    }

    if (num_blocks == 1) {
        *(uint16_t *)(&answer) = *(uint8_t *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

string reverse_dns_lookup(const char *ip_addr) {
    struct sockaddr_in temp_addr{};
    char buf[NI_MAXHOST];

    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);

    if (getnameinfo((struct sockaddr *) &temp_addr, sizeof(struct sockaddr_in), buf, sizeof(buf),
                    nullptr, 0, NI_NAMEREQD)) {
        cout << "Could not resolve reverse lookup of hostname!" << endl;
        return "<Unknown>";
    }
    return buf;
}

void send_pkts(int socket_fd, const string& target, const string& target_reverse_lookup) {
    sockaddr_in address{};  // Initialize address struct
    memset(&address, 0, sizeof(address));  // Clear address struct
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(target.c_str());

    while (true) {
        cout << "sending packet #" << total_pkts << endl;
        char packet[sizeof(icmphdr)];
        // Setting everything to 0, implies that checksum zeroed out, code=0, id=0.
        memset(packet, 0, sizeof(packet));

        auto *req_pkt = (icmphdr *) packet;
        req_pkt->type = ICMP_ECHO;
        req_pkt->un.echo.sequence = total_pkts;
        req_pkt->checksum = checksum((uint16_t *) req_pkt, sizeof(packet));

        // Handle potential error cases/edge cases of packets not being sent properly after this call
        sendto(socket_fd, packet, sizeof(packet), 0, (sockaddr *) &address, sizeof(sockaddr_in));

        // Immediately start the counter after sending the packet.
        // Using a time-based approach to measure RTT here.
        // More correct/difficult is: read timestamp from reply's data bytes and then - start time.
        auto start = chrono::system_clock::now();

        // Wait for echo reply from OS buffer
        while (true) {
            char inbuf[192];
            memset(inbuf, 0, sizeof(inbuf));
            int addrlen = sizeof(sockaddr_in);

            // Immediately record time after receiving echo reply. recvfrom() itself is a blocking call
            int bytes = recvfrom(socket_fd, inbuf, sizeof(inbuf), 0, (sockaddr *) &address, (socklen_t *) &addrlen);
            auto end_time = chrono::system_clock::now();

            // Verify that reply bytes were valid
            if (bytes < sizeof(iphdr) + sizeof(icmphdr)) {
                cout << "Incorrect read bytes!" << endl;
                continue;
            }

            // Construct reply packet from buffer
            auto *iph = (iphdr *) inbuf;
            int hlen = (iph->ihl << 2);
            auto reply_pkt = (icmphdr *)(inbuf + hlen);
            int id = ntohs(reply_pkt->un.echo.id);

            if (reply_pkt->type == ICMP_ECHOREPLY) {
                // Ensure that ID matches && checksum from request was 8 more than reply's checksum
                // (since the type for an ECHO_REPLY = 0 and ECHO_REQ = 8, and bits are flipped in checksum calculation)
                // Update: for some reason the int16_t overflow makes it so that the first reply checksum = 0 != 65535
                // Just keep the checksum assertion here for future reference, if I figure out this issue:
                // if (id == ICMP_HDR_ID && req_pkt->checksum + 8) {
                if (id == ICMP_HDR_ID ) {
                    auto elapsed_time = end_time - start;
                    int elapsed_ms = chrono::duration_cast<chrono::milliseconds>(elapsed_time).count();
                    if (elapsed_ms > max_rtt) {
                        max_rtt = elapsed_ms;
                    }
                    if (elapsed_ms < min_rtt) {
                        min_rtt = elapsed_ms;
                    }
                    sum_rtt += elapsed_ms;
                    recv_pkts++;
                    cout << PING_PACKET_BYTES << " bytes from " << target_reverse_lookup << " (" << target << "): "
                         << "icmp_seq=" << total_pkts << ", elapsed_time=" << elapsed_ms << " ms" << endl;
                    cout << "\n" << endl;
                    break;
                }
            } else if (reply_pkt->type == ICMP_DEST_UNREACH) {
                cout << "From " << target << " icmp_seq=" << total_pkts << " Destination Host Unreachable" << endl;
                break;
            } else {
                cout << "Error, unhandled ICMP protocol response: " << reply_pkt->type << endl;
                break;
            }
        }

        total_pkts++;
        chrono::milliseconds timespan(PING_REQ_INTERVAL_MS);
        this_thread::sleep_for(timespan);
    }
}

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
    string reverse_lookup_target = reverse_dns_lookup(target_cstr);

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
    send_pkts(socket_fd, target_cstr, reverse_lookup_target);

    return 0;
}
