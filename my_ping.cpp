#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <regex>
#include <string>

using namespace std;

bool is_hostname(const char* target) {
    regex hostname_ptn(
            R"(^(
                    ([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])
                        \.
                    )*
                ([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$)"
    );
    return regex_match(string(target), hostname_ptn);
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
    int max_RTT = 0;
    int min_RTT = 0;
    int sum_RTT = 0;
    int lost_pkts = 0;
    int total_reqs = 0;

    // Convert hostname to equivalent IP address if needed
    const char* target = argv[1];
    if (is_hostname(target)) {
        struct addrinfo hints{}, *infoptr;
        hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses

        int result = getaddrinfo(target, nullptr, &hints, &infoptr);
        if (result) {
            cerr << "getaddrinfo: " << gai_strerror(result) << endl;
            exit(1);
        }

        struct addrinfo *p;
        char host[256];

        for (p = infoptr; p != nullptr; p = p->ai_next) {

            getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), nullptr, 0, NI_NUMERICHOST);
            cout << host << endl;
        }

        freeaddrinfo(infoptr);
    }

    return 0;
}
