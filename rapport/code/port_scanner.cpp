// port_scanner.cpp
// -----------------------------------------------------------
// Scanner de ports TCP simple en C++ (sockets POSIX BSD).
//
// Principe : pour chaque port de la plage demandée, on tente
// une connexion TCP non bloquante avec un timeout de 1 s.
// Si elle réussit, le port est considéré ouvert. C'est
// l'équivalent simplifié d'un scan TCP "connect" (`nmap -sT`).
//
// Compilation :
//   c++ -O2 -Wall -std=c++17 -o port_scanner port_scanner.cpp
//
// Utilisation :
//   ./port_scanner <hôte> <port_début> <port_fin>
// Exemple :
//   ./port_scanner 127.0.0.1 1 1024

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cerrno>

#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

namespace {

constexpr int TIMEOUT_SEC = 1;

// Tente une connexion TCP non bloquante avec un timeout.
// Retourne true si le port est ouvert, false sinon.
bool scan_port(const std::string& ip, int port) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Mode non bloquant pour gérer le timeout proprement.
    int flags = ::fcntl(sock, F_GETFL, 0);
    ::fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    ::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int res = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (res == 0) {                 // connexion immédiate
        ::close(sock);
        return true;
    }
    if (errno != EINPROGRESS) {     // refus net (RST par ex.)
        ::close(sock);
        return false;
    }

    // On attend que le socket soit prêt en écriture (= connecté).
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    timeval tv{ TIMEOUT_SEC, 0 };

    bool open = false;
    if (::select(sock + 1, nullptr, &wfds, nullptr, &tv) > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        ::getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        open = (err == 0);
    }
    ::close(sock);
    return open;
}

// Résolution DNS simple : retourne la première IPv4 associée à `host`.
std::string resolve(const std::string& host) {
    hostent* he = ::gethostbyname(host.c_str());
    if (!he) return {};
    char buf[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, he->h_addr_list[0], buf, sizeof(buf));
    return buf;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage : " << argv[0]
                  << " <hôte> <port_début> <port_fin>\n";
        return 1;
    }

    const std::string host  = argv[1];
    const int         start = std::stoi(argv[2]);
    const int         end   = std::stoi(argv[3]);

    const std::string ip = resolve(host);
    if (ip.empty()) {
        std::cerr << "Hôte introuvable : " << host << '\n';
        return 1;
    }

    std::cout << "Scan TCP de " << host << " (" << ip << "), ports "
              << start << " → " << end << '\n';
    std::cout << "------------------------------------------------\n";

    int open_count = 0;
    for (int p = start; p <= end; ++p) {
        if (scan_port(ip, p)) {
            std::cout << "  Port " << p << " : OUVERT\n";
            ++open_count;
        }
    }

    std::cout << "------------------------------------------------\n";
    std::cout << "Terminé. " << open_count << " port(s) ouvert(s) trouvé(s).\n";
    return 0;
}
