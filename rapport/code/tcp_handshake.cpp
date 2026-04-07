// tcp_handshake.cpp
// -----------------------------------------------------------
// Simulation pédagogique du three-way handshake TCP en C++.
//
// Objectif : illustrer les étapes SYN → SYN/ACK → ACK et la
// machine à états TCP, sans nécessiter de privilèges root
// (les raw sockets imposeraient sudo + désactivation des RST
// envoyés par le noyau).
//
// Le programme fork() en deux processus :
//   - parent  = "client" TCP
//   - enfant  = "serveur" TCP
// qui s'échangent les messages du handshake via un socketpair
// (canal local bidirectionnel). Chaque étape affiche son état
// conformément à la RFC 793.
//
// Compilation :
//   c++ -O2 -Wall -std=c++17 -o tcp_handshake tcp_handshake.cpp
// Exécution :
//   ./tcp_handshake

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

namespace {

// "Segment TCP" simplifié pour la simulation.
struct TcpSegment {
    uint32_t seq   = 0;     // numéro de séquence
    uint32_t ack   = 0;     // numéro d'acquittement
    bool     syn   = false; // drapeau SYN
    bool     ack_f = false; // drapeau ACK
    bool     fin   = false; // drapeau FIN
};

void print_segment(const std::string& who, const std::string& etat,
                   const TcpSegment& s) {
    std::cout << "[" << std::left << std::setw(7) << who << "] "
              << "état=" << std::setw(12) << etat << " | "
              << "SYN=" << s.syn << " ACK=" << s.ack_f << " FIN=" << s.fin
              << " | seq=" << s.seq << " ack=" << s.ack << '\n';
    std::cout.flush();
}

// ----------- côté SERVEUR -----------
void run_server(int sock) {
    std::string etat = "LISTEN";
    TcpSegment in, out;

    std::cout << "\n=== Démarrage SERVEUR (état initial : LISTEN) ===\n";

    // 1) Réception du SYN client
    ::read(sock, &in, sizeof(in));
    print_segment("SERVEUR", etat, in);
    if (!in.syn) { std::cerr << "SYN attendu\n"; std::exit(1); }

    // 2) Envoi du SYN/ACK
    etat = "SYN_RECEIVED";
    out = {};
    out.syn   = true;
    out.ack_f = true;
    out.seq   = 4000;            // ISN serveur arbitraire
    out.ack   = in.seq + 1;      // on acquitte le SYN client
    print_segment("SERVEUR", etat, out);
    ::write(sock, &out, sizeof(out));

    // 3) Réception de l'ACK final
    ::read(sock, &in, sizeof(in));
    etat = "ESTABLISHED";
    print_segment("SERVEUR", etat, in);
    if (!in.ack_f) { std::cerr << "ACK attendu\n"; std::exit(1); }

    std::cout << "[SERVEUR] >>> Connexion ÉTABLIE <<<\n";
}

// ----------- côté CLIENT -----------
void run_client(int sock) {
    std::string etat = "CLOSED";
    TcpSegment in, out;

    std::cout << "\n=== Démarrage CLIENT (état initial : CLOSED) ===\n";

    // 1) Envoi du SYN
    etat = "SYN_SENT";
    out = {};
    out.syn = true;
    out.seq = 1000;              // ISN client arbitraire
    print_segment("CLIENT", etat, out);
    ::write(sock, &out, sizeof(out));

    // 2) Réception du SYN/ACK
    ::read(sock, &in, sizeof(in));
    print_segment("CLIENT", etat, in);
    if (!(in.syn && in.ack_f)) { std::cerr << "SYN/ACK attendu\n"; std::exit(1); }

    // 3) Envoi de l'ACK final
    etat = "ESTABLISHED";
    out = {};
    out.ack_f = true;
    out.seq   = in.ack;          // on continue avec le seq attendu
    out.ack   = in.seq + 1;      // on acquitte le SYN serveur
    print_segment("CLIENT", etat, out);
    ::write(sock, &out, sizeof(out));

    std::cout << "[CLIENT ] >>> Connexion ÉTABLIE <<<\n";
}

} // namespace

int main() {
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        std::perror("socketpair");
        return 1;
    }

    std::cout << "Simulation du three-way handshake TCP (RFC 793)\n";
    std::cout << "================================================\n";

    pid_t pid = ::fork();
    if (pid < 0) { std::perror("fork"); return 1; }

    if (pid == 0) {
        // enfant = serveur
        ::close(sv[0]);
        run_server(sv[1]);
        ::close(sv[1]);
        return 0;
    }

    // parent = client
    ::close(sv[1]);
    timespec ts{ 0, 100 * 1000 * 1000 }; // 100 ms : laisse le serveur se préparer
    ::nanosleep(&ts, nullptr);
    run_client(sv[0]);
    ::close(sv[0]);
    ::wait(nullptr);

    std::cout << "\n================================================\n";
    std::cout << "Handshake terminé : les deux pairs sont en ESTABLISHED.\n";
    return 0;
}
