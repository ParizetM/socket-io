// tls_handshake.cpp
// -----------------------------------------------------------
// Simulation pédagogique d'une négociation TLS 1.2 (RFC 5246)
// en C++.
//
// Objectif : illustrer dans l'ordre les messages d'un
// handshake TLS classique :
//   ClientHello → ServerHello → Certificate → ServerKeyExchange
//   → ServerHelloDone → ClientKeyExchange → ChangeCipherSpec
//   → Finished (client) → ChangeCipherSpec → Finished (serveur)
//
// On reste volontairement au niveau "simulation" (pas de vraie
// cryptographie) pour rendre les étapes lisibles. Une version
// réelle utiliserait OpenSSL (SSL_connect / SSL_accept).
//
// Compilation :
//   c++ -O2 -Wall -std=c++17 -o tls_handshake tls_handshake.cpp
// Exécution :
//   ./tls_handshake

#include <iostream>
#include <string>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

namespace {

// Types de message TLS (extraits de la RFC 5246, §7.4).
enum TlsMsgType : int {
    CLIENT_HELLO        = 1,
    SERVER_HELLO        = 2,
    CERTIFICATE         = 11,
    SERVER_KEY_EXCHANGE = 12,
    SERVER_HELLO_DONE   = 14,
    CLIENT_KEY_EXCHANGE = 16,
    CHANGE_CIPHER_SPEC  = 20,
    FINISHED            = 21
};

struct TlsMessage {
    int  type = 0;
    char info[160] = {};
};

void send_msg(int sock, const std::string& who, int type, const std::string& info) {
    TlsMessage m;
    m.type = type;
    std::strncpy(m.info, info.c_str(), sizeof(m.info) - 1);
    std::cout << "  [" << who << "] →  " << info << '\n';
    std::cout.flush();
    ::write(sock, &m, sizeof(m));
}

void recv_msg(int sock, const std::string& who, TlsMessage& m) {
    ::read(sock, &m, sizeof(m));
    std::cout << "  [" << who << "] ←  " << m.info << '\n';
    std::cout.flush();
}

// ----------- côté SERVEUR -----------
void run_server(int sock) {
    TlsMessage m;
    std::cout << "\n--- SERVEUR TLS ---\n";

    recv_msg(sock, "SERVEUR", m); // ClientHello

    send_msg(sock, "SERVEUR", SERVER_HELLO,
             "ServerHello (TLS 1.2, suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, random=R_s)");
    send_msg(sock, "SERVEUR", CERTIFICATE,
             "Certificate (chaîne X.509 du serveur)");
    send_msg(sock, "SERVEUR", SERVER_KEY_EXCHANGE,
             "ServerKeyExchange (paramètres ECDHE + signature RSA)");
    send_msg(sock, "SERVEUR", SERVER_HELLO_DONE,
             "ServerHelloDone");

    recv_msg(sock, "SERVEUR", m); // ClientKeyExchange
    recv_msg(sock, "SERVEUR", m); // ChangeCipherSpec
    recv_msg(sock, "SERVEUR", m); // Finished (client)

    send_msg(sock, "SERVEUR", CHANGE_CIPHER_SPEC,
             "ChangeCipherSpec");
    send_msg(sock, "SERVEUR", FINISHED,
             "Finished (chiffré avec la clé de session)");

    std::cout << "[SERVEUR] >>> Session TLS établie <<<\n";
}

// ----------- côté CLIENT -----------
void run_client(int sock) {
    TlsMessage m;
    std::cout << "\n--- CLIENT TLS ---\n";

    send_msg(sock, "CLIENT", CLIENT_HELLO,
             "ClientHello (TLS 1.2, suites proposées, random=R_c)");

    recv_msg(sock, "CLIENT", m); // ServerHello
    recv_msg(sock, "CLIENT", m); // Certificate
    recv_msg(sock, "CLIENT", m); // ServerKeyExchange
    recv_msg(sock, "CLIENT", m); // ServerHelloDone

    // Le client vérifie le certificat (CA, validité, CN/SAN).
    std::cout << "  [CLIENT ] *  vérification du certificat serveur OK\n";
    // Calcul du pre-master secret puis du master secret.
    std::cout << "  [CLIENT ] *  calcul du pre-master + master secret\n";

    send_msg(sock, "CLIENT", CLIENT_KEY_EXCHANGE,
             "ClientKeyExchange (clé publique ECDHE du client)");
    send_msg(sock, "CLIENT", CHANGE_CIPHER_SPEC,
             "ChangeCipherSpec");
    send_msg(sock, "CLIENT", FINISHED,
             "Finished (chiffré avec la clé de session)");

    recv_msg(sock, "CLIENT", m); // ChangeCipherSpec
    recv_msg(sock, "CLIENT", m); // Finished (serveur)

    std::cout << "[CLIENT ] >>> Session TLS établie <<<\n";
}

} // namespace

int main() {
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        std::perror("socketpair");
        return 1;
    }

    std::cout << "Simulation d'un handshake TLS 1.2 (RFC 5246)\n";
    std::cout << "=============================================\n";

    pid_t pid = ::fork();
    if (pid < 0) { std::perror("fork"); return 1; }

    if (pid == 0) {
        ::close(sv[0]);
        run_server(sv[1]);
        ::close(sv[1]);
        return 0;
    }

    ::close(sv[1]);
    timespec ts{ 0, 100 * 1000 * 1000 };
    ::nanosleep(&ts, nullptr);
    run_client(sv[0]);
    ::close(sv[0]);
    ::wait(nullptr);

    std::cout << "\n=============================================\n";
    std::cout << "Handshake terminé : canal chiffré opérationnel.\n";
    return 0;
}
