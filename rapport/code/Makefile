# Makefile pour les programmes C++ du rapport.
# Usage : `make` pour tout compiler, `make clean` pour nettoyer.

CXX      = c++
CXXFLAGS = -O2 -Wall -Wextra -std=c++17

BINS = port_scanner tcp_handshake tls_handshake

all: $(BINS)

port_scanner: port_scanner.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

tcp_handshake: tcp_handshake.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

tls_handshake: tls_handshake.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(BINS)

.PHONY: all clean
