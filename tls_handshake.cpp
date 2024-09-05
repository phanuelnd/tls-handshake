#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <random>
#include <cmath>

// Global constants
const std::vector<std::string> TLS_VERSIONS = {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
const std::vector<std::pair<std::string, int>> CIPHER_SUITES = {
    {"CHACHA20-POLY1305", 3},
    {"AES-256-GCM", 2},
    {"AES-128-GCM", 1},
    {"DES-CBC3-SHA", 0}
};

// Function prototypes
std::vector<std::string> get_supported_versions(const std::string& entity);
std::string negotiate_version(const std::vector<std::string>& client_versions, const std::vector<std::string>& server_versions);
std::vector<std::string> get_supported_ciphers(const std::string& entity);
std::string select_cipher_suite(const std::vector<std::string>& client_ciphers, const std::vector<std::string>& server_ciphers);
int generate_prime();
bool is_primitive_root(int g, int p);
int find_primitive_root(int p);
std::pair<bool, int> diffie_hellman();
void tls_handshake_simulation();

// Main function
int main() {
    tls_handshake_simulation();
    return 0;
}

// Function to get supported versions
std::vector<std::string> get_supported_versions(const std::string& entity) {
    std::cout << "Available TLS versions for " << entity << ":\n";
    for (size_t i = 0; i < TLS_VERSIONS.size(); ++i) {
        std::cout << i + 1 << ". " << TLS_VERSIONS[i] << "\n";
    }
    
    std::string input;
    std::cout << "Enter numbers for " << entity << "'s supported versions (comma-separated): ";
    std::getline(std::cin, input);
    
    std::vector<std::string> supported_versions;
    std::stringstream ss(input);
    std::string token;
    while (std::getline(ss, token, ',')) {
        int index = std::stoi(token) - 1;
        if (index >= 0 && index < static_cast<int>(TLS_VERSIONS.size())) {
            supported_versions.push_back(TLS_VERSIONS[index]);
        }
    }
    
    return supported_versions;
}

// Function to negotiate version
std::string negotiate_version(const std::vector<std::string>& client_versions, const std::vector<std::string>& server_versions) {
    std::vector<std::string> common_versions;
    std::set_intersection(client_versions.begin(), client_versions.end(),
                          server_versions.begin(), server_versions.end(),
                          std::back_inserter(common_versions));
    
    if (common_versions.empty()) return "";
    
    return *std::max_element(common_versions.begin(), common_versions.end(),
        [](const std::string& a, const std::string& b) {
            return std::find(TLS_VERSIONS.begin(), TLS_VERSIONS.end(), a) <
                   std::find(TLS_VERSIONS.begin(), TLS_VERSIONS.end(), b);
        });
}

// Function to get supported ciphers
std::vector<std::string> get_supported_ciphers(const std::string& entity) {
    std::cout << "Available cipher suites for " << entity << ":\n";
    for (size_t i = 0; i < CIPHER_SUITES.size(); ++i) {
        std::cout << i + 1 << ". " << CIPHER_SUITES[i].first << "\n";
    }
    
    std::string input;
    std::cout << "Enter numbers for " << entity << "'s supported cipher suites (comma-separated): ";
    std::getline(std::cin, input);
    
    std::vector<std::string> supported_ciphers;
    std::stringstream ss(input);
    std::string token;
    while (std::getline(ss, token, ',')) {
        int index = std::stoi(token) - 1;
        if (index >= 0 && index < static_cast<int>(CIPHER_SUITES.size())) {
            supported_ciphers.push_back(CIPHER_SUITES[index].first);
        }
    }
    
    return supported_ciphers;
}

// Function to select cipher suite
std::string select_cipher_suite(const std::vector<std::string>& client_ciphers, const std::vector<std::string>& server_ciphers) {
    std::vector<std::string> common_ciphers;
    std::set_intersection(client_ciphers.begin(), client_ciphers.end(),
                          server_ciphers.begin(), server_ciphers.end(),
                          std::back_inserter(common_ciphers));
    
    if (common_ciphers.empty()) return "";
    
    return *std::max_element(common_ciphers.begin(), common_ciphers.end(),
        [](const std::string& a, const std::string& b) {
            auto it_a = std::find_if(CIPHER_SUITES.begin(), CIPHER_SUITES.end(),
                [&a](const auto& p) { return p.first == a; });
            auto it_b = std::find_if(CIPHER_SUITES.begin(), CIPHER_SUITES.end(),
                [&b](const auto& p) { return p.first == b; });
            return it_a->second < it_b->second;
        });
}

// Function to generate a prime number
int generate_prime() {
    std::vector<int> primes = {61, 53, 47, 43, 41, 37, 31, 29, 23, 19, 17, 13, 11, 7, 5, 3, 2};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, primes.size() - 1);
    return primes[dis(gen)];
}

// Function to check if a number is a primitive root
bool is_primitive_root(int g, int p) {
    return static_cast<int>(std::pow(g, (p-1)/2)) % p != 1;
}

// Function to find a primitive root
int find_primitive_root(int p) {
    for (int g = 2; g < p; ++g) {
        if (is_primitive_root(g, p)) {
            return g;
        }
    }
    return -1;
}

// Function to perform Diffie-Hellman key exchange
std::pair<bool, int> diffie_hellman() {
    int p = generate_prime();
    int g = find_primitive_root(p);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, p-2);
    
    int client_private = dis(gen);
    int client_public = static_cast<int>(std::pow(g, client_private)) % p;
    
    int server_private = dis(gen);
    int server_public = static_cast<int>(std::pow(g, server_private)) % p;
    
    int client_shared_secret = static_cast<int>(std::pow(server_public, client_private)) % p;
    int server_shared_secret = static_cast<int>(std::pow(client_public, server_private)) % p;
    
    return {client_shared_secret == server_shared_secret, client_shared_secret};
}

// Function to simulate TLS handshake
void tls_handshake_simulation() {
    std::cout << "TLS Handshake Simulation\n";
    std::cout << "========================\n";
    
    // Protocol Version Negotiation
    auto client_versions = get_supported_versions("Client");
    auto server_versions = get_supported_versions("Server");
    auto negotiated_version = negotiate_version(client_versions, server_versions);
    
    if (negotiated_version.empty()) {
        std::cout << "Handshake failed: No common TLS version\n";
        return;
    }
    
    std::cout << "Negotiated TLS Version: " << negotiated_version << "\n";
    
    // Cipher Suite Selection
    auto client_ciphers = get_supported_ciphers("Client");
    auto server_ciphers = get_supported_ciphers("Server");
    auto selected_cipher = select_cipher_suite(client_ciphers, server_ciphers);
    
    if (selected_cipher.empty()) {
        std::cout << "Handshake failed: No common cipher suite\n";
        return;
    }
    
    std::cout << "Selected Cipher Suite: " << selected_cipher << "\n";
    
    // Diffie-Hellman Key Exchange
    auto [success, shared_secret] = diffie_hellman();
    
    if (!success) {
        std::cout << "Handshake failed: Key exchange error\n";
        return;
    }
    
    std::cout << "Shared Secret Established: " << shared_secret << "\n";
    std::cout << "TLS Handshake Completed Successfully\n";
}