#include "../common/crypto/Crypto.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using remote_controller::crypto::Bytes;
using remote_controller::crypto::SecureChannel;

static void Check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

int main() {
    SecureChannel client(true);
    SecureChannel agent(false);
    Check(client.Initialize(), "client key generation");
    Check(agent.Initialize(), "agent key generation");
    Check(client.GetPublicKey().size() == 65, "client public key size");
    Check(agent.GetPublicKey().size() == 65, "agent public key size");
    Check(client.GetPublicKey()[0] == 0x04, "client public key format");
    Check(agent.GetPublicKey()[0] == 0x04, "agent public key format");

    Check(client.DeriveSharedSecret(agent.GetPublicKey().data(), agent.GetPublicKey().size()), "client ECDH/HKDF");
    Check(agent.DeriveSharedSecret(client.GetPublicKey().data(), client.GetPublicKey().size()), "agent ECDH/HKDF");
    Check(client.IsReady() && agent.IsReady(), "channels ready");

    const std::string aad = "serialized-header";
    const std::vector<std::uint8_t> plaintext = {0x00, 0x01, 0x7f, 0xff, 0x00};
    Bytes encrypted = client.Encrypt(plaintext.data(), plaintext.size(),
                                     reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size());
    Check(!encrypted.empty(), "AES-GCM encryption");
    Bytes decrypted = agent.Decrypt(encrypted.data(), encrypted.size(),
                                    reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size());
    Check(decrypted == plaintext, "AES-GCM round trip");

    encrypted[encrypted.size() - 1] ^= 0x01;
    Check(agent.Decrypt(encrypted.data(), encrypted.size(),
                        reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size()).empty(),
          "modified tag rejected");

    Bytes empty = client.Encrypt(nullptr, 0, nullptr, 0);
    Check(!empty.empty(), "empty plaintext encryption");
    Check(agent.Decrypt(empty.data(), empty.size(), nullptr, 0).size() == 0, "empty plaintext decryption");

    std::array<std::uint8_t, 32> digest{};
    const std::string abc = "abc";
    Check(SecureChannel::Sha256(reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size(), digest), "SHA-256");
    Check(digest[0] == 0xba && digest[31] == 0xad, "SHA-256 known vector");

    std::cout << "Crypto tests passed\n";
    return 0;
}
