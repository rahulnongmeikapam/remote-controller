#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace remote_controller::crypto {

constexpr std::size_t P256_PUBLIC_KEY_SIZE = 65;
constexpr std::size_t SESSION_KEY_SIZE = 32;
constexpr std::size_t GCM_NONCE_SIZE = 12;
constexpr std::size_t GCM_TAG_SIZE = 16;
constexpr char HKDF_INFO[] = "RemoteController-v2";

using Bytes = std::vector<std::uint8_t>;
using SessionKey = std::array<std::uint8_t, SESSION_KEY_SIZE>;

class SecureChannel {
public:
    explicit SecureChannel(bool clientRole = false);
    ~SecureChannel();

    SecureChannel(const SecureChannel&) = delete;
    SecureChannel& operator=(const SecureChannel&) = delete;

    bool Initialize();
    void Cleanup();

    const Bytes& GetPublicKey() const;
    bool DeriveSharedSecret(const std::uint8_t* peerPublicKey, std::size_t peerPublicKeyLength);

    Bytes Encrypt(const std::uint8_t* plaintext, std::size_t plaintextLength,
                  const std::uint8_t* aad = nullptr, std::size_t aadLength = 0) const;
    Bytes Decrypt(const std::uint8_t* encrypted, std::size_t encryptedLength,
                  const std::uint8_t* aad = nullptr, std::size_t aadLength = 0) const;

    bool IsReady() const;
    std::size_t GetWireOverhead() const { return GCM_NONCE_SIZE + GCM_TAG_SIZE; }
    static bool Sha256(const std::uint8_t* data, std::size_t length,
                       std::array<std::uint8_t, 32>& digest);
    static std::string LastError();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace remote_controller::crypto
