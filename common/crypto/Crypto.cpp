#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>

namespace remote_controller::crypto {
namespace {

struct EvpPkeyDeleter { void operator()(EVP_PKEY* value) const { EVP_PKEY_free(value); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* value) const { EVP_PKEY_CTX_free(value); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* value) const { EVP_CIPHER_CTX_free(value); } };
struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* value) const { EVP_MD_CTX_free(value); } };

using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

std::string OpenSslError() {
    std::ostringstream result;
    unsigned long error = 0;
    while ((error = ERR_get_error()) != 0) {
        char buffer[256] = {};
        ERR_error_string_n(error, buffer, sizeof(buffer));
        if (result.tellp() > 0) result << " | ";
        result << buffer;
    }
    return result.str();
}

void Cleanse(Bytes& value) {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}

bool BuildPublicKey(EVP_PKEY* key, Bytes& output) {
    const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(key);
    if (!ecKey) return false;
    const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    if (!point || !group) return false;

    output.resize(P256_PUBLIC_KEY_SIZE);
    std::size_t written = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                             output.data(), output.size(), nullptr);
    if (written != P256_PUBLIC_KEY_SIZE) {
        output.clear();
        return false;
    }
    return true;
}

PkeyPtr ParsePublicKey(const std::uint8_t* data, std::size_t length) {
    if (!data || length != P256_PUBLIC_KEY_SIZE || data[0] != 0x04) return nullptr;

    PkeyPtr key(EVP_PKEY_new());
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key || !ecKey) {
        EC_KEY_free(ecKey);
        return nullptr;
    }
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* point = EC_POINT_new(group);
    if (!point || EC_POINT_oct2point(group, point, data, length, nullptr) != 1 ||
        EC_KEY_set_public_key(ecKey, point) != 1 || EVP_PKEY_assign_EC_KEY(key.get(), ecKey) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ecKey);
        return nullptr;
    }
    EC_POINT_free(point);
    return key;
}

bool DeriveHkdf(const Bytes& secret, const Bytes& clientPublic, const Bytes& agentPublic,
                SessionKey& clientToAgent, SessionKey& agentToClient) {
    std::array<std::uint8_t, 32> salt{};
    Bytes saltInput;
    saltInput.reserve(clientPublic.size() + agentPublic.size());
    saltInput.insert(saltInput.end(), clientPublic.begin(), clientPublic.end());
    saltInput.insert(saltInput.end(), agentPublic.begin(), agentPublic.end());
    if (!SecureChannel::Sha256(saltInput.data(), saltInput.size(), salt)) return false;

    Bytes output(SESSION_KEY_SIZE * 2);
    PkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt.data(), salt.size()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(context.get(), secret.data(), secret.size()) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(context.get(), (const unsigned char*)HKDF_INFO,
                                    sizeof(HKDF_INFO) - 1) != 1) return false;

    std::size_t outputLength = output.size();
    if (EVP_PKEY_derive(context.get(), output.data(), &outputLength) != 1 || outputLength != output.size()) return false;
    std::copy(output.begin(), output.begin() + SESSION_KEY_SIZE, clientToAgent.begin());
    std::copy(output.begin() + SESSION_KEY_SIZE, output.end(), agentToClient.begin());
    OPENSSL_cleanse(output.data(), output.size());
    OPENSSL_cleanse(salt.data(), salt.size());
    return true;
}

} // namespace

struct SecureChannel::Impl {
    bool clientRole = false;
    bool ready = false;
    PkeyPtr privateKey;
    Bytes publicKey;
    SessionKey clientToAgent{};
    SessionKey agentToClient{};
    Bytes sharedSecret;
};

SecureChannel::SecureChannel(bool clientRole) : impl_(new Impl()) {
    impl_->clientRole = clientRole;
}

SecureChannel::~SecureChannel() {
    Cleanup();
    delete impl_;
}

bool SecureChannel::Initialize() {
    Cleanup();
    PkeyCtxPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) != 1) return false;
    EVP_PKEY* generated = nullptr;
    if (EVP_PKEY_keygen(context.get(), &generated) != 1) return false;
    impl_->privateKey.reset(generated);
    if (!BuildPublicKey(impl_->privateKey.get(), impl_->publicKey)) return false;
    impl_->ready = false;
    return true;
}

void SecureChannel::Cleanup() {
    if (!impl_) return;
    impl_->ready = false;
    impl_->privateKey.reset();
    Cleanse(impl_->publicKey);
    Cleanse(impl_->sharedSecret);
    OPENSSL_cleanse(impl_->clientToAgent.data(), impl_->clientToAgent.size());
    OPENSSL_cleanse(impl_->agentToClient.data(), impl_->agentToClient.size());
}

const Bytes& SecureChannel::GetPublicKey() const { return impl_->publicKey; }

bool SecureChannel::DeriveSharedSecret(const std::uint8_t* peerPublicKey, std::size_t peerPublicKeyLength) {
    if (!impl_->privateKey || peerPublicKeyLength != P256_PUBLIC_KEY_SIZE) return false;
    PkeyPtr peer(ParsePublicKey(peerPublicKey, peerPublicKeyLength));
    if (!peer) return false;

    PkeyCtxPtr context(EVP_PKEY_CTX_new(impl_->privateKey.get(), nullptr));
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1) return false;
    std::size_t secretLength = 0;
    if (EVP_PKEY_derive(context.get(), nullptr, &secretLength) != 1) return false;
    impl_->sharedSecret.resize(secretLength);
    if (EVP_PKEY_derive(context.get(), impl_->sharedSecret.data(), &secretLength) != 1) return false;
    impl_->sharedSecret.resize(secretLength);

    SessionKey clientToAgent{};
    SessionKey agentToClient{};
    if (!DeriveHkdf(impl_->sharedSecret, impl_->clientRole ? impl_->publicKey : Bytes(peerPublicKey, peerPublicKey + peerPublicKeyLength),
                    impl_->clientRole ? Bytes(peerPublicKey, peerPublicKey + peerPublicKeyLength) : impl_->publicKey,
                    clientToAgent, agentToClient)) return false;
    impl_->clientToAgent = clientToAgent;
    impl_->agentToClient = agentToClient;
    impl_->ready = true;
    return true;
}

Bytes SecureChannel::Encrypt(const std::uint8_t* plaintext, std::size_t plaintextLength,
                             const std::uint8_t* aad, std::size_t aadLength) const {
    if (!impl_->ready || (!plaintext && plaintextLength)) return {};
    const SessionKey& key = impl_->clientRole ? impl_->clientToAgent : impl_->agentToClient;
    std::array<std::uint8_t, GCM_NONCE_SIZE> nonce{};
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) return {};
    CipherCtxPtr context(EVP_CIPHER_CTX_new());
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) return {};
    int written = 0;
    if (aadLength && EVP_EncryptUpdate(context.get(), nullptr, &written, aad, (int)aadLength) != 1) return {};
    Bytes result(GCM_NONCE_SIZE + plaintextLength + GCM_TAG_SIZE);
    std::copy(nonce.begin(), nonce.end(), result.begin());
    if (plaintextLength && EVP_EncryptUpdate(context.get(), result.data() + GCM_NONCE_SIZE, &written, plaintext, (int)plaintextLength) != 1) return {};
    int finalLength = 0;
    if (EVP_EncryptFinal_ex(context.get(), result.data() + GCM_NONCE_SIZE + written, &finalLength) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, result.data() + GCM_NONCE_SIZE + plaintextLength) != 1) return {};
    result.resize(GCM_NONCE_SIZE + plaintextLength + GCM_TAG_SIZE);
    return result;
}

Bytes SecureChannel::Decrypt(const std::uint8_t* encrypted, std::size_t encryptedLength,
                             const std::uint8_t* aad, std::size_t aadLength) const {
    if (!impl_->ready || !encrypted || encryptedLength < GCM_NONCE_SIZE + GCM_TAG_SIZE) return {};
    const SessionKey& key = impl_->clientRole ? impl_->agentToClient : impl_->clientToAgent;
    const std::size_t ciphertextLength = encryptedLength - GCM_NONCE_SIZE - GCM_TAG_SIZE;
    CipherCtxPtr context(EVP_CIPHER_CTX_new());
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), encrypted) != 1) return {};
    int written = 0;
    if (aadLength && EVP_DecryptUpdate(context.get(), nullptr, &written, aad, (int)aadLength) != 1) return {};
    Bytes result(ciphertextLength);
    if (ciphertextLength && EVP_DecryptUpdate(context.get(), result.data(), &written,
                                               encrypted + GCM_NONCE_SIZE, (int)ciphertextLength) != 1) return {};
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                            const_cast<std::uint8_t*>(encrypted + GCM_NONCE_SIZE + ciphertextLength)) != 1) return {};
    int finalLength = 0;
    if (EVP_DecryptFinal_ex(context.get(), result.data() + written, &finalLength) != 1) return {};
    result.resize(static_cast<std::size_t>(written + finalLength));
    return result;
}

bool SecureChannel::IsReady() const { return impl_->ready; }

bool SecureChannel::Sha256(const std::uint8_t* data, std::size_t length,
                           std::array<std::uint8_t, 32>& digest) {
    MdCtxPtr context(EVP_MD_CTX_new());
    unsigned int outputLength = 0;
    return context && EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1 &&
           EVP_DigestUpdate(context.get(), data, length) == 1 &&
           EVP_DigestFinal_ex(context.get(), digest.data(), &outputLength) == 1 && outputLength == digest.size();
}

std::string SecureChannel::LastError() { return OpenSslError(); }

} // namespace remote_controller::crypto
