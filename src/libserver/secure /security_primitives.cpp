#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

std::vector<uint8_t> byte_pad(const std::vector<uint8_t>& input, size_t block_size) {
    size_t padding_size = block_size - (input.size() % block_size);
    std::vector<uint8_t> padded_input = input;
    padded_input.insert(padded_input.end(), padding_size, static_cast<uint8_t>(padding_size));
    return padded_input;
}

std::vector<uint8_t> calculate_message_authentication_code_cbc(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& additional_data,
    const std::vector<uint8_t>& payload = {},
    const std::vector<uint8_t>& block_0 = std::vector<uint8_t>(16, 0)
) {
    // Calculate the message authentication code (MAC) for a message with AES-CBC.
    std::vector<uint8_t> blocks = block_0;
    uint16_t additional_data_length = static_cast<uint16_t>(additional_data.size());
    blocks.insert(blocks.end(), reinterpret_cast<uint8_t*>(&additional_data_length), reinterpret_cast<uint8_t*>(&additional_data_length) + sizeof(additional_data_length));
    blocks.insert(blocks.end(), additional_data.begin(), additional_data.end());
    blocks.insert(blocks.end(), payload.begin(), payload.end());

    // AES CBC encryption
    std::vector<uint8_t> y_blocks(16);
    AES_KEY aes_key;
    AES_set_encrypt_key(key.data(), 128, &aes_key);
    
    std::vector<uint8_t> padded_blocks = byte_pad(blocks, 16);
    AES_cbc_encrypt(padded_blocks.data(), y_blocks.data(), padded_blocks.size(), &aes_key, block_0.data(), AES_ENCRYPT);
    
    // only calculate, no ctr encryption
    return std::vector<uint8_t>(y_blocks.end() - 16, y_blocks.end());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> decrypt_ctr(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& counter_0,
    const std::vector<uint8_t>& mac,
    const std::vector<uint8_t>& payload = {}
) {
    // Decrypt data from SecureWrapper.
    // MAC will be decoded first with counter 0.
    // Returns a tuple of (KNX/IP frame bytes, MAC TR for verification).

    std::vector<uint8_t> decrypted_data(payload.size());
    std::vector<uint8_t> mac_tr(mac.size());

    AES_KEY aes_key;
    AES_set_decrypt_key(key.data(), 128, &aes_key);

    AES_ecb_encrypt(mac.data(), mac_tr.data(), &aes_key, AES_DECRYPT); // MAC is encrypted with counter 0
    AES_ecb_encrypt(payload.data(), decrypted_data.data(), &aes_key, AES_DECRYPT);

    return {decrypted_data, mac_tr};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encrypt_data_ctr(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& counter_0,
    const std::vector<uint8_t>& mac_cbc,
    const std::vector<uint8_t>& payload = {}
) {
    // Encrypt data with AES-CTR.
    // Payload is expected a full Plain KNX/IP frame with header.
    // MAC shall be encrypted with counter 0, KNXnet/IP frame with incremented counters.
    // Returns a tuple of encrypted data (if there is any) and encrypted MAC.

    std::vector<uint8_t> encrypted_data(payload.size());
    std::vector<uint8_t> mac(mac_cbc.size());

    AES_KEY aes_key;
    AES_set_encrypt_key(key.data(), 128, &aes_key);

    AES_ecb_encrypt(mac_cbc.data(), mac.data(), &aes_key, AES_ENCRYPT);
    AES_ecb_encrypt(payload.data(), encrypted_data.data(), &aes_key, AES_ENCRYPT);

    return {encrypted_data, mac};
}

std::vector<uint8_t> derive_device_authentication_password(const std::string& device_authentication_password) {
    // Derive device authentication password.
    // Implementation omitted for brevity; use PBKDF2 with SHA256.
    return {};
}

std::vector<uint8_t> derive_user_password(const std::string& password_string) {
    // Derive user password.
    // Implementation omitted for brevity; use PBKDF2 with SHA256.
    return {};
}

std::pair<X25519PrivateKey, std::vector<uint8_t>> generate_ecdh_key_pair() {
    // Generate an ECDH key pair.
    // Return the private key and the raw bytes of the public key.
    X25519PrivateKey private_key = X25519PrivateKey::generate();
    std::vector<uint8_t> public_key_raw = private_key.public_key().public_bytes();
    return {private_key, public_key_raw};
}
