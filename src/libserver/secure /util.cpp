#include <iostream>
#include <vector>
#include <stdexcept>
#include <cryptlib.h>
#include <sha.h>
#include <filters.h>
#include <hex.h>

std::vector<unsigned char> bytes_xor(const std::vector<unsigned char>& firstBytes, const std::vector<unsigned char>& secondBytes) {  // pylint: disable=invalid-name
    /*
    XOR two bytes values.

    Different lengths raise std::invalid_argument.
    */
    if (firstBytes.size() != secondBytes.size()) {
        throw std::invalid_argument("Length of firstBytes and secondBytes must be equal.");
    }
    std::vector<unsigned char> result(firstBytes.size());
    for (size_t i = 0; i < firstBytes.size(); ++i) {
        result[i] = firstBytes[i] ^ secondBytes[i];
    }
    return result;
}

std::vector<unsigned char> byte_pad(const std::vector<unsigned char>& data, size_t blockSize) {
    /** Pad data with 0x00 until its length is a multiple of block_size. */
    size_t remainder = data.size() % blockSize;
    if (remainder != 0) {
        std::vector<unsigned char> paddedData(data);
        paddedData.insert(paddedData.end(), blockSize - remainder, 0x00);
        return paddedData;
    }
    return data;
}

std::vector<unsigned char> sha256_hash(const std::vector<unsigned char>& data) {
    /** Calculate SHA256 hash of data. */
    CryptoPP::SHA256 hash;
    std::vector<unsigned char> digest(hash.DigestSize());
    hash.Update(data.data(), data.size());
    hash.Final(digest.data());
    return digest;
}
