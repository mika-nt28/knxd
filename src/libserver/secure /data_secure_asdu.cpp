// This code is a translation from Python to C++ for KNX Data Secure functionality.

#include <cstdint>
#include <vector>
#include <string>

constexpr uint8_t APCI_SEC_HIGH = 0x03;
constexpr uint8_t APCI_SEC_LOW = 0xF1;
constexpr uint8_t B0_AT_FIELD_FLAGS_MASK = 0b10001111;

std::vector<uint8_t> block_0(
    const std::vector<uint8_t>& sequence_number,
    const std::vector<uint8_t>& address_fields_raw,
    int frame_flags,
    int tpci_int,
    int payload_length
) {
    // Return Block 0 for KNX Data Secure.
    std::vector<uint8_t> result = sequence_number;
    result.insert(result.end(), address_fields_raw.begin(), address_fields_raw.end());
    result.push_back(0);
    result.push_back(frame_flags & B0_AT_FIELD_FLAGS_MASK);
    result.push_back((tpci_int << 2) + APCI_SEC_HIGH);
    result.push_back(APCI_SEC_LOW);
    result.push_back(0);
    result.push_back(static_cast<uint8_t>(payload_length));
    return result;
}

std::vector<uint8_t> counter_0(
    const std::vector<uint8_t>& sequence_number,
    const std::vector<uint8_t>& address_fields_raw
) {
    // Return Block Counter 0 for KNX Data Secure.
    std::vector<uint8_t> result = sequence_number;
    result.insert(result.end(), address_fields_raw.begin(), address_fields_raw.end());
    result.insert(result.end(), {0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    return result;
}

enum class SecurityAlgorithmIdentifier : uint8_t {
    CCM_AUTHENTICATION = 0b000,
    CCM_ENCRYPTION = 0b001
};

enum class SecurityALService : uint8_t {
    S_A_DATA = 0b000,
    S_A_SYNC_REQ = 0b001,
    S_A_SYNC_RES = 0b011
};

class SecurityControlField {
public:
    // Class for KNX Data Secure Security Control Field (SCF).
    bool tool_access;
    SecurityAlgorithmIdentifier algorithm;
    bool system_broadcast;
    SecurityALService service;

    SecurityControlField(
        bool tool_access,
        SecurityAlgorithmIdentifier algorithm,
        bool system_broadcast,
        SecurityALService service
    ) : tool_access(tool_access), algorithm(algorithm), system_broadcast(system_broadcast), service(service) {
        // Initialize SecurityControlField class.
    }

    static SecurityControlField from_knx(int raw) {
        // Parse/deserialize from KNX raw data.
        bool tool_access = raw & 0b10000000;
        SecurityAlgorithmIdentifier sai = static_cast<SecurityAlgorithmIdentifier>((raw >> 4) & 0b111);
        bool system_broadcast = raw & 0b1000;
        SecurityALService s_al_service = static_cast<SecurityALService>(raw & 0b111);

        return SecurityControlField(
            tool_access = tool_access,
            algorithm = sai,
            system_broadcast = system_broadcast,
            service = s_al_service
        );
    }

    std::vector<uint8_t> to_knx() const {
        // Serialize to KNX raw data.
        int raw = 0;
        raw |= tool_access << 7;
        raw |= static_cast<int>(algorithm) << 4;
        raw |= system_broadcast << 3;
        raw |= static_cast<int>(service);
        return {static_cast<uint8_t>(raw)};
    }

    std::string to_string() const {
        // Return object as readable string.
        return "<SecurityControlField tool_access=" + std::to_string(tool_access) +
               " algorithm=" + std::to_string(static_cast<int>(algorithm)) +
               " system_broadcast=" + std::to_string(system_broadcast) +
               " service=" + std::to_string(static_cast<int>(service)) + " />";
    }
};

class SecureData {
public:
    std::vector<uint8_t> message_authentication_code;
    std::vector<uint8_t> secured_apdu;
    std::vector<uint8_t> sequence_number_bytes;

    SecureData(
        const std::vector<uint8_t>& sequence_number_bytes,
        const std::vector<uint8_t>& secured_apdu,
        const std::vector<uint8_t>& message_authentication_code
    ) : sequence_number_bytes(sequence_number_bytes),
        secured_apdu(secured_apdu),
        message_authentication_code(message_authentication_code) {}

    size_t length() const {
        return 10 + secured_apdu.size(); // 10 = 6 bytes sequence number + 4 bytes MAC
    }

    static SecureData init_from_plain_apdu(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& apdu,
        const SecurityControlField& scf,
        int sequence_number,
        const std::vector<uint8_t>& address_fields_raw,
        int frame_flags,
        const TPCI& tpci
    ) {
        std::vector<uint8_t> sequence_number_bytes(6);
        for (int i = 5; i >= 0; --i) {
            sequence_number_bytes[i] = sequence_number & 0xFF;
            sequence_number >>= 8;
        }

        std::vector<uint8_t> mac;
        std::vector<uint8_t> secured_apdu;

        if (scf.algorithm == CCM_AUTHENTICATION) {
            mac = calculate_message_authentication_code_cbc(
                key,
                scf.to_knx(),
                apdu,
                block_0(sequence_number_bytes, address_fields_raw, frame_flags, tpci.to_knx(), 0)
            );
            mac.resize(4);
            secured_apdu = apdu;
        } else if (scf.algorithm == CCM_ENCRYPTION) {
            std::vector<uint8_t> mac_cbc = calculate_message_authentication_code_cbc(
                key,
                scf.to_knx(),
                apdu,
                block_0(sequence_number_bytes, address_fields_raw, frame_flags, tpci.to_knx(), apdu.size())
            );
            mac_cbc.resize(4);
            std::tie(secured_apdu, mac) = encrypt_data_ctr(
                key,
                counter_0(sequence_number_bytes, address_fields_raw),
                mac_cbc,
                apdu
            );
        } else {
            throw DataSecureError("Unknown secure algorithm");
        }

        return SecureData(sequence_number_bytes, secured_apdu, mac); // only 4 bytes are used
    }

    std::vector<uint8_t> to_knx() const {
        std::vector<uint8_t> result;
        result.insert(result.end(), sequence_number_bytes.begin(), sequence_number_bytes.end());
        result.insert(result.end(), secured_apdu.begin(), secured_apdu.end());
        result.insert(result.end(), message_authentication_code.begin(), message_authentication_code.end());
        return result;
    }

    static SecureData from_knx(const std::vector<uint8_t>& raw) {
        return SecureData(
            std::vector<uint8_t>(raw.begin(), raw.begin() + 6),
            std::vector<uint8_t>(raw.begin() + 6, raw.end() - 4),
            std::vector<uint8_t>(raw.end() - 4, raw.end())
        );
    }

    std::vector<uint8_t> get_plain_apdu(
        const std::vector<uint8_t>& key,
        const SecurityControlField& scf,
        const std::vector<uint8_t>& address_fields_raw,
        int frame_flags,
        const TPCI& tpci
    ) {
        if (scf.algorithm == CCM_ENCRYPTION) {
            std::vector<uint8_t> dec_payload, mac_tr;
            std::tie(dec_payload, mac_tr) = decrypt_ctr(
                key,
                counter_0(sequence_number_bytes, address_fields_raw),
                message_authentication_code,
                secured_apdu
            );

            std::vector<uint8_t> mac_cbc = calculate_message_authentication_code_cbc(
                key,
                scf.to_knx(),
                dec_payload,
                block_0(sequence_number_bytes, address_fields_raw, frame_flags, tpci.to_knx(), dec_payload.size())
            );
            mac_cbc.resize(4);

            if (mac_cbc != mac_tr) {
                throw DataSecureError("Data Secure MAC verification failed");
            }
            return dec_payload;
        }

        if (scf.algorithm == CCM_AUTHENTICATION) {
            std::vector<uint8_t> mac = calculate_message_authentication_code_cbc(
                key,
                scf.to_knx(),
                secured_apdu,
                block_0(sequence_number_bytes, address_fields_raw, frame_flags, tpci.to_knx(), 0)
            );
            mac.resize(4);

            if (mac != message_authentication_code) {
                throw DataSecureError("Data Secure MAC verification failed.");
            }
            return secured_apdu;
        }

        throw DataSecureError("Unknown secure algorithm");
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << "<SecureData sequence_number=" << static_cast<int>(sequence_number_bytes[0]) 
            << " secured_apdu=\"" << bytes_to_hex(secured_apdu) 
            << "\" message_authentication_code=\"" << bytes_to_hex(message_authentication_code) << "\" />";
        return oss.str();
    }

private:
    std::string bytes_to_hex(const std::vector<uint8_t>& bytes) const {
        std::ostringstream oss;
        for (auto byte : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }
};
