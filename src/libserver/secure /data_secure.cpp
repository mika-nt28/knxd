#include <iostream>
#include <unordered_map>
#include <stdexcept>
#include <memory>
#include <ctime>
#include <string>
#include <iterator>
#include <chrono>

#include <Keyring.h>
const std::chrono::system_clock::time_point SEQUENCE_NUMBER_INIT_TIMESTAMP = 
    std::chrono::system_clock::from_time_t(1515110400); // Equivalent to "2018-01-05T00:00:00+00:00"

int initial_sequence_number() {
    // Return an initial sequence number for sending Data Secure Telegrams.
    auto current_time = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - SEQUENCE_NUMBER_INIT_TIMESTAMP);
    return static_cast<int>(duration.count());
}

class DataSecure {
    std::unordered_map<GroupAddress, std::vector<uint8_t>> group_key_table;
    std::unordered_map<IndividualAddress, int> individual_address_table;
    int sequence_number_sending;

public:
    DataSecure(std::unordered_map<GroupAddress, std::vector<uint8_t>> groupKeyTable,
               std::unordered_map<IndividualAddress, int> individualAddressTable,
               int lastSequenceNumberSending = -1) {
        group_key_table = std::move(groupKeyTable);
        individual_address_table = std::move(individualAddressTable);
        sequence_number_sending = (lastSequenceNumberSending != -1) ? lastSequenceNumberSending : _initial_sequence_number();

        if (!(0 < sequence_number_sending && sequence_number_sending < 0xFFFFFFFFFFFF)) {
            throw DataSecureError("Initial sequence number out of range.");
        }
        std::cout << "Data Secure initialized for " << group_key_table.size() 
                  << " group addresses from " << individual_address_table.size() << " individual addresses.\n";
    }

    static std::unique_ptr<DataSecure> init_from_keyring(Keyring& keyring) {
        auto ga_key_table = keyring.get_data_secure_group_keys();
        auto ia_seq_table = keyring.get_data_secure_senders();
        if (ga_key_table.empty()) {
            return nullptr;
        }
        return std::make_unique<DataSecure>(ga_key_table, ia_seq_table);
    }

    int get_sequence_number() {
        return sequence_number_sending++;
    }

    class SequenceNumberChecker {
        DataSecure& dataSecure;
        IndividualAddress source_address;
        int received_sequence_number;
        int last_valid_sequence_number;

    public:
        SequenceNumberChecker(DataSecure& ds, IndividualAddress srcAddr, int receivedSeqNum) 
            : dataSecure(ds), source_address(srcAddr), received_sequence_number(receivedSeqNum) {}

        void check() {
            auto it = dataSecure.individual_address_table.find(source_address);
            if (it == dataSecure.individual_address_table.end()) {
                throw DataSecureError("Source address not found in Security Individual Address Table.");
            }
            last_valid_sequence_number = it->second;
            if (!(received_sequence_number > last_valid_sequence_number)) {
                throw DataSecureError("Sequence number too low.");
            }
            dataSecure.individual_address_table[source_address] = received_sequence_number;
        }
    };

    CEMILData received_cemi(CEMILData cemi_data) {
        // Data Secure frame
        if (dynamic_cast<SecureAPDU*>(&cemi_data.payload)) {
            return _received_secure_cemi(cemi_data, cemi_data.payload);
        }
        // Plain group communication frame
        if (dynamic_cast<GroupAddress*>(&cemi_data.dst_addr)) {
            if (group_key_table.find(cemi_data.dst_addr) != group_key_table.end()) {
                throw DataSecureError("Discarding frame with plain APDU for secure group address.");
            }
            return cemi_data;
        }
        return cemi_data;
    }

private:
    int _initial_sequence_number() {
        return 0; // Placeholder for the actual implementation
    }

    CEMILData _received_secure_cemi(CEMILData cemi_data, SecureAPDU& payload) {
        // Placeholder for handling received secure CEMI
        return cemi_data;
    }
  CEMILData _received_secure_cemi(CEMILData cemi_data, SecureAPDU s_apdu) {
        // Handle received secured CEMI frame.
        if (s_apdu.scf.service != SecurityALService::S_A_DATA) {
            throw DataSecureError("Only SecurityALService.S_A_DATA supported " + cemi_data.src_addr);
        }
        if (s_apdu.scf.system_broadcast || s_apdu.scf.tool_access) {
            // TODO: handle incoming responses with tool key of sending device
            // when we can send with tool key
            throw DataSecureError("System broadcast and tool access not supported " + cemi_data.src_addr);
        }

        // Secure group communication frame
        std::vector<uint8_t> key;
        if (dynamic_cast<GroupAddress*>(&cemi_data.dst_addr)) {
            if (_group_key_table.find(cemi_data.dst_addr) != _group_key_table.end()) {
                key = _group_key_table[cemi_data.dst_addr];
            } else {
                throw DataSecureError("No key found for group address " + cemi_data.dst_addr + " from " + cemi_data.src_addr);
            }
        } else {
            // Secure point-to-point frame
            // TODO: maybe possible to implement this over tool key
            throw DataSecureError("Secure Point-to-Point communication not supported " + cemi_data.src_addr);
        }

        {
            SequenceChecker sequenceChecker(cemi_data.src_addr, static_cast<int>(s_apdu.secured_data.sequence_number_bytes[0]));
            std::vector<uint8_t> address_fields_raw = cemi_data.src_addr + cemi_data.dst_addr;
            std::vector<uint8_t> plain_apdu_raw = s_apdu.secured_data.get_plain_apdu(
                key, 
                s_apdu.scf, 
                address_fields_raw, 
                cemi_data.flags, 
                cemi_data.tpci
            );
            APCI decrypted_payload = APCI::from_knx(plain_apdu_raw);
            _LOGGER.debug("Unpacked APDU from " + s_apdu.secured_data.sequence_number_bytes[0]);

            CEMILData plain_cemi_data = cemi_data;
            plain_cemi_data.payload = decrypted_payload; // Assuming payload can accept APCI
            return plain_cemi_data;
        }
    }

    CEMILData outgoing_cemi(CEMILData cemi_data) {
        // Handle outgoing CEMI frame. Pass through as plain frame or encrypt.
        // Outgoing group communication frame
        if (dynamic_cast<GroupAddress*>(&cemi_data.dst_addr)) {
            std::vector<uint8_t> key;
            if (_group_key_table.find(cemi_data.dst_addr) != _group_key_table.end()) {
                key = _group_key_table[cemi_data.dst_addr];
                SecureAPDU::SCF scf = { 
                    .service = SecurityALService::S_A_DATA, 
                    .system_broadcast = false, 
                    .tool_access = false 
                };
                return _secure_data_cemi(key, scf, cemi_data);
            }
            return cemi_data;
        }
        // Outgoing secure point-to-point frames are sent plain.
        // Data Secure point-to-point is not supported.
        return cemi_data;
    }

    CEMILData _secure_data_cemi(
        const std::vector<uint8_t>& key,
        const SecureAPDU::SCF& scf,
        CEMILData cemi_data) {
        // Wrap encrypted payload of a plain CEMILData in a SecureAPDU.
        std::vector<uint8_t> plain_apdu_raw;

        if (!cemi_data.payload.empty()) {
            plain_apdu_raw = cemi_data.payload; // Assuming payload can be converted
        } else {
            // TODO: test if this is correct
            plain_apdu_raw = {}; // used in point-to-point eg. TConnect
        }
        SecureData secure_asdu = SecureData::init_from_plain_apdu(
            key,
            plain_apdu_raw,
            scf,
            get_sequence_number(),
            cemi_data.src_addr + cemi_data.dst_addr,
            cemi_data.flags,
            cemi_data.tpci
        );
        CEMILData secure_cemi_data = cemi_data;
        secure_cemi_data.payload = SecureAPDU{ scf, secure_asdu };
        _LOGGER.debug("Secured APDU with " + cemi_data.src_addr);
        return secure_cemi_data;
    }
};
