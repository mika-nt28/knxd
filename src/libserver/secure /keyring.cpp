#include "keyring.h"
#include "util.h"
#include <iostream>
#include <string>
#include <memory>
#include <unordered_map>
#include <optional>
#include <cstdint>
#include <vector>
#include <base64.h> // Hypothetical header for base64 decoding
#include <aes.h>    // Hypothetical header for AES decryption
#include <future>
#include <algorithm>
#include "Logger.h" // Assuming logger is defined in Logger.h
#include "XMLParser.h" // Assuming XML parsing functions are defined here

enum class InterfaceType {
    TUNNELING, // Interface type enum.
    BACKBONE,
    USB
};

// Abstract base class for modeling attribute reader capabilities.
class AttributeReader {
public:
    virtual void parseXml(const Element& node) = 0; // Parse all needed attributes from the given node map.

    void decryptAttributes(const std::vector<uint8_t>& passwordHash, const std::vector<uint8_t>& initializationVector) {
        // Decrypt attribute data.
        return;
    }

    static Any getAttributeValue(const Attr& attribute) { // Get a given attribute value from an attribute document.
        if (dynamic_cast<const Attr*>(&attribute) != nullptr) {
            return attribute.value;
        }

        return attribute;
    }
};
class XMLAssignedGroupAddress {
    /** Assigned Group Addresses to an interface in a knxkeys file. */

public:
    GroupAddress address;
    std::vector<IndividualAddress> senders;

    void parse_xml(const Element& node) {
        /** Parse all needed attributes from the given node map. */
        const auto& attributes = node.attributes;
        address = GroupAddress(get_attribute_value(attributes.at("Address")));
        
        std::string sendersString = get_attribute_value(attributes.at("Senders"));
        std::istringstream sendersStream(sendersString);
        std::string sender;
        while (sendersStream >> sender) {
            senders.emplace_back(IndividualAddress(sender));
        }
    }

private:
    std::string get_attribute_value(const std::string& attribute) {
        return attribute; // Placeholder for actual implementation
    }
};
class XMLInterface : public AttributeReader {
public:
    /// Interface in a knxkeys file.

    InterfaceType type;
    IndividualAddress individualAddress;
    IndividualAddress* host = nullptr; // Use pointer for nullable type
    int* userId = nullptr; // Use pointer for nullable type
    std::string* password = nullptr; // Use pointer for nullable type
    std::string* decryptedPassword = nullptr; // Use pointer for nullable type
    std::string* decryptedAuthentication = nullptr; // Use pointer for nullable type
    std::string* authentication = nullptr; // Use pointer for nullable type
    std::map<GroupAddress, std::vector<IndividualAddress>> groupAddresses; // Use std::map for dictionary

    void parseXml(Element* node) {
        /// Parse all needed attributes from the given node map.
        auto attributes = node->attributes;
        type = InterfaceType(getAttributeValue(attributes["Type"]));
        individualAddress = IndividualAddress(getAttributeValue(attributes["IndividualAddress"]));
        std::string hostValue = getAttributeValue(attributes["Host"]);
        host = hostValue.empty() ? nullptr : new IndividualAddress(hostValue);
        std::string userIdValue = getAttributeValue(attributes["UserID"]);
        userId = userIdValue.empty() ? nullptr : new int(std::stoi(userIdValue));
        password = new std::string(getAttributeValue(attributes["Password"]));
        authentication = new std::string(getAttributeValue(attributes["Authentication"]));

        groupAddresses.clear();
        for (auto& assignedGa : node->childNodes) {
            if (assignedGa.nodeType != 3) {
                XMLAssignedGroupAddress xmlGroupAddress;
                xmlGroupAddress.parseXml(&assignedGa);
                groupAddresses[xmlGroupAddress.address] = xmlGroupAddress.senders;
            }
        }
    }

    void decryptAttributes(const std::vector<uint8_t>& passwordHash, const std::vector<uint8_t>& initializationVector) {
        /// Decrypt attributes.

        if (password != nullptr) {
            decryptedPassword = new std::string(extractPassword(decryptAes128Cbc(base64Decode(*password), passwordHash, initializationVector)));
        } else {
            decryptedPassword = nullptr;
        }

        if (authentication != nullptr) {
            decryptedAuthentication = new std::string(extractPassword(decryptAes128Cbc(base64Decode(*authentication), passwordHash, initializationVector)));
        } else {
            decryptedAuthentication = nullptr;
        }
    }
};
class XMLBackbone {
public:
    // Backbone in a knxkeys file.
    std::optional<std::vector<uint8_t>> decryptedKey;
    std::optional<std::string> key;
    std::optional<int> latency;
    std::optional<std::string> multicastAddress;

    void parseXML(const Element& node) {
        // Parse all needed attributes from the given node map.
        const auto& attributes = node.attributes;
        key = getAttributeValue(attributes.at("Key"));
        auto latencyValue = getAttributeValue(attributes.at("Latency"));
        if (latencyValue.has_value()) {
            latency = std::stoi(latencyValue.value());
        }
        multicastAddress = getAttributeValue(attributes.at("MulticastAddress"));
    }

    void decryptAttributes(const std::vector<uint8_t>& passwordHash, const std::vector<uint8_t>& initializationVector) {
        // Decrypt attribute data.
        if (key.has_value()) {
            decryptedKey = decryptAES128CBC(base64Decode(key.value()), passwordHash, initializationVector);
        }
    }

private:
    std::optional<std::string> getAttributeValue(const std::optional<std::string>& attribute) const {
        return attribute; // Hypothetical function to get attribute value
    }

    std::vector<uint8_t> decryptAES128CBC(const std::vector<uint8_t>& encryptedData, const std::vector<uint8_t>& passwordHash, const std::vector<uint8_t>& initializationVector) {
        // Hypothetical function to perform AES decryption
        // Implementation goes here
        return {}; // Placeholder
    }

    std::vector<uint8_t> base64Decode(const std::string& encodedData) {
        // Hypothetical function for base64 decoding
        return {}; // Placeholder
    }
};
class XMLGroupAddress : public AttributeReader {
    /// Group Address in a knxkeys file.
public:
    GroupAddress address;
    std::optional<std::vector<uint8_t>> decrypted_key; // Use optional to represent None
    std::string key;

    void parse_xml(const Element& node) {
        /// Parse all needed attributes from the given node map.
        auto attributes = node.attributes;
        address = GroupAddress(get_attribute_value(attributes["Address"]));
        key = get_attribute_value(attributes["Key"]);
    }

    void decrypt_attributes(const std::vector<uint8_t>& password_hash, const std::vector<uint8_t>& initialization_vector) {
        /// Decrypt attribute data.
        if (!key.empty()) {
            decrypted_key = decrypt_aes128cbc(
                base64_decode(key), password_hash, initialization_vector
            );
        }
    }
};

class XMLDevice : public AttributeReader {
    /// Device in a knxkeys file.
public:
    IndividualAddress individual_address;
    std::string tool_key;
    std::optional<std::vector<uint8_t>> decrypted_tool_key; // Use optional to represent None
    std::string management_password;
    std::optional<std::string> decrypted_management_password; // Use optional to represent None
    std::optional<std::string> decrypted_authentication; // Use optional to represent None
    std::string authentication;
    int sequence_number;

    void parse_xml(const Element& node) {
        /// Parse all needed attributes from the given node map.
        auto attributes = node.attributes;
        individual_address = IndividualAddress(get_attribute_value(attributes["IndividualAddress"]));
        tool_key = get_attribute_value(attributes["ToolKey"]);
        management_password = get_attribute_value(attributes["ManagementPassword"]);
        authentication = get_attribute_value(attributes["Authentication"]);
        sequence_number = std::stoi(get_attribute_value(attributes["SequenceNumber"], "0"));
    }

    void decrypt_attributes(const std::vector<uint8_t>& password_hash, const std::vector<uint8_t>& initialization_vector) {
        /// Decrypt attributes.
        if (!tool_key.empty()) {
            decrypted_tool_key = decrypt_aes128cbc(
                base64_decode(tool_key), password_hash, initialization_vector
            );
        } else {
            decrypted_tool_key.reset();
        }

        if (!authentication.empty()) {
            decrypted_authentication = extract_password(
                decrypt_aes128cbc(
                    base64_decode(authentication),
                    password_hash,
                    initialization_vector
                )
            );
        } else {
            decrypted_authentication.reset();
        }

        if (!management_password.empty()) {
            decrypted_management_password = extract_password(
                decrypt_aes128cbc(
                    base64_decode(management_password),
                    password_hash,
                    initialization_vector
                )
            );
        } else {
            decrypted_management_password.reset();
        }
    }
};

class Keyring : public AttributeReader {
    public:
        // Class for loading and decrypting knxkeys XML files.
        std::optional<XMLBackbone> backbone;
        std::vector<XMLInterface> interfaces;
        std::vector<XMLGroupAddress> groupAddresses;
        std::vector<XMLDevice> devices;
        std::string projectName;
        std::string createdBy;
        std::string created;
        std::vector<uint8_t> signature;
        std::string xmlns;

        Keyring() {
            // Initialize the Keyring.
            interfaces = {};
            devices = {};
            groupAddresses = {};
        }

        std::optional<XMLDevice> getDeviceByInterface(const XMLInterface& interface) {
            // Get the device for a given interface.
            for (const auto& device : devices) {
                if (device.individualAddress == interface.host) {
                    return device;
                }
            }
            return std::nullopt;
        }

        std::optional<IndividualAddress> getTunnelHostByInterface(const IndividualAddress& tunnellingSlot) {
            // Get the tunnel host for a given interface.
            for (const auto& interface : interfaces) {
                if (interface.type == InterfaceType::TUNNELING && interface.individualAddress == tunnellingSlot) {
                    return interface.host;
                }
            }
            return std::nullopt;
        }

        std::vector<XMLInterface> getTunnelInterfacesByHost(const IndividualAddress& host) {
            // Get all tunnel interfaces of a given host individual address.
            std::vector<XMLInterface> tunnels;
            for (const auto& tunnel : interfaces) {
                if (tunnel.type == InterfaceType::TUNNELING && tunnel.host == host) {
                    tunnels.push_back(tunnel);
                }
            }
            return tunnels;
        }

        std::optional<XMLInterface> getTunnelInterfaceByHostAndUserId(const IndividualAddress& host, int userId) {
            // Get the tunnel interface with the given host and user id.
            for (const auto& tunnel : getTunnelInterfacesByHost(host)) {
                if (tunnel.userId == userId) {
                    return tunnel;
                }
            }
            return std::nullopt;
        }

        std::optional<XMLInterface> getTunnelInterfaceByIndividualAddress(const IndividualAddress& tunnellingSlot) {
            // Get the interface with the given tunneling address.
            for (const auto& tunnel : interfaces) {
                if (tunnel.type == InterfaceType::TUNNELING && tunnel.individualAddress == tunnellingSlot) {
                    return tunnel;
                }
            }
            return std::nullopt;
        }

        std::optional<XMLInterface> getInterfaceByIndividualAddress(const IndividualAddress& individualAddress) {
            // Get the interface with the given individual address. Any interface type.
            for (const auto& interface : interfaces) {
                if (interface.individualAddress == individualAddress) {
                    return interface;
                }
            }
            return std::nullopt;
        }

        std::unordered_map<GroupAddress, std::vector<uint8_t>> getDataSecureGroupKeys(std::optional<IndividualAddress> receiver = std::nullopt) {
            // Get data secure group keys.
            std::unordered_map<GroupAddress, std::vector<uint8_t>> gaKeyTable;
            for (const auto& groupAddress : groupAddresses) {
                if (groupAddress.decryptedKey.has_value()) {
                    gaKeyTable[groupAddress.address] = groupAddress.decryptedKey.value();
                }
            }
            if (!receiver.has_value()) {
                return gaKeyTable;
            }

            auto rcvInterface = getInterfaceByIndividualAddress(receiver.value());
            if (!rcvInterface.has_value()) {
                return {};
            }

            std::unordered_map<GroupAddress, std::vector<uint8_t>> filteredKeys;
            for (const auto& [ga, key] : gaKeyTable) {
                if (std::find(rcvInterface.value()->groupAddresses.begin(), rcvInterface.value()->groupAddresses.end(), ga) != rcvInterface.value()->groupAddresses.end()) {
                    filteredKeys[ga] = key;
                }
            }
            return filteredKeys;
        }

        std::unordered_map<IndividualAddress, int> getDataSecureSenders() {
            // Get all data secure sending device addresses.
            std::unordered_map<IndividualAddress, int> iaSeqTable;
            for (const auto& interface : interfaces) {
                for (const auto& senders : interface.groupAddresses) {
                    for (const auto& ia : senders) {
                        iaSeqTable[ia] = 0;
                    }
                }
            }
            for (const auto& device : devices) {
                iaSeqTable[device.individualAddress] = device.sequenceNumber;
            }
            return iaSeqTable;
        }

        void parseXml(const Element& node) {
            // Parse all needed attributes from the given node map.
            const auto& attributes = node.attributes;
            projectName = getAttributeValue(attributes.at("Project"));
            createdBy = getAttributeValue(attributes.at("CreatedBy"));
            created = getAttributeValue(attributes.at("Created"));
            signature = base64Decode(getAttributeValue(attributes.at("Signature")));
            xmlns = getAttributeValue(attributes.at("xmlns"));

            for (const auto& subNode : node.childNodes) {
                if (subNode.nodeName == "Interface") {
                    XMLInterface interface;
                    interface.parseXml(subNode);
                    interfaces.push_back(interface);
                }
                if (subNode.nodeName == "Backbone") {
                    XMLBackbone backbone;
                    backbone.parseXml(subNode);
                    this->backbone = backbone;
                }
                if (subNode.nodeName == "Devices") {
                    for (const auto& deviceDoc : subNode.childNodes) {
                        XMLDevice device;
                        device.parseXml(deviceDoc);
                        devices.push_back(device);
                    }
                }
                else if (subNode.nodeName == "GroupAddresses") {
                    for (const auto& gaDoc : subNode.childNodes) {
                        XMLGroupAddress xmlGa;
                        xmlGa.parseXml(gaDoc);
                        groupAddresses.push_back(xmlGa);
                    }
                }
            }
        }

        void decrypt(const std::string& password) {
            // Decrypt all data.
            auto hashedPassword = hashKeyringPassword(password);
            auto initializationVector = sha256Hash(created).substr(0, 16);

            for (const auto& xmlElement : interfaces) {
                xmlElement.decryptAttributes(hashedPassword, initializationVector);
            }
            for (const auto& xmlElement : groupAddresses) {
                xmlElement.decryptAttributes(hashedPassword, initializationVector);
            }
            for (const auto& xmlElement : devices) {
                xmlElement.decryptAttributes(hashedPassword, initializationVector);
            }

            if (backbone.has_value()) {
                backbone->decryptAttributes(hashedPassword, initializationVector);
            }
        }
        void sync_load_keyring(const std::string& path, const std::string& password, bool validate_signature = true) {
    // Load a .knxkeys file from the given path.
    std::filesystem::path filePath(path);
    if (validate_signature && !verify_keyring_signature(filePath, password)) {
        throw InvalidSecureConfiguration("Signature verification of keyring file failed. Invalid password or malformed file content.");
    }
    try {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open the file.");
        }

        Document dom = parse(file);
        keyring.parse_xml(dom.getElementsByTagName("Keyring")[0]);

        keyring.decrypt(password);

        return keyring;
    } catch (const std::exception& exception) {
        logger.exception("There was an error during loading the knxkeys file.");
        throw InvalidSecureConfiguration() from exception;
    }
}
};

std::future<Keyring> loadKeyring(const std::string& path, const std::string& password, bool validateSignature = true) {
    // Load a .knxkeys file from the given path in an executor.
    return std::async(std::launch::async, syncLoadKeyring, path, password, validateSignature);
}

class KeyringSAXContentHandler {
    // SAX parser for keyring signature verification.
private:
    std::vector<uint8_t> output;
    std::string hashed_password;
    const std::vector<std::string> attribute_blacklist = {"xmlns", "Signature"};

public:
    KeyringSAXContentHandler(const std::string& keyring_password) {
        // Initialize.
        hashed_password = hash_keyring_password(keyring_password);
        output.clear();
    }

    void endDocument() {
        // Receive notification of the end of a document.
        append_string(base64_encode(hashed_password));
    }

    void startElement(const std::string& name, const std::map<std::string, std::string>& attrs) {
        // Start Element.
        output.push_back(1);
        append_string(name);

        for (const auto& [attr_name, attr_value] : attrs) {
            if (std::find(attribute_blacklist.begin(), attribute_blacklist.end(), attr_name) == attribute_blacklist.end()) {
                append_string(attr_name);
                append_string(attr_value);
            }
        }
    }

    void endElement(const std::string& name) {
        // Receive notification of the end of an element.
        output.push_back(2);
    }

    void append_string(const std::string& value) {
        // Append a string to a byte array for signature verification.
        output.push_back(static_cast<uint8_t>(value.length()));
        output.insert(output.end(), value.begin(), value.end());
    }

private:
    std::string hash_keyring_password(const std::string& password) {
        // Hash a given keyring password.
        unsigned char hash[SHA256_DIGEST_LENGTH];
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), 
                          reinterpret_cast<const unsigned char*>("1.keyring.ets.knx.org"), 25, 
                          65536, SHA256_DIGEST_LENGTH, hash);
        return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
    }
};

bool verify_keyring_signature(const std::string& path, const std::string& password) {
    // Verify the signature of the given knxkeys file.
    KeyringSAXContentHandler handler(password);
    std::string signature;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    // Assume XML parsing and signature extraction happens here
    // signature = ... 

    file.clear();
    file.seekg(0, std::ios::beg);
    // Assume SAX parser setup and parsing happens here

    // Assuming sha256_hash is defined to hash the output
    return sha256_hash(handler.output) == signature;
}

std::vector<uint8_t> decrypt_aes128cbc(
    const std::vector<uint8_t>& encrypted_data, 
    const std::vector<uint8_t>& key, 
    const std::vector<uint8_t>& initialization_vector) {
    // Decrypt data with AES 128 CBC.
    std::vector<uint8_t> decrypted_data(encrypted_data.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), initialization_vector.data());
    int len;
    EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(), encrypted_data.size());
    int final_len;
    EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    
    decrypted_data.resize(len + final_len);
    return decrypted_data;
}

std::string extract_password(const std::vector<uint8_t>& data) {
    // Extract the password.
    if (data.empty()) {
        return "";
    }
    size_t length = data.back();
    return std::string(data.begin() + 8, data.end() - length);
}
