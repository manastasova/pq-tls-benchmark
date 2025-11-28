#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/nid.h>
#include <openssl/bytestring.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <cstring>
#include <vector>

// g++ -o generate_mldsa_certs generate_mldsa_certs.cpp -I../aws-lc/include ../build/ssl/libssl.a ../build/crypto/libcrypto.a -std=c++11 -lpthread -ldl && rm -f *_key.* *_cert.* *.pem *.der 2>/dev/null; ./generate_mldsa_certs

// RAII wrappers for OpenSSL objects
struct EVPKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct X509Deleter {
    void operator()(X509* cert) const { X509_free(cert); }
};
struct X509ReqDeleter {
    void operator()(X509_REQ* req) const { X509_REQ_free(req); }
};
struct BIODeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using X509_ptr = std::unique_ptr<X509, X509Deleter>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using BIO_ptr = std::unique_ptr<BIO, BIODeleter>;

// Helper function to handle OpenSSL errors
void handleOpenSSLError(const std::string& context) {
    std::cerr << "Error in " << context << ": ";
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Generate ML-DSA key pair
EVP_PKEY* generateMLDSAKey(int level) {
    int nid;
    std::string algorithm;
    
    switch(level) {
        case 44:
            nid = NID_MLDSA44;
            algorithm = "MLDSA44";
            break;
        case 65:
            nid = NID_MLDSA65;
            algorithm = "MLDSA65";
            break;
        case 87:
            nid = NID_MLDSA87;
            algorithm = "MLDSA87";
            break;
        default:
            std::cerr << "Invalid ML-DSA level: " << level << std::endl;
            return nullptr;
    }
    
    std::cout << "   Generating " << algorithm << " key pair..." << std::endl;
    
    // Create PQDSA context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, nullptr);
    if (!ctx) {
        handleOpenSSLError("EVP_PKEY_CTX_new_id");
    }
    
    // Set specific PQDSA parameters for this NID
    if (!EVP_PKEY_CTX_pqdsa_set_params(ctx, nid)) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_CTX_pqdsa_set_params");
    }
    
    // Initialize keygen
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen_init");
    }
    
    // Generate the key pair
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return key;
}

// Set certificate subject name
void setCertificateSubject(X509* cert, const std::string& country, 
                          const std::string& state, const std::string& locality,
                          const std::string& org, const std::string& cn) {
    X509_NAME* name = X509_NAME_new();
    
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               (unsigned char*)country.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, 
                               (unsigned char*)state.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, 
                               (unsigned char*)locality.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
                               (unsigned char*)org.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               (unsigned char*)cn.c_str(), -1, -1, 0);
    
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);
}

// Create self-signed certificate (for root CA)
X509* createSelfSignedCertificate(EVP_PKEY* key, int days,
                                  const std::string& country, const std::string& state,
                                  const std::string& locality, const std::string& org,
                                  const std::string& cn) {
    X509* cert = X509_new();
    if (!cert) {
        handleOpenSSLError("X509_new");
    }
    
    // Set version to X.509 v3
    X509_set_version(cert, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600);
    
    // Set public key
    X509_set_pubkey(cert, key);
    
    // Set subject name
    setCertificateSubject(cert, country, state, locality, org, cn);
    
    // Set issuer name (same as subject for self-signed)
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    
    // Add basic constraints extension for CA
    X509_EXTENSION* ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate (NULL digest for ML-DSA - it uses internal hashing)
    if (!X509_sign(cert, key, NULL)) {
        X509_free(cert);
        handleOpenSSLError("X509_sign");
    }
    
    return cert;
}

// Create certificate signing request
X509_REQ* createCertificateRequest(EVP_PKEY* key,
                                   const std::string& country, const std::string& state,
                                   const std::string& locality, const std::string& org,
                                   const std::string& cn) {
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        handleOpenSSLError("X509_REQ_new");
    }
    
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, key);
    
    // Set subject name
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               (unsigned char*)country.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, 
                               (unsigned char*)state.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, 
                               (unsigned char*)locality.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
                               (unsigned char*)org.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               (unsigned char*)cn.c_str(), -1, -1, 0);
    
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);
    
    // Sign the request (NULL digest for ML-DSA - it uses internal hashing)
    if (!X509_REQ_sign(req, key, NULL)) {
        X509_REQ_free(req);
        handleOpenSSLError("X509_REQ_sign");
    }
    
    return req;
}

// Sign a certificate request with a CA certificate
X509* signCertificateRequest(X509_REQ* req, X509* ca_cert, EVP_PKEY* ca_key, 
                             int days, bool is_ca) {
    X509* cert = X509_new();
    if (!cert) {
        handleOpenSSLError("X509_new");
    }
    
    // Set version
    X509_set_version(cert, 2);
    
    // Set serial number (in real implementation, use proper serial number management)
    static long serial = 2;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600);
    
    // Set subject name from request
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    
    // Set issuer name from CA certificate
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    
    // Set public key from request
    EVP_PKEY* req_key = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, req_key);
    EVP_PKEY_free(req_key);
    
    // Add extensions
    X509_EXTENSION* ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, nullptr, nullptr, 0);
    
    if (is_ca) {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    } else {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, 
                                  "critical,digitalSignature,keyEncipherment");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    
    // Sign the certificate (NULL digest for ML-DSA - it uses internal hashing)
    if (!X509_sign(cert, ca_key, NULL)) {
        X509_free(cert);
        handleOpenSSLError("X509_sign");
    }
    
    return cert;
}

// Get OID for ML-DSA algorithm
bool getMLDSAOID(EVP_PKEY* key, const uint8_t** oid, size_t* oid_len) {
    // Get the NID - for PQDSA keys, we need to check the algorithm
    int pkey_type = EVP_PKEY_base_id(key);
    
    // For PQDSA keys, try to extract raw key to determine size
    size_t raw_key_len = 0;
    if (!EVP_PKEY_get_raw_private_key(key, nullptr, &raw_key_len)) {
        return false;
    }
    
    // Determine algorithm based on key size
    // ML-DSA-44 expanded key: ~2560 bytes
    // ML-DSA-65 expanded key: ~4032 bytes  
    // ML-DSA-87 expanded key: ~4896 bytes
    if (raw_key_len >= 4500) {
        // ML-DSA-87: 2.16.840.1.101.3.4.3.19
        static const uint8_t mldsa87_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
        *oid = mldsa87_oid;
        *oid_len = sizeof(mldsa87_oid);
        return true;
    } else if (raw_key_len >= 3500) {
        // ML-DSA-65: 2.16.840.1.101.3.4.3.18
        static const uint8_t mldsa65_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
        *oid = mldsa65_oid;
        *oid_len = sizeof(mldsa65_oid);
        return true;
    } else if (raw_key_len >= 2000) {
        // ML-DSA-44: 2.16.840.1.101.3.4.3.17
        static const uint8_t mldsa44_oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
        *oid = mldsa44_oid;
        *oid_len = sizeof(mldsa44_oid);
        return true;
    }
    
    return false;
}

// Write private key in expanded format to DER file
bool writePrivateKeyDER(EVP_PKEY* key, const std::string& filename) {
    // Get the raw private key (expanded format)
    size_t priv_len = 0;
    if (!EVP_PKEY_get_raw_private_key(key, nullptr, &priv_len) || priv_len == 0) {
        std::cerr << "Failed to get private key length" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> priv_key(priv_len);
    if (!EVP_PKEY_get_raw_private_key(key, priv_key.data(), &priv_len)) {
        std::cerr << "Failed to get raw private key" << std::endl;
        return false;
    }
    
    // Get OID for the algorithm
    const uint8_t* oid;
    size_t oid_len;
    if (!getMLDSAOID(key, &oid, &oid_len)) {
        std::cerr << "Failed to get OID for key type" << std::endl;
        return false;
    }
    
    // Build PKCS#8 structure with expanded key format
    // PKCS#8 format: SEQUENCE { version, AlgorithmIdentifier, PrivateKey }
    // For ML-DSA expanded format, PrivateKey contains: OCTET_STRING { expandedKey }
    CBB cbb, pkcs8, algorithm, oid_cbb, private_key, expanded_key;
    if (!CBB_init(&cbb, 0) ||
        !CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&algorithm, &oid_cbb, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid_cbb, oid, oid_len) ||
        !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_asn1(&private_key, &expanded_key, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&expanded_key, priv_key.data(), priv_key.size()) ||
        !CBB_flush(&cbb)) {
        CBB_cleanup(&cbb);
        std::cerr << "Failed to build PKCS#8 structure" << std::endl;
        return false;
    }
    
    uint8_t *der_bytes;
    size_t der_len;
    if (!CBB_finish(&cbb, &der_bytes, &der_len)) {
        CBB_cleanup(&cbb);
        std::cerr << "Failed to finish CBB" << std::endl;
        return false;
    }
    
    // Write to file
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        OPENSSL_free(der_bytes);
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    file.write(reinterpret_cast<char*>(der_bytes), der_len);
    file.close();
    OPENSSL_free(der_bytes);
    
    return true;
}

// Write certificate to DER file
bool writeCertificateDER(X509* cert, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    bool success = (i2d_X509_bio(bio, cert) > 0);
    BIO_free(bio);
    
    if (!success) {
        std::cerr << "Failed to write certificate to " << filename << std::endl;
    }
    return success;
}

// Write certificate chain to DER file
bool writeCertificateChainDER(const std::vector<X509*>& certs, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    for (X509* cert : certs) {
        unsigned char* der = nullptr;
        int len = i2d_X509(cert, &der);
        if (len < 0 || !der) {
            std::cerr << "Failed to convert certificate to DER" << std::endl;
            return false;
        }
        
        file.write(reinterpret_cast<char*>(der), len);
        OPENSSL_free(der);
    }
    
    file.close();
    return true;
}

// Write private key in expanded format to PEM file
bool writePrivateKeyPEM(EVP_PKEY* key, const std::string& filename) {
    // Get the raw private key (expanded format)
    size_t priv_len = 0;
    if (!EVP_PKEY_get_raw_private_key(key, nullptr, &priv_len) || priv_len == 0) {
        std::cerr << "Failed to get private key length" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> priv_key(priv_len);
    if (!EVP_PKEY_get_raw_private_key(key, priv_key.data(), &priv_len)) {
        std::cerr << "Failed to get raw private key" << std::endl;
        return false;
    }
    
    // Get OID for the algorithm
    const uint8_t* oid;
    size_t oid_len;
    if (!getMLDSAOID(key, &oid, &oid_len)) {
        std::cerr << "Failed to get OID for key type" << std::endl;
        return false;
    }
    
    // Build PKCS#8 structure with expanded key format
    CBB cbb, pkcs8, algorithm, oid_cbb, private_key, expanded_key;
    if (!CBB_init(&cbb, 0) ||
        !CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1(&algorithm, &oid_cbb, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid_cbb, oid, oid_len) ||
        !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_asn1(&private_key, &expanded_key, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&expanded_key, priv_key.data(), priv_key.size()) ||
        !CBB_flush(&cbb)) {
        CBB_cleanup(&cbb);
        std::cerr << "Failed to build PKCS#8 structure" << std::endl;
        return false;
    }
    
    uint8_t *der_bytes;
    size_t der_len;
    if (!CBB_finish(&cbb, &der_bytes, &der_len)) {
        CBB_cleanup(&cbb);
        std::cerr << "Failed to finish CBB" << std::endl;
        return false;
    }
    
    // Write as PEM
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        OPENSSL_free(der_bytes);
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    // Write PEM header
    bool success = (PEM_write_bio(bio, "PRIVATE KEY", "", der_bytes, der_len) > 0);
    BIO_free(bio);
    OPENSSL_free(der_bytes);
    
    if (!success) {
        std::cerr << "Failed to write private key to " << filename << std::endl;
    }
    return success;
}

// Write certificate to PEM file using BIO
bool writeCertificatePEM(X509* cert, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    bool success = PEM_write_bio_X509(bio, cert) > 0;
    BIO_free(bio);
    
    if (!success) {
        std::cerr << "Failed to write certificate to " << filename << std::endl;
    }
    return success;
}

// Write certificate chain to PEM file using BIO
bool writeCertificateChainPEM(const std::vector<X509*>& certs, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return false;
    }
    
    bool success = true;
    for (X509* cert : certs) {
        if (PEM_write_bio_X509(bio, cert) <= 0) {
            std::cerr << "Failed to write certificate to chain file" << std::endl;
            success = false;
            break;
        }
    }
    
    BIO_free(bio);
    return success;
}

int main() {
    std::cout << "=== Generating ML-DSA Certificate Chain with AWS-LC ===" << std::endl;
    std::cout << std::endl;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    std::cout << "=== Step 1: Generating ML-DSA Keys ===" << std::endl;
    std::cout << std::endl;
    
    // Generate root CA key (ML-DSA-65)
    std::cout << "1. Generating Root CA key (ML-DSA-65)..." << std::endl;
    EVP_PKEY_ptr root_key(generateMLDSAKey(65));
    if (!root_key) {
        return 1;
    }
    writePrivateKeyDER(root_key.get(), "root_ca_key.der");
    writePrivateKeyPEM(root_key.get(), "root_ca_key.pem");
    std::cout << "   ✓ Root CA key generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    // Generate intermediate CA 1 key (ML-DSA-65)
    std::cout << "2. Generating Intermediate CA 1 key (ML-DSA-65)..." << std::endl;
    EVP_PKEY_ptr int1_key(generateMLDSAKey(65));
    if (!int1_key) {
        return 1;
    }
    writePrivateKeyDER(int1_key.get(), "intermediate1_ca_key.der");
    writePrivateKeyPEM(int1_key.get(), "intermediate1_ca_key.pem");
    std::cout << "   ✓ Intermediate CA 1 key generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    // Generate intermediate CA 2 key (ML-DSA-65)
    std::cout << "3. Generating Intermediate CA 2 key (ML-DSA-65)..." << std::endl;
    EVP_PKEY_ptr int2_key(generateMLDSAKey(65));
    if (!int2_key) {
        return 1;
    }
    writePrivateKeyDER(int2_key.get(), "intermediate2_ca_key.der");
    writePrivateKeyPEM(int2_key.get(), "intermediate2_ca_key.pem");
    std::cout << "   ✓ Intermediate CA 2 key generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    // Generate leaf key (ML-DSA-44)
    std::cout << "4. Generating Leaf key (ML-DSA-44)..." << std::endl;
    EVP_PKEY_ptr leaf_key(generateMLDSAKey(44));
    if (!leaf_key) {
        return 1;
    }
    writePrivateKeyDER(leaf_key.get(), "leaf_key.der");
    writePrivateKeyPEM(leaf_key.get(), "leaf_key.pem");
    std::cout << "   ✓ Leaf key generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 2: Generating Root CA Certificate (Self-Signed) ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "5. Creating Root CA self-signed certificate..." << std::endl;
    X509_ptr root_cert(createSelfSignedCertificate(
        root_key.get(), 7300,
        "US", "California", "San Francisco", 
        "Example Root CA", "Example Root CA"
    ));
    writeCertificateDER(root_cert.get(), "root_ca_cert.der");
    writeCertificatePEM(root_cert.get(), "root_ca_cert.pem");
    std::cout << "   ✓ Root CA certificate generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 3: Generating Intermediate CA 1 Certificate ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "6. Creating Intermediate CA 1 certificate signing request..." << std::endl;
    X509_REQ_ptr int1_req(createCertificateRequest(
        int1_key.get(),
        "US", "California", "San Francisco",
        "Example Intermediate CA 1", "Example Intermediate CA 1"
    ));
    std::cout << "   ✓ Intermediate CA 1 CSR created" << std::endl;
    
    std::cout << "7. Signing Intermediate CA 1 certificate with Root CA..." << std::endl;
    X509_ptr int1_cert(signCertificateRequest(
        int1_req.get(), root_cert.get(), root_key.get(), 3650, true
    ));
    writeCertificateDER(int1_cert.get(), "intermediate1_ca_cert.der");
    writeCertificatePEM(int1_cert.get(), "intermediate1_ca_cert.pem");
    std::cout << "   ✓ Intermediate CA 1 certificate signed and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 4: Generating Intermediate CA 2 Certificate ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "8. Creating Intermediate CA 2 certificate signing request..." << std::endl;
    X509_REQ_ptr int2_req(createCertificateRequest(
        int2_key.get(),
        "US", "California", "San Francisco",
        "Example Intermediate CA 2", "Example Intermediate CA 2"
    ));
    std::cout << "   ✓ Intermediate CA 2 CSR created" << std::endl;
    
    std::cout << "9. Signing Intermediate CA 2 certificate with Intermediate CA 1..." << std::endl;
    X509_ptr int2_cert(signCertificateRequest(
        int2_req.get(), int1_cert.get(), int1_key.get(), 1825, true
    ));
    writeCertificateDER(int2_cert.get(), "intermediate2_ca_cert.der");
    writeCertificatePEM(int2_cert.get(), "intermediate2_ca_cert.pem");
    std::cout << "   ✓ Intermediate CA 2 certificate signed and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 5: Generating Leaf Certificate ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "10. Creating Leaf certificate signing request..." << std::endl;
    X509_REQ_ptr leaf_req(createCertificateRequest(
        leaf_key.get(),
        "US", "California", "San Francisco",
        "Example Server", "localhost"
    ));
    std::cout << "   ✓ Leaf CSR created" << std::endl;
    
    std::cout << "11. Signing Leaf certificate with Intermediate CA 2..." << std::endl;
    X509_ptr leaf_cert(signCertificateRequest(
        leaf_req.get(), int2_cert.get(), int2_key.get(), 365, false
    ));
    writeCertificateDER(leaf_cert.get(), "leaf_cert.der");
    writeCertificatePEM(leaf_cert.get(), "leaf_cert.pem");
    std::cout << "   ✓ Leaf certificate signed and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 6: Generating Client Certificate ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "12. Generating Client key (ML-DSA-44)..." << std::endl;
    EVP_PKEY_ptr client_key(generateMLDSAKey(44));
    if (!client_key) {
        return 1;
    }
    writePrivateKeyDER(client_key.get(), "client_key.der");
    writePrivateKeyPEM(client_key.get(), "client_key.pem");
    std::cout << "   ✓ Client key generated and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "13. Creating Client certificate signing request..." << std::endl;
    X509_REQ_ptr client_req(createCertificateRequest(
        client_key.get(),
        "US", "California", "San Francisco",
        "Example Client", "client.example.com"
    ));
    std::cout << "   ✓ Client CSR created" << std::endl;
    
    std::cout << "14. Signing Client certificate with Intermediate CA 2..." << std::endl;
    X509_ptr client_cert(signCertificateRequest(
        client_req.get(), int2_cert.get(), int2_key.get(), 365, false
    ));
    writeCertificateDER(client_cert.get(), "client_cert.der");
    writeCertificatePEM(client_cert.get(), "client_cert.pem");
    std::cout << "   ✓ Client certificate signed and saved (DER + PEM)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Step 7: Creating Certificate Chain Files ===" << std::endl;
    std::cout << std::endl;
    
    std::cout << "15. Building server certificate chain file..." << std::endl;
    std::vector<X509*> chain = {leaf_cert.get(), int2_cert.get(), int1_cert.get()};
    writeCertificateChainDER(chain, "certificate_chain.der");
    writeCertificateChainPEM(chain, "certificate_chain.pem");
    std::cout << "   ✓ Server certificate chain created: certificate_chain.der + certificate_chain.pem" << std::endl;
    
    std::cout << "16. Building client certificate chain file..." << std::endl;
    std::vector<X509*> client_chain = {client_cert.get(), int2_cert.get(), int1_cert.get()};
    writeCertificateChainDER(client_chain, "client_certificate_chain.der");
    writeCertificateChainPEM(client_chain, "client_certificate_chain.pem");
    std::cout << "   ✓ Client certificate chain created: client_certificate_chain.der + client_certificate_chain.pem" << std::endl;
    
    std::vector<X509*> full_chain = {leaf_cert.get(), int2_cert.get(), int1_cert.get(), root_cert.get()};
    writeCertificateChainDER(full_chain, "full_chain_with_root.der");
    writeCertificateChainPEM(full_chain, "full_chain_with_root.pem");
    std::cout << "   ✓ Full server chain with root created: full_chain_with_root.der + full_chain_with_root.pem" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=== Certificate Chain Summary ===" << std::endl;
    std::cout << std::endl;
    std::cout << "Certificate hierarchy:" << std::endl;
    std::cout << "  Root CA (ML-DSA-65) [root_ca_cert.der]" << std::endl;
    std::cout << "    └── Intermediate CA 1 (ML-DSA-65) [intermediate1_ca_cert.der]" << std::endl;
    std::cout << "          └── Intermediate CA 2 (ML-DSA-65) [intermediate2_ca_cert.der]" << std::endl;
    std::cout << "                ├── Server Leaf Certificate (ML-DSA-44) [leaf_cert.der]" << std::endl;
    std::cout << "                └── Client Certificate (ML-DSA-44) [client_cert.der]" << std::endl;
    std::cout << std::endl;
    std::cout << "All files generated (DER + PEM):" << std::endl;
    std::cout << "  Keys:" << std::endl;
    std::cout << "    - root_ca_key.der / root_ca_key.pem" << std::endl;
    std::cout << "    - intermediate1_ca_key.der / intermediate1_ca_key.pem" << std::endl;
    std::cout << "    - intermediate2_ca_key.der / intermediate2_ca_key.pem" << std::endl;
    std::cout << "    - leaf_key.der / leaf_key.pem (server)" << std::endl;
    std::cout << "    - client_key.der / client_key.pem (client)" << std::endl;
    std::cout << std::endl;
    std::cout << "  Certificates:" << std::endl;
    std::cout << "    - root_ca_cert.der / root_ca_cert.pem" << std::endl;
    std::cout << "    - intermediate1_ca_cert.der / intermediate1_ca_cert.pem" << std::endl;
    std::cout << "    - intermediate2_ca_cert.der / intermediate2_ca_cert.pem" << std::endl;
    std::cout << "    - leaf_cert.der / leaf_cert.pem (server)" << std::endl;
    std::cout << "    - client_cert.der / client_cert.pem (client)" << std::endl;
    std::cout << std::endl;
    std::cout << "  Certificate Chains:" << std::endl;
    std::cout << "    - certificate_chain.der / certificate_chain.pem (Server: Leaf + Int2 + Int1)" << std::endl;
    std::cout << "    - client_certificate_chain.der / client_certificate_chain.pem (Client + Int2 + Int1)" << std::endl;
    std::cout << "    - full_chain_with_root.der / full_chain_with_root.pem (Server: Leaf + Int2 + Int1 + Root)" << std::endl;
    std::cout << std::endl;
    std::cout << "✓ All done! ML-DSA certificate chain generated successfully in DER and PEM formats." << std::endl;
    std::cout << "✓ All certificates use ML-DSA (post-quantum) signatures." << std::endl;
    std::cout << std::endl;
    
    // Cleanup (deprecated but harmless)
    
    return 0;
}
