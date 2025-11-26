#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <vector>

// Compile: g++ -o generate_traditional_certs generate_traditional_certs.cpp -I../install/include -L../install/lib -lcrypto -lpthread -ldl -std=c++11

// RAII wrappers
struct EVPKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct X509Deleter {
    void operator()(X509* cert) const { X509_free(cert); }
};
struct X509ReqDeleter {
    void operator()(X509_REQ* req) const { X509_REQ_free(req); }
};

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using X509_ptr = std::unique_ptr<X509, X509Deleter>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, X509ReqDeleter>;

void handleOpenSSLError(const std::string& context) {
    std::cerr << "Error in " << context << ": ";
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Generate RSA key
EVP_PKEY* generateRSAKey(int bits) {
    std::cout << "   Generating RSA-" << bits << " key pair..." << std::endl;
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) handleOpenSSLError("EVP_PKEY_CTX_new_id");
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen_init");
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_CTX_set_rsa_keygen_bits");
    }
    
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return key;
}

// Generate ECDSA key
EVP_PKEY* generateECDSAKey(int nid) {
    std::cout << "   Generating ECDSA P-256 key pair..." << std::endl;
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) handleOpenSSLError("EVP_PKEY_CTX_new_id");
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen_init");
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
    }
    
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLError("EVP_PKEY_keygen");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return key;
}

void setCertificateSubject(X509* cert, const std::string& country, 
                          const std::string& state, const std::string& locality,
                          const std::string& org, const std::string& cn) {
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)country.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)state.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)locality.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)org.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);
}

X509* createSelfSignedCertificate(EVP_PKEY* key, int days,
                                  const std::string& country, const std::string& state,
                                  const std::string& locality, const std::string& org,
                                  const std::string& cn) {
    X509* cert = X509_new();
    if (!cert) handleOpenSSLError("X509_new");
    
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600);
    X509_set_pubkey(cert, key);
    setCertificateSubject(cert, country, state, locality, org, cn);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    
    X509_EXTENSION* ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    
    if (!X509_sign(cert, key, EVP_sha256())) {
        X509_free(cert);
        handleOpenSSLError("X509_sign");
    }
    
    return cert;
}

X509_REQ* createCertificateRequest(EVP_PKEY* key,
                                   const std::string& country, const std::string& state,
                                   const std::string& locality, const std::string& org,
                                   const std::string& cn) {
    X509_REQ* req = X509_REQ_new();
    if (!req) handleOpenSSLError("X509_REQ_new");
    
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, key);
    
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)country.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)state.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)locality.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)org.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);
    
    if (!X509_REQ_sign(req, key, EVP_sha256())) {
        X509_REQ_free(req);
        handleOpenSSLError("X509_REQ_sign");
    }
    
    return req;
}

X509* signCertificateRequest(X509_REQ* req, X509* ca_cert, EVP_PKEY* ca_key, 
                             int days, bool is_ca) {
    X509* cert = X509_new();
    if (!cert) handleOpenSSLError("X509_new");
    
    X509_set_version(cert, 2);
    static long serial = 2;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600);
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    
    EVP_PKEY* req_key = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, req_key);
    EVP_PKEY_free(req_key);
    
    X509_EXTENSION* ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, nullptr, nullptr, 0);
    
    if (is_ca) {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    } else {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    }
    
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        handleOpenSSLError("X509_sign");
    }
    
    return cert;
}

bool writePrivateKeyPEM(EVP_PKEY* key, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w");
    if (!file) return false;
    bool success = PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr) > 0;
    fclose(file);
    return success;
}

bool writeCertificatePEM(X509* cert, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w");
    if (!file) return false;
    bool success = PEM_write_X509(file, cert) > 0;
    fclose(file);
    return success;
}

bool writeCertificateChainPEM(const std::vector<X509*>& certs, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "w");
    if (!file) return false;
    bool success = true;
    for (X509* cert : certs) {
        if (PEM_write_X509(file, cert) <= 0) {
            success = false;
            break;
        }
    }
    fclose(file);
    return success;
}

int main() {
    std::cout << "=== Generating Traditional RSA/ECDSA Certificate Chain ===" << std::endl << std::endl;
    
    std::cout << "=== Step 1: Generating Keys ===" << std::endl << std::endl;
    
    std::cout << "1. Generating Root CA key (RSA-4096)..." << std::endl;
    EVP_PKEY_ptr root_key(generateRSAKey(4096));
    writePrivateKeyPEM(root_key.get(), "root_ca_key.pem");
    std::cout << "   ✓ Root CA key saved" << std::endl << std::endl;
    
    std::cout << "2. Generating Intermediate CA 1 key (RSA-2048)..." << std::endl;
    EVP_PKEY_ptr int1_key(generateRSAKey(2048));
    writePrivateKeyPEM(int1_key.get(), "intermediate1_ca_key.pem");
    std::cout << "   ✓ Intermediate CA 1 key saved" << std::endl << std::endl;
    
    std::cout << "3. Generating Intermediate CA 2 key (ECDSA P-256)..." << std::endl;
    EVP_PKEY_ptr int2_key(generateECDSAKey(NID_X9_62_prime256v1));
    writePrivateKeyPEM(int2_key.get(), "intermediate2_ca_key.pem");
    std::cout << "   ✓ Intermediate CA 2 key saved" << std::endl << std::endl;
    
    std::cout << "4. Generating Leaf key (ECDSA P-256)..." << std::endl;
    EVP_PKEY_ptr leaf_key(generateECDSAKey(NID_X9_62_prime256v1));
    writePrivateKeyPEM(leaf_key.get(), "leaf_key.pem");
    std::cout << "   ✓ Leaf key saved" << std::endl << std::endl;
    
    std::cout << "=== Step 2: Creating Certificates ===" << std::endl << std::endl;
    
    std::cout << "5. Creating Root CA certificate..." << std::endl;
    X509_ptr root_cert(createSelfSignedCertificate(root_key.get(), 7300,
        "US", "California", "San Francisco", "Example Root CA", "Example Root CA"));
    writeCertificatePEM(root_cert.get(), "root_ca_cert.pem");
    std::cout << "   ✓ Root CA certificate saved" << std::endl << std::endl;
    
    std::cout << "6-7. Creating Intermediate CA 1 certificate..." << std::endl;
    X509_REQ_ptr int1_req(createCertificateRequest(int1_key.get(),
        "US", "California", "San Francisco", "Example Intermediate CA 1", "Example Intermediate CA 1"));
    X509_ptr int1_cert(signCertificateRequest(int1_req.get(), root_cert.get(), root_key.get(), 3650, true));
    writeCertificatePEM(int1_cert.get(), "intermediate1_ca_cert.pem");
    std::cout << "   ✓ Intermediate CA 1 certificate saved" << std::endl << std::endl;
    
    std::cout << "8-9. Creating Intermediate CA 2 certificate..." << std::endl;
    X509_REQ_ptr int2_req(createCertificateRequest(int2_key.get(),
        "US", "California", "San Francisco", "Example Intermediate CA 2", "Example Intermediate CA 2"));
    X509_ptr int2_cert(signCertificateRequest(int2_req.get(), int1_cert.get(), int1_key.get(), 1825, true));
    writeCertificatePEM(int2_cert.get(), "intermediate2_ca_cert.pem");
    std::cout << "   ✓ Intermediate CA 2 certificate saved" << std::endl << std::endl;
    
    std::cout << "10-11. Creating Leaf certificate..." << std::endl;
    X509_REQ_ptr leaf_req(createCertificateRequest(leaf_key.get(),
        "US", "California", "San Francisco", "Example Server", "localhost"));
    X509_ptr leaf_cert(signCertificateRequest(leaf_req.get(), int2_cert.get(), int2_key.get(), 365, false));
    writeCertificatePEM(leaf_cert.get(), "leaf_cert.pem");
    std::cout << "   ✓ Leaf certificate saved" << std::endl << std::endl;
    
    std::cout << "12-14. Creating Client certificate..." << std::endl;
    EVP_PKEY_ptr client_key(generateECDSAKey(NID_X9_62_prime256v1));
    writePrivateKeyPEM(client_key.get(), "client_key.pem");
    X509_REQ_ptr client_req(createCertificateRequest(client_key.get(),
        "US", "California", "San Francisco", "Example Client", "client.example.com"));
    X509_ptr client_cert(signCertificateRequest(client_req.get(), int2_cert.get(), int2_key.get(), 365, false));
    writeCertificatePEM(client_cert.get(), "client_cert.pem");
    std::cout << "   ✓ Client certificate saved" << std::endl << std::endl;
    
    std::cout << "=== Step 3: Creating Certificate Chains ===" << std::endl << std::endl;
    
    std::vector<X509*> chain = {leaf_cert.get(), int2_cert.get(), int1_cert.get()};
    writeCertificateChainPEM(chain, "certificate_chain.pem");
    std::cout << "✓ Server certificate chain created" << std::endl;
    
    std::vector<X509*> client_chain = {client_cert.get(), int2_cert.get(), int1_cert.get()};
    writeCertificateChainPEM(client_chain, "client_certificate_chain.pem");
    std::cout << "✓ Client certificate chain created" << std::endl;
    
    std::vector<X509*> full_chain = {leaf_cert.get(), int2_cert.get(), int1_cert.get(), root_cert.get()};
    writeCertificateChainPEM(full_chain, "full_chain_with_root.pem");
    std::cout << "✓ Full chain with root created" << std::endl << std::endl;
    
    std::cout << "=== Summary ===" << std::endl << std::endl;
    std::cout << "Certificate hierarchy:" << std::endl;
    std::cout << "  Root CA (RSA-4096)" << std::endl;
    std::cout << "    └── Intermediate CA 1 (RSA-2048)" << std::endl;
    std::cout << "          └── Intermediate CA 2 (ECDSA P-256)" << std::endl;
    std::cout << "                ├── Server Leaf (ECDSA P-256)" << std::endl;
    std::cout << "                └── Client (ECDSA P-256)" << std::endl << std::endl;
    std::cout << "✓ All done! Traditional certificate chain generated successfully." << std::endl;
    
    return 0;
}
