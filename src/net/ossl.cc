/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2015 Cloudius Systems
 */

#include <seastar/net/tls.hh>
#include <seastar/net/stack.hh>
#include <seastar/core/gate.hh>
#include <seastar/util/later.hh>

#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

namespace seastar {

template<typename T, auto fn>
struct ssl_deleter {
    void operator()(T* ptr) { fn(ptr); }
};

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;
using x509_ptr = ssl_handle<X509, X509_free>;
using x509_store_ptr = ssl_handle<X509_STORE, X509_STORE_free>;
using x509_store_ctx_ptr = ssl_handle<X509_STORE_CTX, X509_STORE_CTX_free>;
using pkcs12 = ssl_handle<PKCS12, PKCS12_free>;

/// TODO: use non global ossl lib context
///
class tls::dh_params::impl {
public:
    static int level_to_bits(level l) {
        switch (l) {
            case level::LEGACY:
                return 1776;
            case level::MEDIUM:
                return 2432;
            case level::HIGH:
                return 3248;
            case level::ULTRA:
                return 15424;
            default:
                throw std::runtime_error(format("Unknown value of dh_params::level: {:d}", static_cast<std::underlying_type_t<level>>(l)));
        }
    }

    static evp_pkey_ptr make_evp_pkey(level l) {
        /// Instantiate new Diffie-Hellman key context
        EVP_PKEY *pkey = nullptr;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);

        OSSL_PARAM params[3];
        unsigned int bits = level_to_bits(l);
        char group[] = "group";
        params[0] = OSSL_PARAM_construct_utf8_string("type", group, strlen(group));
        params[1] = OSSL_PARAM_construct_uint("pbits", &bits);
        params[2] = OSSL_PARAM_construct_end();

        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_params(pctx, params);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);
        return evp_pkey_ptr(pkey);
    }

    impl(level l) : _pkey(make_evp_pkey(l)) {}

    impl(EVP_PKEY* pkey) : _pkey(pkey) {}

    impl(const blob& pkcs3, x509_crt_format fmt)
        : _pkey([&] {
            bio_ptr key_bio(BIO_new_mem_buf(pkcs3.begin(), pkcs3.size()));
            auto pkey_temp = EVP_PKEY_new();
            if(fmt == x509_crt_format::PEM) {
                if (nullptr == PEM_read_bio_Parameters(key_bio.get(), &pkey_temp)) {
                    EVP_PKEY_free(pkey_temp);
                    throw std::system_error(0, error_category());
                }
            } else if (fmt == x509_crt_format::DER) {
                if(nullptr == d2i_KeyParams_bio(EVP_PKEY_DH, &pkey_temp, key_bio.get())){
                    EVP_PKEY_free(pkey_temp);
                    throw std::system_error(0, error_category());
                }
            } else {
                throw std::invalid_argument("Unknown x509_crt_format selected");
            }
            return evp_pkey_ptr(pkey_temp);
        }())
    {}

    EVP_PKEY* get() const { return _pkey.get(); }

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    evp_pkey_ptr _pkey;
};

class tls::certificate_credentials::impl {
    struct cert_key_pair{
        x509_ptr cert;
        evp_pkey_ptr key;
    };

public:
    impl() : _creds([] {
        auto store = X509_STORE_new();
        if(store == nullptr) {
            throw std::bad_alloc();
        }
        return store;
    }()) {}

    static X509* parse_x509_cert(const blob& b, x509_crt_format fmt, X509** cert){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        X509* x509_cert = X509_new();
        if(fmt == tls::x509_crt_format::PEM) {
            if (nullptr == PEM_read_bio_X509(cert_bio.get(), &x509_cert, nullptr, nullptr)) {
                X509_free(x509_cert);
                return nullptr;
            }
        } else if(fmt == tls::x509_crt_format::DER) {
            if (nullptr == d2i_X509_bio(cert_bio.get(), &x509_cert)){
                X509_free(x509_cert);
                return nullptr;
            }
        }
        *cert = x509_cert;
        return *cert;
    }

    void set_x509_trust(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        X509* x509_cert = nullptr;
        if(nullptr == parse_x509_cert(b, fmt, &x509_cert)){
            throw std::system_error(0, tls::error_category());
        }
        X509_STORE_add_cert(*this, x509_cert);
    }

    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        X509_CRL* x509_crl = X509_CRL_new();
        if(fmt == x509_crt_format::PEM) {
            if (nullptr == PEM_read_bio_X509_CRL(cert_bio.get(), &x509_crl, nullptr, nullptr)){
                X509_CRL_free(x509_crl);
                throw std::system_error(0, tls::error_category());
            }
        } else if (fmt == x509_crt_format::DER){
            if (nullptr == d2i_X509_CRL_bio(cert_bio.get(), &x509_crl)){
                X509_CRL_free(x509_crl);
                throw std::system_error(0, tls::error_category());
            }
        } else {
            throw std::runtime_error("Unsupported cert format");
        }
        X509_STORE_add_crl(*this, x509_crl);
    }

    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        // Theres no interface to add cert-key pair to the certificate store as
        // the store represents the root and intermediate chain. Exposed for later
        // use when the ssl socket is created
        X509* x509_tmp = nullptr;
        if(nullptr == parse_x509_cert(cert, fmt, &x509_tmp)){
            throw std::system_error(0, tls::error_category());
        }
        auto x509_cert = x509_ptr(x509_tmp);
        bio_ptr key_bio(BIO_new_mem_buf(key.begin(), key.size()));
        auto pkey_temp = EVP_PKEY_new();
        if (nullptr == PEM_read_bio_PrivateKey(key_bio.get(), &pkey_temp, nullptr, nullptr)) {
            EVP_PKEY_free(pkey_temp);
            throw std::system_error(0, tls::error_category());
        }
        auto pkey = evp_pkey_ptr(pkey_temp);
        _ck_pair = std::make_optional(cert_key_pair{.cert = std::move(x509_cert), .key = std::move(pkey)});
    }

    void set_simple_pkcs12(const blob& b, x509_crt_format fmt, const sstring& password) {
        // Load the PKCS12 file
        bio_ptr bio(BIO_new_mem_buf(b.begin(), b.size()));
        PKCS12 *p12_tmp = nullptr;
        if(nullptr == d2i_PKCS12_bio(bio.get(), &p12_tmp)) {
            throw std::system_error(0, tls::error_category());
        }
        auto p12 = pkcs12(p12_tmp);
        // Extract the certificate and private key from PKCS12, using provided password
        EVP_PKEY *pkey = nullptr;
        X509 *cert = nullptr;
        if (!PKCS12_parse(p12.get(), password.c_str(), &pkey, &cert, nullptr)) {
            throw std::system_error(0, tls::error_category());
        }
        X509_STORE_add_cert(*this, cert);
        EVP_PKEY_free(pkey);
    }

    void dh_params(const tls::dh_params& dh) {
        // Theres no interface to add DH params to the certificate store as the store
        // represents the root and intermediate chain. Exposed for later use when
        auto cpy = std::make_unique<tls::dh_params::impl>(dh._impl->get());
        _dh_params = std::move(cpy);
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    operator X509_STORE*() const { return _creds.get(); }

    const std::optional<cert_key_pair>& get_cert_key_pair() const {
        return _ck_pair;
    }

private:
    friend class credentials_builder;

    x509_store_ptr _creds;
    std::optional<cert_key_pair> _ck_pair;
    std::unique_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    bool _load_system_trust = false;
    dn_callback _dn_callback;
};

} // namespace seastar
