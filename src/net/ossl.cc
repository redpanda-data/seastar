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

#ifdef SEASTAR_MODULE
module;
#endif

#include <system_error>

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/safestack.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#ifdef SEASTAR_MODULE
module seastar;
#else
#include <seastar/net/tls.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/stack.hh>
#include <seastar/core/gate.hh>
#include <seastar/util/later.hh>
#endif

namespace seastar {

class ossl_error_category : public std::error_category {
public:
    constexpr ossl_error_category() noexcept : std::error_category{} {}
    const char * name() const noexcept override {
        return "OpenSSL";
    }
    std::string message(int) const override {
        return "";
    }
};

const std::error_category& tls::error_category() {
    static const ossl_error_category ec;
    return ec;
}

class ossl_error : public std::runtime_error {
public:
    explicit ossl_error(const sstring& msg)
      : std::runtime_error{format("{}: {}", msg, build_error())} {}

private:
    static sstring build_error(){
        sstring msg = "{";
        std::array<char, 256> buf{};
        for (auto code = ERR_get_error(); code != 0; code = ERR_get_error()) {
            ERR_error_string_n(code, buf.data(), buf.size());
            msg += fmt::format("{{{}: {}}}", code, buf.data());
        }
        msg += "}";

        return msg;
    }
};

template<typename T, auto fn>
struct ssl_deleter {
    void operator()(T* ptr) { fn(ptr); }
};

// Must define this method as sk_X509_pop_free is a macro
void X509_pop_free(STACK_OF(X509)* ca) {
    sk_X509_pop_free(ca, X509_free);
}

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;
using x509_ptr = ssl_handle<X509, X509_free>;
using x509_crl_ptr = ssl_handle<X509_CRL, X509_CRL_free>;
using x509_store_ptr = ssl_handle<X509_STORE, X509_STORE_free>;
using x509_store_ctx_ptr = ssl_handle<X509_STORE_CTX, X509_STORE_CTX_free>;
using x509_chain_ptr = ssl_handle<STACK_OF(X509), X509_pop_free>;
using pkcs12 = ssl_handle<PKCS12, PKCS12_free>;

/// TODO: Implement the DH params impl struct
///
class tls::dh_params::impl {
public:
    impl(level) {}
    impl(const blob&, x509_crt_format){}

    EVP_PKEY* get() const { return _pkey.get(); }

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    evp_pkey_ptr _pkey;
};

tls::dh_params::dh_params(level lvl) : _impl(std::make_unique<impl>(lvl))
{}

tls::dh_params::dh_params(const blob& b, x509_crt_format fmt)
        : _impl(std::make_unique<impl>(b, fmt)) {
}

// TODO(rob) some small amount of code duplication here
tls::dh_params::~dh_params() {
}

tls::dh_params::dh_params(dh_params&&) noexcept = default;
tls::dh_params& tls::dh_params::operator=(dh_params&&) noexcept = default;

class tls::certificate_credentials::impl {
    struct server_credentials{
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

    static x509_ptr parse_x509_cert(const blob& b, x509_crt_format fmt){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        x509_ptr cert;
        switch(fmt) {
        case tls::x509_crt_format::PEM:
            cert = x509_ptr(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
            break;
        case tls::x509_crt_format::DER:
            cert = x509_ptr(d2i_X509_bio(cert_bio.get(), nullptr));
            break;
        default:
            __builtin_unreachable();
        }
        if (!cert) {
            throw ossl_error("Failed to parse x509 certificate");
        }
        return cert;
    }

    static x509_crl_ptr parse_x509_crl(const blob& b, x509_crt_format fmt){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        x509_crl_ptr crl;
        switch(fmt) {
        case x509_crt_format::PEM:
            crl = x509_crl_ptr(PEM_read_bio_X509_CRL(cert_bio.get(), nullptr, nullptr, nullptr));
            break;
        case x509_crt_format::DER:
            crl = x509_crl_ptr(d2i_X509_CRL_bio(cert_bio.get(), nullptr));
            break;
        default:
            __builtin_unreachable();
        }
        if (!crl) {
            throw ossl_error("Failed to parse x509 crl");
        }
        return crl;
    }

    void set_x509_trust(const blob& b, x509_crt_format fmt) {
        auto x509_cert = parse_x509_cert(b, fmt);
        X509_STORE_add_cert(*this, x509_cert.get());
    }

    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        auto x509_crl = parse_x509_crl(b, fmt);
        X509_STORE_add_crl(*this, x509_crl.get());
    }

    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        auto x509_cert = parse_x509_cert(cert, fmt);
        bio_ptr key_bio(BIO_new_mem_buf(key.begin(), key.size()));
        evp_pkey_ptr pkey;
        switch(fmt) {
        case x509_crt_format::PEM:
            pkey = evp_pkey_ptr(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
            break;
        case x509_crt_format::DER:
            pkey = evp_pkey_ptr(d2i_PrivateKey_bio(key_bio.get(), nullptr));
            break;
        default:
            __builtin_unreachable();
        }
        if (!pkey) {
            throw ossl_error("Error attempting to parse private key");
        }
        if (!X509_verify(x509_cert.get(), pkey.get())) {
            throw ossl_error("Failed to verify cert/key pair");
        }
        X509_STORE_add_cert(*this, x509_cert.get());
        _server_creds = server_credentials{.cert = std::move(x509_cert), .key = std::move(pkey)};
    }

    void set_simple_pkcs12(const blob& b, x509_crt_format, const sstring& password) {
        // Load the PKCS12 file
        bio_ptr bio(BIO_new_mem_buf(b.begin(), b.size()));
        if (auto p12 = pkcs12(d2i_PKCS12_bio(bio.get(), nullptr))) {
            // Extract the certificate and private key from PKCS12, using provided password
            EVP_PKEY *pkey = nullptr;
            X509 *cert = nullptr;
            STACK_OF(X509) *ca = nullptr;
            if (!PKCS12_parse(p12.get(), password.c_str(), &pkey, &cert, &ca)) {
                throw ossl_error("Failed to extract cert key pair from pkcs12 file");
            }
            // Ensure signature validation checks pass before continuing
            if (!X509_verify(cert, pkey)) {
                X509_free(cert);
                EVP_PKEY_free(pkey);
                throw ossl_error("Failed to verify cert/key pair");
            }
            _server_creds = server_credentials{.cert = x509_ptr(cert), .key = evp_pkey_ptr(pkey)};

            // Iterate through all elements in the certificate chain, adding them to the store
            auto ca_ptr = x509_chain_ptr(ca);
            if (ca_ptr) {
                auto num_elements = sk_X509_num(ca_ptr.get());
                while (num_elements > 0) {
                    auto e = sk_X509_pop(ca_ptr.get());
                    X509_STORE_add_cert(*this, e);
                    // store retains certificate
                    X509_free(e);
                    num_elements -= 1;
                }
            }
        } else {
            throw ossl_error("Failed to parse pkcs12 file");
        }
    }

    void dh_params(const tls::dh_params&) {}

    std::vector<cert_info> get_x509_info() const {
        return {};
    }

    std::vector<cert_info> get_x509_trust_list_info() const {
        return {};
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    void set_priority_string(const sstring&) {}

    void set_dn_verification_callback(dn_callback cb) {
        _dn_callback = std::move(cb);
    }

    operator X509_STORE*() const { return _creds.get(); }

    const server_credentials& get_server_credentials() const {
        return _server_creds;
    }

    future<> set_system_trust() {
        return make_ready_future<>();
    }

private:
    friend class credentials_builder;

    x509_store_ptr _creds;

    server_credentials _server_creds;
    std::shared_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    dn_callback _dn_callback;
};

tls::certificate_credentials::certificate_credentials()
        : _impl(make_shared<impl>()) {
}

tls::certificate_credentials::~certificate_credentials() {
}

tls::certificate_credentials::certificate_credentials(
        certificate_credentials&&) noexcept = default;
tls::certificate_credentials& tls::certificate_credentials::operator=(
        certificate_credentials&&) noexcept = default;

void tls::certificate_credentials::set_x509_trust(const blob& b,
        x509_crt_format fmt) {
    _impl->set_x509_trust(b, fmt);
}

void tls::certificate_credentials::set_x509_crl(const blob& b,
        x509_crt_format fmt) {
    _impl->set_x509_crl(b, fmt);

}
void tls::certificate_credentials::set_x509_key(const blob& cert,
        const blob& key, x509_crt_format fmt) {
    _impl->set_x509_key(cert, key, fmt);
}

void tls::certificate_credentials::set_simple_pkcs12(const blob& b,
        x509_crt_format fmt, const sstring& password) {
    _impl->set_simple_pkcs12(b, fmt, password);
}

future<> tls::certificate_credentials::set_system_trust() {
    return _impl->set_system_trust();
}

void tls::certificate_credentials::set_priority_string(const sstring& prio) {
    _impl->set_priority_string(prio);
}

void tls::certificate_credentials::set_dn_verification_callback(dn_callback cb) {
    _impl->set_dn_verification_callback(std::move(cb));
}

std::optional<std::vector<cert_info>> tls::certificate_credentials::get_cert_info() const noexcept {
    if (_impl == nullptr) {
        return std::nullopt;
    }

    try {
        auto result = _impl->get_x509_info();
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<cert_info>> tls::certificate_credentials::get_trust_list_info() const noexcept {
    if (_impl == nullptr) {
        return std::nullopt;
    }

    try {
        auto result = _impl->get_x509_trust_list_info();
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

void tls::certificate_credentials::enable_load_system_trust() {}

void tls::certificate_credentials::set_client_auth(client_auth ca) {
    _impl->set_client_auth(ca);
}

tls::server_credentials::server_credentials()
    : server_credentials(dh_params{})
{}

tls::server_credentials::server_credentials(shared_ptr<dh_params> dh)
    : server_credentials(*dh)
{}

tls::server_credentials::server_credentials(const dh_params& dh) {
    _impl->dh_params(dh);
}

tls::server_credentials::server_credentials(server_credentials&&) noexcept = default;
tls::server_credentials& tls::server_credentials::operator=(
        server_credentials&&) noexcept = default;

void tls::server_credentials::set_client_auth(client_auth ca) {
    _impl->set_client_auth(ca);
}


} // namespace seastar
