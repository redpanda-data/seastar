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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/safestack.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#ifdef SEASTAR_MODULE
module seastar;
#else
#include "net/tls-impl.hh"
#include <seastar/net/tls.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/stack.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/with_timeout.hh>
#include <seastar/util/later.hh>
#include <seastar/util/defer.hh>
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

template<typename T>
sstring asn1_str_to_str(T* asn1) {
    const auto len = ASN1_STRING_length(asn1);
    return sstring((char*)ASN1_STRING_get0_data(asn1), len);
};

static cert_info::bytes extract_x509_serial(X509* cert) {
    constexpr size_t serial_max = 160;
    const ASN1_INTEGER *serial_no = X509_get_serialNumber(cert);
    const size_t serial_size = std::min(serial_max, (size_t)serial_no->length);
    cert_info::bytes serial(cert_info::bytes::initialized_later{}, serial_size);
    std::memcpy(serial.begin(), reinterpret_cast<cert_info::bytes::value_type*>(serial_no->data), serial_size);
    return serial;
}

static time_t extract_x509_expiry(X509* cert) {
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    if (not_after) {
        struct tm tm_struct;
        memset(&tm_struct, 0, sizeof(struct tm));
        ASN1_TIME_to_tm(not_after, &tm_struct);
        return mktime(&tm_struct);
    }
    return -1;
}

template<typename T, auto fn>
struct ssl_deleter {
    void operator()(T* ptr) { fn(ptr); }
};

// Must define this method as sk_X509_pop_free is a macro
void X509_pop_free(STACK_OF(X509)* ca) {
    sk_X509_pop_free(ca, X509_free);
}

void GENERAL_NAME_pop_free(GENERAL_NAMES* gns) {
    sk_GENERAL_NAME_pop_free(gns, GENERAL_NAME_free);
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
using x509_extension_ptr = ssl_handle<X509_EXTENSION, X509_EXTENSION_free>;
using general_names_ptr = ssl_handle<GENERAL_NAMES, GENERAL_NAME_pop_free>;
using pkcs12 = ssl_handle<PKCS12, PKCS12_free>;
using ssl_ctx_ptr = ssl_handle<SSL_CTX, SSL_CTX_free>;
using ssl_ptr = ssl_handle<SSL, SSL_free>;

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
    struct certkey_pair {
        x509_ptr cert;
        evp_pkey_ptr key;
        explicit operator bool() const noexcept {
            return cert != nullptr && key != nullptr;
        }
    };

    static const int credential_store_idx = 0;

public:
    // This callback is designed to intercept the verification process and to implement an additional
    // check, returning 0 or -1 will force verification to fail.
    //
    // However it has been implemented in this case soley to cache the last observed certificate so
    // that it may be inspected during the session::verify() method, if desired.
    //
    static int verify_callback(int preverify_ok, X509_STORE_CTX* store_ctx) {
        // Grab the 'this' pointer from the stores generic data cache, it should always exist
        auto store = X509_STORE_CTX_get0_store(store_ctx);
        auto credential_impl = static_cast<impl*>(X509_STORE_get_ex_data(store, credential_store_idx));
        assert(credential_impl != nullptr);
        // Store a pointer to the current connection certificate within the impl instance
        auto cert = X509_STORE_CTX_get_current_cert(store_ctx);
        X509_up_ref(cert);
        credential_impl->_last_cert = x509_ptr(cert);
        return preverify_ok;
    }

    impl() : _creds([] {
        auto store = X509_STORE_new();
        if(store == nullptr) {
            throw std::bad_alloc();
        }
        X509_STORE_set_verify_cb(store, verify_callback);
        return store;
    }()) {
        // The static verify_callback above will use the stored pointer to 'this' to store the last
        // observed x509 certificate
        assert(X509_STORE_set_ex_data(_creds.get(), credential_store_idx, this) == 1);
    }

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
        _cert_and_key = certkey_pair{.cert = std::move(x509_cert), .key = std::move(pkey)};
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
            _cert_and_key = certkey_pair{.cert = x509_ptr(cert), .key = evp_pkey_ptr(pkey)};

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
        if (_cert_and_key.cert) {
            return {
                cert_info{
                    .serial = extract_x509_serial(_cert_and_key.cert.get()),
                    .expiry = extract_x509_expiry(_cert_and_key.cert.get())}
            };
        }
        return {};
    }

    std::vector<cert_info> get_x509_trust_list_info() const {
        std::vector<cert_info> cert_infos;
        STACK_OF(X509_OBJECT) *chain = X509_STORE_get0_objects(_creds.get());
        auto num_elements = sk_X509_OBJECT_num(chain);
        for (auto i=0; i < num_elements; i++) {
            auto object = sk_X509_OBJECT_value(chain, i);
            auto type = X509_OBJECT_get_type(object);
            if (type == X509_LU_X509) {
                auto cert = X509_OBJECT_get0_X509(object);
                cert_infos.push_back(cert_info{
                        .serial = extract_x509_serial(cert),
                        .expiry = extract_x509_expiry(cert)});
            }
            num_elements -= 1;
        }
        return cert_infos;
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    void set_priority_string(const sstring& priority) {
        _priority = priority;
    }

    void set_dn_verification_callback(dn_callback cb) {
        _dn_callback = std::move(cb);
    }

    const sstring& get_priority_string() const { return _priority; }

    // Returns the certificate of last attempted verification attempt, if there was no attempt,
    // this will not be updated and will remain stale
    const x509_ptr& get_last_cert() const { return _last_cert; }

    operator X509_STORE*() const { return _creds.get(); }

    const certkey_pair& get_certkey_pair() const {
        return _cert_and_key;
    }

    future<> set_system_trust() {
        return make_ready_future<>();
    }

private:
    friend class credentials_builder;
    friend class session;

    x509_ptr _last_cert;
    x509_store_ptr _creds;

    certkey_pair _cert_and_key;
    std::shared_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    dn_callback _dn_callback;
    sstring _priority;
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

namespace tls {

/**
 * Session wraps gnutls session, and is the
 * actual conduit for an TLS/SSL data flow.
 *
 * We use a connected_socket and its sink/source
 * for IO. Note that we need to keep ownership
 * of these, since we handle handshake etc.
 *
 * The implmentation below relies on OpenSSL, for the gnutls implementation
 * see tls.cc and the CMake option 'Seastar_WITH_OSSL'
 */
class session : public enable_shared_from_this<session>, public session_impl {
public:
    typedef temporary_buffer<char> buf_type;
    typedef net::fragment* frag_iter;

    session(session_type t, shared_ptr<tls::certificate_credentials> creds,
            std::unique_ptr<net::connected_socket_impl> sock, tls_options options = {})
            : _type(t), _sock(std::move(sock)), _creds(creds->_impl),
                   _in(_sock->source()), _out(_sock->sink()),
                   _in_sem(1), _out_sem(1),  _options(options),
                   _in_bio(BIO_new(BIO_s_mem())) , _out_bio(BIO_new(BIO_s_mem())),
                   _ctx(make_ssl_context()),
                   _ssl(SSL_new(_ctx.get())) {
        if (!_ssl){
            BIO_free(_in_bio);
            BIO_free(_out_bio);
            throw ossl_error("Failed to initialize ssl object");
        }
        if (t == session_type::SERVER) {
            SSL_set_accept_state(_ssl.get());
        } else {
            if (!_options.server_name.empty()){
                SSL_set_tlsext_host_name(_ssl.get(), _options.server_name.c_str());
            }
            SSL_set_connect_state(_ssl.get());
        }
        // SSL_set_bio transfers ownership of the read and write bios to the SSL instance
        SSL_set_bio(_ssl.get(), _in_bio, _out_bio);
    }

    session(session_type t, shared_ptr<certificate_credentials> creds,
            connected_socket sock,
            tls_options options = {})
            : session(t, std::move(creds), net::get_impl::get(std::move(sock)), options) {}

    // This method pulls encrypted data from the SSL context and writes
    // it to the underlying socket.
    future<> pull_encrypted_and_send(){
        auto msg = make_lw_shared<scattered_message<char>>();
        return do_until(
            [this] { return BIO_ctrl_pending(_out_bio) == 0; },
            [this, msg]{
                // TODO(rob) avoid magic numbers
                buf_type buf(4096);
                auto n = BIO_read(_out_bio, buf.get_write(), buf.size());
                if (n > 0){
                    buf.trim(n);
                    msg->append(std::move(buf));
                } else if (!BIO_should_retry(_out_bio)) {
                    _error = std::make_exception_ptr(ossl_error("Failed to read data from the BIO"));
                    return make_exception_future<>(_error);
                }
                return make_ready_future<>();
        }).then([this, msg](){
            if(msg->size() > 0){
                return _out.put(std::move(*msg).release());
            }
            return make_ready_future<>();
        });
    }

    // This method puts unencrypted data is written into the SSL context.
    // This data is later able to be retrieved in its encrypted form by reading
    // from the associated _out_bio
    future<> do_put(frag_iter i, frag_iter e) {
        return do_for_each(i, e, [this](net::fragment& f){
            auto ptr = f.base;
            auto size = f.size;
            size_t off = 0;
            // SSL_write isn't guaranteed to write entire fragments at a time
            // continue to write until all is consumed by openssl
            return repeat([this, ptr, size, off]() mutable {
                if(off == size) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                auto bytes_written = SSL_write(_ssl.get(), ptr + off, size - off);
                if(bytes_written <= 0){
                    const auto ec = SSL_get_error(_ssl.get(), bytes_written);
                    if (ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE) {
                        /// TODO(rob) handle this condition
                    }
                    _error = std::make_exception_ptr(ossl_error("Failed on call to SSL_write"));
                    return make_exception_future<stop_iteration>(_error);
                }
                off += bytes_written;
                /// Regardless of error, continue to send fragments
                return pull_encrypted_and_send().then([]{
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }

    future<> put(net::packet p) override {
        if (_error) {
            return make_exception_future<>(_error);
        }
        if (_shutdown) {
            return make_exception_future<>(std::system_error(EPIPE, std::system_category()));
        }
        if (!connected()) {
            return handshake().then([this, p = std::move(p)]() mutable {
               return put(std::move(p));
            });
        }

        // We want to make sure that we write to the underlying bio with as large
        // packets as possible. This is because eventually this translates to a
        // sendmsg syscall. Further it results in larger TLS records which makes
        // encryption/decryption faster. Hence to avoid cases where we would do
        // an extra syscall for something like a 100 bytes header we linearize the
        // packet if it's below the max TLS record size.
        // TODO(Rob): Avoid magic numbers
        if (p.nr_frags() > 1 && p.len() <= 16000) {
            p.linearize();
        }

        auto i = p.fragments().begin();
        auto e = p.fragments().end();
        return with_semaphore(_out_sem, 1, std::bind(&session::do_put, this, i, e)).finally([p = std::move(p)] {});
    }

    template<typename session_func, typename want_read_func>
    future<> do_handshake(session_func session_fn, want_read_func want_read_fn) {
        auto n = session_fn(_ssl.get());
        auto ssl_err = SSL_get_error(_ssl.get(), n);
        switch (ssl_err) {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_READ:
            return want_read_fn();
        case SSL_ERROR_WANT_WRITE:
            return wait_for_input();
        case SSL_ERROR_SSL:
        {
            // Catch-all for handshake errors
            auto ec = ERR_GET_REASON(ERR_get_error());
            switch (ec) {
            case SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE:
            case SSL_R_CERTIFICATE_VERIFY_FAILED:
            case SSL_R_NO_CERTIFICATES_RETURNED:
                verify(); // should throw
                [[fallthrough]];
            default:
                _error = std::make_exception_ptr(ossl_error("Failed to establish SSL handshake"));
                return make_exception_future<>(_error);
            }
        }
        default:
            _error = std::make_exception_ptr(ossl_error("Unhandled error code observed"));
            return make_exception_future<>(_error);
        }
        return make_ready_future<>();
    }

    future<> wait_for_input() {
        if (eof()) {
            return make_ready_future<>();
        }
        return _in.get().then([this](buf_type data) {
            if (data.empty()) {
                _eof = true;
                return make_ready_future<>();
            }
            // Write the received data to the "read bio".  This bio is consumed
            // by the SSL struct.  Think of this of writing encrypted data into
            // the SSL session
            auto buf = make_lw_shared<buf_type>(std::move(data));
            return do_until(
              [buf]{ return buf->empty(); },
              [this, buf]{
                  const auto n = BIO_write(_in_bio, buf->get(), buf->size());
                  if (n <= 0) {
                      _error = std::make_exception_ptr(ossl_error("Error while waiting for input"));
                      return make_exception_future<>(_error);
                  }
                  buf->trim_front(n);
                  return make_ready_future();
              }).finally([buf]{});
        });
    }

    future<buf_type> do_get() {
        // Check if there is encrypted data sitting in ssls internal buffers, otherwise wait
        // for data and use a
        auto f = make_ready_future<>();
        auto avail = BIO_ctrl_pending(_in_bio);
        if (avail == 0 && SSL_pending(_ssl.get()) == 0) {
            f = wait_for_input();
        }
        return f.then([this]() {
            if (eof()) {
                /// Connection has been closed by client
                return make_ready_future<buf_type>(buf_type());
            }
            const auto buf_size = 4096;
            buf_type buf(buf_size);
            // Read decrypted data from ssls internal buffers
            auto bytes_read = SSL_read(_ssl.get(), buf.get_write(), buf_size);
            if (bytes_read <= 0) {
                const auto ec = SSL_get_error(_ssl.get(), bytes_read);
                if (ec == SSL_ERROR_ZERO_RETURN) {
                    // Client has initiated shutdown by sending EOF
                    _eof = true;
                    close();
                    return make_ready_future<buf_type>(buf_type());
                } else if (ec == SSL_ERROR_WANT_READ) {
                    // Not enough data resides in the internal SSL buffers to merit a read, i.e.
                    // maybe a record doesn't exist in its entirety, therefore read more from input.
                    return do_get();
                }
                _error = std::make_exception_ptr(ossl_error(fmt::format("Error upon call to SSL_read: {}", ec)));
                return make_exception_future<buf_type>(_error);
            }
            buf.trim(bytes_read);
            return make_ready_future<buf_type>(std::move(buf));
        });
    }

    future<buf_type> get() override {
        if (_error) {
            return make_exception_future<temporary_buffer<char>>(_error);
        }
        if (_shutdown || eof()) {
            return make_ready_future<temporary_buffer<char>>(buf_type());
        }
        if (!connected()) {
            return handshake().then(std::bind(&session::get, this));
        }
        return with_semaphore(_in_sem, 1, std::bind(&session::do_get, this)).then([](temporary_buffer<char> buf) {
            // TODO(rob) - maybe re-handshake?
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        });
    }

    future<> do_shutdown() {
        if(_error || !connected() || eof()) {
            return make_ready_future();
        }
        auto res = SSL_shutdown(_ssl.get());
        if (res == 1){
            // Shutdown has completed successfully
            return make_ready_future<>();
        } else if (res == 0) {
            // Shutdown process is ongoing and has not yet completed, peer has not yet replied
            // 0 does not indicate error, calling SSL_get_error is undefined
            return yield().then([this]{
                return do_shutdown();
            });
        }
        // Shutdown was not successful, calling SSL_get_error will indicate why
        auto err = SSL_get_error(_ssl.get(), res);
        if (err == SSL_ERROR_WANT_READ) {
            auto f = make_ready_future();
            if (_type == session_type::CLIENT) {
                // Clients will be sending the close_notify message, and expecting SSL_ERROR_ZERO_RETURN
                // from the server, logic in wait_for_input will detect this and set _eof to true
                f = pull_encrypted_and_send();
            }
            return f.then([this]{
                return wait_for_input().then([this] {
                    return do_shutdown();
                });
            });
        }

        // Fatal error
        _error = std::make_exception_ptr(ossl_error("fatal error during ssl shutdown"));
        return make_exception_future<>(_error);
    }

    void verify() {
        // A success return code (0) does not signify if a cert was presented or not, that
        // must be explicitly queried via SSL_get_peer_certificate
        auto res = SSL_get_verify_result(_ssl.get());
        if (res != X509_V_OK) {
            sstring stat_str(X509_verify_cert_error_string(res));
            auto dn = extract_dn_information();
            if (dn) {
                std::stringstream ss;
                ss << stat_str;
                if (stat_str.back() != ' ') {
                    ss << ' ';
                }
                ss << "(Issuer=[" << dn->issuer << "], Subject=[" << dn->subject << "])";
                stat_str = ss.str();
            }
            throw verification_error(stat_str);
        } else if (SSL_get0_peer_certificate(_ssl.get()) == nullptr) {
            if (_type == session_type::SERVER && _creds->get_client_auth() == client_auth::REQUIRE) {
                throw verification_error("no certificate presented");
            }
            return;
        }

        if (_creds->_dn_callback) {
            auto dn = extract_dn_information();
            assert(dn.has_value());
            _creds->_dn_callback(_type, std::move(dn->subject), std::move(dn->issuer));
        }
    }

    bool eof() const {
        return _eof;
    }

    bool connected() const {
        return SSL_is_init_finished(_ssl.get());
    }

    // Identical (or almost) portion of implementation
    //
    future<> wait_for_eof() {
        if (!_options.wait_for_eof_on_shutdown) {
            return make_ready_future();
        }

        // read records until we get an eof alert
        // since this call could time out, we must not ac
        return with_semaphore(_in_sem, 1, [this] {
            if (_error || !connected()) {
                return make_ready_future();
            }
            return repeat([this] {
                if (eof()) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                return do_get().then([](auto) {
                   return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }


    future<> handshake() {
        // acquire both semaphores to sync both read & write
        return with_semaphore(_in_sem, 1, [this] {
            return with_semaphore(_out_sem, 1, [this] {
                if (connected()) {
                    return make_ready_future<>();
                }
                auto fn = (_type == session_type::SERVER) ?
                        std::bind(&session::server_handshake, this) :
                        std::bind(&session::client_handshake, this);
                return do_until(
                    [this]{ return connected(); },
                    [fn = std::move(fn)]{ return fn(); }
                ).then([this]{
                    if (_type == session_type::CLIENT || _creds->get_client_auth() != client_auth::NONE) {
                        verify();
                    }
                }).handle_exception([this](auto ep) {
                    if (!_error) {
                        _error = ep;
                    }
                    return make_exception_future<>(_error);
                });
            });
        });
    }

    future<> shutdown() {
        // first, make sure any pending write is done.
        // bye handshake is a flush operation, but this
        // allows us to not pay extra attention to output state
        //
        // we only send a simple "bye" alert packet. Then we
        // read from input until we see EOF. Any other reader
        // before us will get it instead of us, and mark _eof = true
        // in which case we will be no-op.
        return with_semaphore(_out_sem, 1,
                        std::bind(&session::do_shutdown, this)).then(
                        std::bind(&session::wait_for_eof, this)).finally([me = shared_from_this()] {});
        // note moved finally clause above. It is theorethically possible
        // that we could complete do_shutdown just before the close calls
        // below, get pre-empted, have "close()" finish, get freed, and
        // then call wait_for_eof on stale pointer.
    }
    void close() noexcept override {
        // only do once.
        if (!std::exchange(_shutdown, true)) {
            auto me = shared_from_this();
            // running in background. try to bye-handshake us nicely, but after 10s we forcefully close.
            (void)with_timeout(timer<>::clock::now() + std::chrono::seconds(10), shutdown()).finally([this] {
                _eof = true;
                try {
                    (void)_in.close().handle_exception([](std::exception_ptr) {}); // should wake any waiters
                } catch (...) {
                }
                try {
                    (void)_out.close().handle_exception([](std::exception_ptr) {});
                } catch (...) {
                }
                // make sure to wait for handshake attempt to leave semaphores. Must be in same order as
                // handshake aqcuire, because in worst case, we get here while a reader is attempting
                // re-handshake.
                return with_semaphore(_in_sem, 1, [this] {
                    return with_semaphore(_out_sem, 1, [] {});
                });
            }).then_wrapped([me = std::move(me)](future<> f) { // must keep object alive until here.
                f.ignore_ready_future();
            });
        }
    }
    // helper for sink
    future<> flush() noexcept override {
        return with_semaphore(_out_sem, 1, [this] {
            return _out.flush();
        });
    }

    seastar::net::connected_socket_impl & socket() const override {
        return *_sock;
    }

    future<std::optional<session_dn>> get_distinguished_name() override {
        using result_t = std::optional<session_dn>;
        if (_error) {
            return make_exception_future<result_t>(_error);
        }
        if (_shutdown) {
            return make_exception_future<result_t>(std::system_error(ENOTCONN, std::system_category()));
        }
        if (!connected()) {
            return handshake().then([this]() mutable {
               return get_distinguished_name();
            });
        }
        result_t dn = extract_dn_information();
        return make_ready_future<result_t>(std::move(dn));
    }

    future<std::vector<subject_alt_name>> get_alt_name_information(std::unordered_set<subject_alt_name_type> types) override {
        using result_t = std::vector<subject_alt_name>;

        if (_error) {
            return make_exception_future<result_t>(_error);
        }
        if (_shutdown) {
            return make_exception_future<result_t>(std::system_error(ENOTCONN, std::system_category()));
        }
        if (!connected()) {
            return handshake().then([this, types = std::move(types)]() mutable {
               return get_alt_name_information(std::move(types));
            });
        }

        const auto& peer_cert = get_peer_certificate();
        if (!peer_cert) {
            return make_ready_future<result_t>();
        }
        return make_ready_future<result_t>(do_get_alt_name_information(peer_cert, types));
    }

private:
    std::vector<subject_alt_name> do_get_alt_name_information(const x509_ptr &peer_cert,
                                                              const std::unordered_set<subject_alt_name_type> &types) const {
        int ext_idx = X509_get_ext_by_NID(peer_cert.get(), NID_subject_alt_name, -1);
        if (ext_idx < 0) {
            return {};
        }
        auto ext = x509_extension_ptr(X509_get_ext(peer_cert.get(), ext_idx));
        if (!ext) {
            return {};
        }
        auto names = general_names_ptr((GENERAL_NAMES*)X509V3_EXT_d2i(ext.get()));
        if (!names) {
            return {};
        }
        int num_names = sk_GENERAL_NAME_num(names.get());
        std::vector<subject_alt_name> alt_names;
        alt_names.reserve(num_names);

        for (auto i = 0; i < num_names; i++) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(names.get(), i);
            if (auto known_t = field_to_san_type(name)) {
                if (types.empty() || types.count(known_t->type)) {
                    alt_names.push_back(std::move(*known_t));
                }
            }
        }
        return alt_names;
    }

    std::optional<subject_alt_name> field_to_san_type(GENERAL_NAME* name) const {
        subject_alt_name san;
        switch(name->type) {
            case GEN_IPADD:
            {
                san.type = subject_alt_name_type::ipaddress;
                const auto* data = ASN1_STRING_get0_data(name->d.iPAddress);
                const auto size = ASN1_STRING_length(name->d.iPAddress);
                if (size == sizeof(::in_addr)) {
                    ::in_addr addr;
                    memcpy(&addr, data, size);
                    san.value = net::inet_address(addr);
                } else if (size == sizeof(::in6_addr)) {
                    ::in6_addr addr;
                    memcpy(&addr, data, size);
                    san.value = net::inet_address(addr);
                } else {
                    throw std::runtime_error(fmt::format("Unexpected size: {} for ipaddress alt name value", size));
                }
                break;
            }
            case GEN_EMAIL:
            {
                san.type = subject_alt_name_type::rfc822name;
                san.value = asn1_str_to_str(name->d.rfc822Name);
                break;
            }
            case GEN_URI:
            {
                san.type = subject_alt_name_type::uri;
                san.value = asn1_str_to_str(name->d.uniformResourceIdentifier);
                break;
            }
            case GEN_DNS:
            {
                san.type = subject_alt_name_type::dnsname;
                san.value = asn1_str_to_str(name->d.dNSName);
                break;
            }
            case GEN_OTHERNAME:
            {
                san.type = subject_alt_name_type::othername;
                san.value = asn1_str_to_str(name->d.dNSName);
                break;
            }
            case GEN_DIRNAME:
            {
                san.type = subject_alt_name_type::dn;
                auto dirname = get_ossl_string(name->d.directoryName);
                if (!dirname) {
                    throw std::runtime_error("Expected non null value for SAN dirname");
                }
                san.value = std::move(*dirname);
                break;
            }
            default:
                return std::nullopt;
        }
        return san;
    }

    const x509_ptr& get_peer_certificate() const {
        return _creds->get_last_cert();
    }

    std::optional<session_dn> extract_dn_information() const {
        const auto& peer_cert = get_peer_certificate();
        if (!peer_cert) {
            return std::nullopt;
        }
        auto subject = get_ossl_string(X509_get_subject_name(peer_cert.get()));
        auto issuer = get_ossl_string(X509_get_issuer_name(peer_cert.get()));
        if(!subject || !issuer) {
            throw ossl_error("error while extracting certificate DN strings");
        }
        return session_dn{.subject= std::move(*subject), .issuer = std::move(*issuer)};
    }

    ssl_ctx_ptr make_ssl_context(){
        auto ssl_ctx = ssl_ctx_ptr(SSL_CTX_new(TLS_method()));
        if (!ssl_ctx) {
            throw ossl_error("Failed to initialize SSL context");
        }

        const auto& ck_pair = _creds->get_certkey_pair();
        if (_type == session_type::SERVER) {
            if (!ck_pair) {
                throw ossl_error("Cannot start session without cert/key pair for server");
            }
            switch(_creds->get_client_auth()) {
                case client_auth::NONE:
                default:
                    SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
                    break;
                case client_auth::REQUEST:
                    SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);
                    break;
                case client_auth::REQUIRE:
                    SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
                    break;
            }
        }

        // Servers must supply both certificate and key, clients may optionally use these
        if (ck_pair) {
            if (!SSL_CTX_use_cert_and_key(ssl_ctx.get(), ck_pair.cert.get(), ck_pair.key.get(), nullptr, 1)) {
                throw ossl_error("Failed to load cert/key pair");
            }
        }
        // Increments the reference count of *_creds, now should have a total ref count of two, will be deallocated
        // when both OpenSSL and the certificate_manager call X509_STORE_free
        SSL_CTX_set1_cert_store(ssl_ctx.get(), *_creds);

        if (_creds->get_priority_string() != "") {
            if (SSL_CTX_set_cipher_list(ssl_ctx.get(), _creds->get_priority_string().c_str()) != 1) {
                throw ossl_error("Failed to set priority list");
            }
        }
        return ssl_ctx;
    }

    static std::optional<sstring> get_ossl_string(X509_NAME* name){
        if (auto name_str = X509_NAME_oneline(name, nullptr, 0)) {
            // sstring constructor may throw, to ensure deallocation of this OpenSSL string in
            // all cases, wrap the call to free() in a deferred_action
            auto done = defer([&name_str]() noexcept { OPENSSL_free(name_str); });
            sstring ossl_str(name_str);
            return ossl_str;
        }
        return std::nullopt;
    }

    future<> client_handshake() {
        return do_handshake(SSL_connect, [this]{
            return pull_encrypted_and_send().then([this]{
                return wait_for_input().then([this]{
                    if (eof()) {
                        return make_exception_future<>(std::runtime_error("EOF observed during handshake"));
                    }
                    return make_ready_future<>();
                });
            });
        });
    }

    future<> server_handshake() {
        return wait_for_input().then([this]{
            if (eof()) {
                return make_exception_future<>(std::runtime_error("EOF observed during handshake"));
            }
            return do_handshake(SSL_accept, std::bind(&session::pull_encrypted_and_send, this));
        });
    }

private:
    session_type _type;

    std::unique_ptr<net::connected_socket_impl> _sock;
    shared_ptr<tls::certificate_credentials::impl> _creds;
    data_source _in;
    data_sink _out;
    std::exception_ptr _error;

    bool _eof = false;
    // bool _maybe_load_system_trust = false;
    semaphore _in_sem, _out_sem;
    tls_options _options;

    bool _shutdown = false;
    buf_type _input;
    gate _read_gate;
    BIO* _in_bio;
    BIO* _out_bio;
    ssl_ctx_ptr _ctx;
    ssl_ptr _ssl;
};
} // namespace tls

future<connected_socket> tls::wrap_client(shared_ptr<certificate_credentials> cred, connected_socket&& s, sstring name) {
    tls_options options{.server_name = std::move(name)};
    return wrap_client(std::move(cred), std::move(s), std::move(options));
}

future<connected_socket> tls::wrap_client(shared_ptr<certificate_credentials> cred, connected_socket&& s, tls_options options) {
    session_ref sess(seastar::make_shared<session>(session_type::CLIENT, std::move(cred), std::move(s),  options));
    connected_socket sock(std::make_unique<tls_connected_socket_impl>(std::move(sess)));
    return make_ready_future<connected_socket>(std::move(sock));
}

future<connected_socket> tls::wrap_server(shared_ptr<server_credentials> cred, connected_socket&& s) {
    session_ref sess(seastar::make_shared<session>(session_type::SERVER, std::move(cred), std::move(s)));
    connected_socket sock(std::make_unique<tls_connected_socket_impl>(std::move(sess)));
    return make_ready_future<connected_socket>(std::move(sock));
}

} // namespace seastar

// TODO(rob) fix
const int seastar::tls::ERROR_UNKNOWN_COMPRESSION_ALGORITHM = 0;
const int seastar::tls::ERROR_UNKNOWN_CIPHER_TYPE = 1;
const int seastar::tls::ERROR_INVALID_SESSION = 2;
const int seastar::tls::ERROR_UNEXPECTED_HANDSHAKE_PACKET = 3;
const int seastar::tls::ERROR_UNKNOWN_CIPHER_SUITE = 4;
const int seastar::tls::ERROR_UNKNOWN_ALGORITHM = 5;
const int seastar::tls::ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM = 6;
const int seastar::tls::ERROR_SAFE_RENEGOTIATION_FAILED = 7;
const int seastar::tls::ERROR_UNSAFE_RENEGOTIATION_DENIED = 8;
const int seastar::tls::ERROR_UNKNOWN_SRP_USERNAME = 9;
const int seastar::tls::ERROR_PREMATURE_TERMINATION = 10;
