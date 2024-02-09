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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#ifdef SEASTAR_MODULE
module seastar;
#else
#include <seastar/net/tls.hh>
#include <seastar/core/sstring.hh>
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

class ossl_error : public std::system_error {
public:
    ossl_error() : std::system_error(0, tls::error_category(), build_error()) {}

    ossl_error(const sstring& msg)
      : std::system_error(0, tls::error_category(), format("{}: {}", msg, build_error())) {}

    ossl_error(int ec, const sstring& msg)
      : std::system_error(ec, tls::error_category(), format("{}: {}", msg, build_error())) {}

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

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;

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

    static std::shared_ptr<EVP_PKEY> make_evp_pkey(level l) {
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
        return std::shared_ptr<EVP_PKEY>(pkey, [](EVP_PKEY * ptr){
            EVP_PKEY_free(ptr);
        });
    }

    impl(level l) : _pkey(make_evp_pkey(l)) {}

    impl(const blob& pkcs3, x509_crt_format fmt)
        : _pkey([&] {
            bio_ptr key_bio(BIO_new_mem_buf(pkcs3.begin(), pkcs3.size()));
            EVP_PKEY* pkey_temp = EVP_PKEY_new();
            if(fmt == x509_crt_format::PEM) {
                if (nullptr == PEM_read_bio_Parameters(key_bio.get(), &pkey_temp)) {
                    EVP_PKEY_free(pkey_temp);
                    throw ossl_error();
                }
            } else if (fmt == x509_crt_format::DER) {
                if(nullptr == d2i_KeyParams_bio(EVP_PKEY_DH, &pkey_temp, key_bio.get())){
                    EVP_PKEY_free(pkey_temp);
                    throw ossl_error();
                }
            } else {
                throw std::invalid_argument("Unknown x509_crt_format selected");
            }
            return std::shared_ptr<EVP_PKEY>(pkey_temp, [](auto ptr){
                EVP_PKEY_free(ptr);
            });
        }())
    {}

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    std::shared_ptr<EVP_PKEY> _pkey;
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

}
