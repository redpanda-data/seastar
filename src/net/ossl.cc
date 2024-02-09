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

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;

/// TODO: Implement the DH params impl struct
///
class tls::dh_params::impl {
public:
    impl(level) {}
    impl(const blob&, x509_crt_format){}

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

}
