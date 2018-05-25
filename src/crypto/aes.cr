# Copyright (c) 2018 Christian Huxtable <chris@huxtable.ca>.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

require "./cipher"


module Crypto::AES

	{% for name in { "gcm", "ofb", "cfb", "ctr" } %} # TODO: cbc, xts, ecb

		module {{ name.upcase.id }}

			def self.encryptor(key : Bytes? = nil, iv : Bytes? = nil) : Cipher::Encryptor
				return Cipher.encryptor(key, iv)
			end

			def self.decryptor(key : Bytes? = nil, iv : Bytes? = nil) : Cipher::Decryptor
				return Cipher.decryptor(key, iv)
			end

			class Cipher < Crypto::OpenSSLCipher

				private def check_key_size(key : Bytes) : Nil
					return if ( {BYTES_256, BYTES_192, BYTES_128}.includes?(key.size) )
					raise "Invalid key size - expected: 256, 192, or 128; was: #{key.size*8}"
				end

				private def cipher_string(key_size : Int) : String
					return case key_size
						when BYTES_256 then "aes-256-{{ name.id }}"
						when BYTES_192 then "aes-192-{{ name.id }}"
						when BYTES_128 then "aes-128-{{ name.id }}"
						else raise "Invalid key size - expected: 256, 192, or 128; was: #{key_size*8}"
					end
				end

			end
		end

	{% end %}
end