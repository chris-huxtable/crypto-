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


module Crypto::AES

	private module Mode

		macro construct_factories()

			alias IV = Cipher::IV

			def self.encryptor(key : Bytes, iv : Bytes|IV = IV::Random) : Cipher::Encryptor
				return Cipher.new(key, iv).encryptor
			end

			def self.decryptor(key : Bytes, iv : Bytes|IV = IV::Prefix) : Cipher::Decryptor
				return Cipher.new(key, iv).decryptor
			end

		end

	end

	module GCM

		alias IV = Cipher::IV

		def self.encryptor(key : Bytes, iv : Bytes|IV = IV::Random, tag : Bytes? = nil) : Cipher::Encryptor
			return Cipher.new(key, iv, tag).encryptor
		end

		def self.decryptor(key : Bytes, iv : Bytes|IV = IV::Prefix, tag : Bytes? = nil) : Cipher::Decryptor
			return Cipher.new(key, iv, tag).decryptor
		end

		def self.iv_size() : Int32
			return Cipher::BYTES_96
		end

		private class Cipher < Crypto::AES::Cipher

		def initialize(key : Bytes, iv : Bytes|IV, tag : Bytes?)
			super(key, iv)
			@cipher.tag = tag if ( tag )
		end

			def cipher_string(key_size : Int) : String
				return case key_size
					when BYTES_256 then "aes-256-gcm"
					when BYTES_192 then "aes-192-gcm"
					when BYTES_128 then "aes-128-gcm"
					else raise "Invalid key size - expected: 256, 192, or 128; was: #{key_size*8}"
				end
			end

		end
	end

	{% for mode in { "ofb", "cfb", "ctr", "cbc" } %} # TODO: cbc

		module {{ mode.upcase.id }}

			Mode.construct_factories()

			def self.iv_size() : Int32
				return Cipher::BYTES_128
			end

			private class Cipher < Crypto::AES::Cipher

				def cipher_string(key_size : Int) : String
					return case key_size
						when BYTES_256 then "aes-256-{{ mode.id }}"
						when BYTES_192 then "aes-192-{{ mode.id }}"
						when BYTES_128 then "aes-128-{{ mode.id }}"
						else raise "Invalid key size - expected: 256, 192, or 128; was: #{key_size*8}"
					end
				end

			end
		end

	{% end %}

	module XTS

		Mode.construct_factories()

		def self.iv_size() : Int32
			return Cipher::BYTES_128
		end

		def key_sizes()
			return {BYTES_512, BYTES_384, BYTES_256}
		end

		private class Cipher < Crypto::AES::Cipher

			def cipher_string(key_size : Int) : String
				return case key_size
					when BYTES_512 then "aes-256-xts"
					when BYTES_384 then "aes-192-xts"
					when BYTES_256 then "aes-128-xts"
					else raise "Invalid key size - expected: 512, 384, or 256; was: #{key_size*8}"
				end
			end

		end
	end

	module ECB

		alias IV = Cipher::IV

		def self.encryptor(key : Bytes) : Cipher::Encryptor
			return Cipher.new(key, IV::Zero).encryptor
		end

		def self.decryptor(key : Bytes) : Cipher::Decryptor
			return Cipher.new(key, IV::Zero).decryptor
		end

		def self.iv_size() : Int32
			return 0
		end

		private class Cipher < Crypto::AES::Cipher

			def cipher_string(key_size : Int) : String
				return case key_size
					when BYTES_256 then "aes-256-ecb"
					when BYTES_192 then "aes-192-ecb"
					when BYTES_128 then "aes-128-ecb"
					else raise "Invalid key size - expected: 256, 192, or 128; was: #{key_size*8}"
				end
			end

		end
	end

end
