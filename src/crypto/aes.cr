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

	abstract class Cipher < Crypto::Cipher

		BYTES_512 = 64 # 512/8
		BYTES_384 = 48 # 384/8
		BYTES_256 = 32 # 256/8
		BYTES_192 = 24 # 192/8
		BYTES_128 = 16 # 128/8
		BYTES_96  = 12 # 96/8

		enum IV
			Random
			Zero
		end


		# MARK: - Initializers

		def initialize(key : Bytes, iv : Bytes|IV)
			check_key_size(key)

			@cipher = OpenSSL::Cipher.new(cipher_string(key.size))
			@cipher.key = key

			case iv
				when IV::Random then iv = Random::Secure.random_bytes(@cipher.iv_len)
				when IV::Zero   then iv = nil
			end

			raise "Bad IV" if ( iv.is_a?(IV) )

			if ( iv )
				check_iv_size(iv, @cipher.iv_len)
				@iv = iv
				@cipher.iv = iv
			end
		end


		# MARK: - Properties

		getter(iv : Bytes?)


		# MARK: - Mutators

		def encrypt(bytes : Bytes) : Bytes
			return @cipher.update(bytes)
		end

		def decrypt(bytes : Bytes) : Bytes
			return @cipher.update(bytes)
		end


		# MARK - Utilities

		private def check_key_size(key : Bytes) : Nil
			return if ( key_sizes.includes?(key.size) )
			raise "Invalid key size - expected: 256, 192, or 128; was: #{key.size*8}"
		end

		private def check_iv_size(iv : Bytes|IV?, size : Int32) : Nil
			return if ( iv.nil? )
			return if ( !iv.is_a?(Bytes) )
			return if ( iv.size == size )
			raise "Invalid initialization vector size - expected: #{size*8}; was: #{iv.size*8}"
		end

		def key_sizes()
			return {BYTES_256, BYTES_192, BYTES_128}
		end

		def iv_size() : Int32
			return @cipher.iv_len
		end

		def self.iv_size() : Int32
			raise "Must implement self.iv_size in subclass."
		end

		private abstract def cipher_string(key_size : Int) : String

	end

end

require "./aes/*"
