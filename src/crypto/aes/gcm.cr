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

module Crypto::AES::GCM

	BYTES_256 = 32 # 256/8
	BYTES_192 = 24 # 192/8
	BYTES_128 = 16 # 128/8


	# MARK: - Constructors

	def self.encrypt(key : Bytes, init_vector : Bytes, &block : GCM -> Nil)
		encryptor = Encryptor.new(key, init_vector)
		yield(encryptor)

		encryptor.cleanup
		return nil
	end

	def self.decrypt(key : Bytes, init_vector : Bytes, &block : GCM -> Nil)
		decryptor = Decryptor.new(key, init_vector)
		yield(decryptor)

		decryptor.cleanup
		return nil
	end

	class Encryptor < Crypto::Encryptor

		def initialize(key : Bytes, init_vector : Bytes)
			check_key_size(key)
			super(key, init_vector)

			@cipher OpenSSL::Cipher.new(AES::GCM.cipher_string(@key_bytes))
		end


		# MARK: - Mutators

		def update(bytes : Bytes) : Bytes

		end

	end

	class Decryptor < Crypto::Decryptor

		def initialize(key : Bytes, init_vector : Bytes)
			check_key_size(key)
			super(key, init_vector)

			@cipher OpenSSL::Cipher.new(AES::GCM.cipher_string(@key_bytes))
		end

		# MARK: - Mutators

		def update(bytes : Bytes) : Bytes

		end

	end


	# MARK: - Utilities

	private def self.check_key_size(key : Bytes)
		key = key.size
		return if ( key == BYTES_256 || key == BYTES_192 || key == BYTES_128 )
		raise "Invalid key size - expected: 256, 192, or 128; was: #{@key_size}"
	end

	private def self.cipher_string(key_bytes : UInt32) : String
		return case key_bytes
			when BYTES_256 then "aes-256-gcm"
			when BYTES_192 then "aes-192-gcm"
			when BYTES_128 then "aes-128-gcm"
			else raise "Invalid key size - expected: 256, 192, or 128; was: #{key.size}"
		end
	end

end