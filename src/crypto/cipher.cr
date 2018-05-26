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

require "openssl/cipher"
require "../openssl/*"

abstract class Crypto::Cipher

	# MARK: - Factories

	def self.encryptor(*args, **options) : Encryptor
		return new(*args, **options).encryptor()
	end

	def self.decryptor(*args, **options) : Decryptor
		return new(*args, **options).decryptor()
	end


	# MARK: - Specialization

	def encryptor() : Encryptor
		return Encryptor.new(self)
	end

	def decryptor() : Decryptor
		return Decryptor.new(self)
	end


	# MARK: - Mutators

	abstract def encrypt(bytes : Bytes) : Bytes
	abstract def decrypt(bytes : Bytes) : Bytes


	# MARK - Utility Classes

	class Decryptor

		def initialize(@cipher : Crypto::Cipher); end

		delegate(decrypt, to: @cipher)

	end

	class Encryptor

		def initialize(@cipher : Crypto::Cipher); end

		delegate(encrypt, to: @cipher)

		def encrypt(string : String, encoding : String = "UTF-8", invalid : Symbol? = nil) : Bytes
			return encrypt(string.encode(encoding, invalid))
		end

	end

end
