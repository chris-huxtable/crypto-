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

require "../../src/crypto/aes"
require "../spec_helper"

private OPENSSL = "/usr/bin/openssl"

private def check_openssl(algo : String, data : String, key : Bytes, iv : Bytes? = nil) : String
	args = if ( iv )
		{ "enc", "-e", "-base64", "-nosalt", "-"+algo, "-K", key.hexstring, "-iv", iv.hexstring }
	else
		{ "enc", "-e", "-base64", "-nosalt", "-"+algo, "-K", key.hexstring }
	end

	return Process.run(OPENSSL, args, input: IO::Memory.new(data)) { |proc|
		next proc.output.gets_to_end.chomp
	}
end

private def check_correct(algo, key_size, key, iv, data, encrypted, decrypted)
	base64 = Base64.strict_encode(encrypted)
	check64 = check_openssl(algo, data, key, iv)

	decrypted.size.should be > 0
	data.should eq(String.new(decrypted))

	base64.should eq(check64)
end

{% for mode in { "gcm", "ofb", "cfb", "ctr", "ecb", "cbc", "xts" } %}#

	private def test_{{ mode.id }}(key_size : Int, data : String, key : String, iv : String)
		key = key.ljust((key_size/8).to_i, '\0').encode("UTF-8")
		iv = iv.ljust(Crypto::AES::{{ mode.upcase.id }}.iv_size, '\0').encode("UTF-8")

		{% if mode == "ecb" %}
			encryptor = Crypto::AES::ECB.encryptor(key)
			decryptor = Crypto::AES::ECB.decryptor(key)
		{% else %}
			encryptor = Crypto::AES::{{ mode.upcase.id }}.encryptor(key, iv)
			decryptor = Crypto::AES::{{ mode.upcase.id }}.decryptor(key, iv)
		{% end %}

		encrypted = encryptor.encrypt(data)
		decrypted = decryptor.decrypt(encrypted)

		check_correct("aes-#{key_size}-{{ mode.id }}", key_size, key, iv, data, encrypted, decrypted)
	end

	describe Crypto::AES::{{ mode.upcase.id }} do

		it "works" do
			test_{{ mode.id }}(256, "foobardata", "foo", "bar")
			test_{{ mode.id }}(192, "foobardata", "foo", "bar")
			test_{{ mode.id }}(128, "foobardata", "foo", "bar")

			#test_{{ mode.id }}(256, "foobardata", "foo")
			#test_{{ mode.id }}(192, "foobardata", "foo")
			#test_{{ mode.id }}(128, "foobardata", "foo")
		end

	end

{% end %}