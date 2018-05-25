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

private def check_openssl(key, iv, data, algo) : String
	args = { "enc", "-e", "-base64", "-nosalt", "-"+algo, "-iv", iv.hexstring, "-K", key.hexstring }

	return Process.run(OPENSSL, args, input: IO::Memory.new(data)) { |proc|
		proc.output.gets_to_end.chomp
	}
end


{% for name in { "gcm", "ofb", "cfb", "ctr" } %}

	private def test_{{ name.id }}(key_size, key, iv, data)

		key		= key.ljust((key_size/8).to_i, '\0').encode("UTF-8")
		{% if name == "gcm" %}\
			iv		= iv.ljust(12, '\0').encode("UTF-8")
		{% else %}\
			iv		= iv.ljust(16, '\0').encode("UTF-8")
		{% end %}\

		encryptor = Crypto::AES::{{ name.upcase.id }}.encryptor(key, iv)
		decryptor = Crypto::AES::{{ name.upcase.id }}.decryptor(key, iv)

		encrypted = encryptor.encrypt(data)
		decrypted = decryptor.decrypt(encrypted)

		decrypted.size.should_not eq(0)
		data.should eq(String.new(decrypted))
		Base64.strict_encode(encrypted).should eq(check_openssl(key, iv, data,  "aes-#{key_size}-{{ name.id }}"))

	end

	describe Crypto::AES::{{ name.upcase.id }} do

		it "works" do
			test_{{ name.id }}(256, "foo", "bar", "foobardata")
			test_{{ name.id }}(192, "foo", "bar", "foobardata")
			test_{{ name.id }}(128, "foo", "bar", "foobardata")
		end

	end

{% end %}