# crypto-plus.cr

**Work In Progress**

Adds new crypto features to crystal. Currently planned:

Algorithems:
- AES GCM 128/192/256
- AES OFB 128/192/256
- AES CFB 128/192/256
- AES CTR 128/192/256
- AES CBC 128/192/256 *not yet supported*
- AES XTS 128/192/256 *not yet supported*
- AES ECB 128/192/256 *not yet supported*

Key Stretching
- bcrypt *not yet supported*
- PBKDF2 *not yet supported*

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crypto+:
    github: chris-huxtable/crypto-plus.cr
```


## Usage

```crystal
require "crypto+"
```


## Contributing

1. Fork it ( https://github.com/chris-huxtable/crypto-plus.cr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request


## Contributors

- [Chris Huxtable](https://github.com/chris-huxtable) - creator, maintainer
