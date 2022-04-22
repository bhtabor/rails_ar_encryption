# Rails ActiveRecord encryption for python

Rails 7 introduced a new option in ActiveRecord to encrypt data.

This library aims at decrypting the data with a simple interface.

## Usage

1. Find your credentials `primary_key` and `key_derivation_salt` (those generated by Rails `bin/rails db:encryption:init` - see RoR docs linked below)
1. Add the package `pip install git+ssh://git@github.com/digitalepidemiologylab/rails_ar_encryption.git`
1. Use it

```
from rails_ar_encryption import derive_key, decrypt

# step 1 - derive the encryption key
key = derive_key(primary_key, key_derivation_salt)

# step 2 - decrypt message (message is the full payload generated by Rails)
clear_text = decrypt(message, key)
```

Have a look at a working [example](example.py).

## Notes

* [Rails active record encryption](https://edgeguides.rubyonrails.org/active_record_encryption.html)
