# Rabin Encryption and Digital Signing Implementation on Ruby

## Rabin Encryption

Just use ruby rabin_encryption.rb to get started.

## Rabin Signing

You can see usage with ruby rabin_signing.rb.

## Corrupter

To see how it behaves on corrupted or modified files, you can use corrupter.rb to corrupt your dummy file and try to verify. Usage same as rabin_encryption.rb.

PS: Beware, corrupter.rb has issues with Ruby version 2.2

## Note

This project uses Ruby's OpenSSL,Digest, Prime and SecureRandom libraries.

Only tested on Linux(Arch Linux and Solus Linux) Ruby Version 2.4.1.
