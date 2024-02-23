Schnorr's digital signture algorithm implemented in various languages, using language idioms where suited

Intended to showcase language features, not to provide cryptographic security

The main implementation is in [Elixir](dsa.ex)

If a language has a built-in library for hashing, prng or generating primes then it is used
Otherwise openssl is used via a system command
