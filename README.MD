# Easy pgp encryption with go

Light wrapper around proton mail's crypto library https://github.com/ProtonMail/gopenpgp

### Installation:

```go get github.com/digitalhurricane-io/gopgp```

Add the following to your go.mod

```replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20191122234321-e77a1f03baa0```



### Exports the following functions:

Encrypt message with partner public key. Sign with own private key.

```go
func Encrypt(data []byte, publicKey string, signingPrivateKey string) ([]byte, error)
```

Decrypt message with own private key. Verify with partner public key.

```go
func Decrypt(data []byte, privateKey string, verifyPublicKey string) ([]byte, error)
```

Generates public and private pgp keys in standard string format (armored)

```go
func GenerateKeys(name, email string) (publicKey, privateKey string, err error)
```

See the test file for examples.

### Full Example from [pgp_test.go](pgp_test.go)
```go	
message := "My Test Message"

partnerPublicKey, partnerPrivateKey, err := GenerateKeys("Alice", "alice@example.com")
if err != nil {
    t.Error(err)
}

myPublicKey, myPrivateKey , err := GenerateKeys("Bob", "bob@example.com")
if err != nil {
    t.Error(err)
}

// encrypting message with partners public key to send him message. signing with my private key.
encrypted, err := Encrypt([]byte(message), partnerPublicKey, myPrivateKey)
if err != nil {
    t.Error(err)
}

// partner is decrypting the message with his private key and verifying the signature with my public key
decrypted, err := Decrypt(encrypted, partnerPrivateKey, myPublicKey)
if err != nil {
    t.Error(err)
}

if string(decrypted) != message {
    t.Error(fmt.Errorf("Original message and decrypted message did not match"))
}
```