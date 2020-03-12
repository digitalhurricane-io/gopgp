Light wrapper around proton mail's crypto library https://github.com/ProtonMail/gopenpgp

Provides pgp encryption, decryption, and key generation functions.

Installation with go module:

go get github.com/digitalhurricane-io/gopgp

Add the following to your go.mod
replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20191122234321-e77a1f03baa0



Exports the following functions:

/*
Encrypt message with partner public key. Sign with own private key.
*/

func Encrypt(data []byte, publicKey string, signingPrivateKey string) ([]byte, error)

/*
Decrypt message with own private key. Verify with partner public key.
*/

func Decrypt(data []byte, privateKey string, verifyPublicKey string) ([]byte, error)

/*
Generates public and private pgp keys in standard string format (armored)
*/

func GenerateKeys(name, email string) (publicKey, privateKey string, err error)

See the test file for examples.