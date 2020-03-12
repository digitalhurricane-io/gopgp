package gopgp

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"log"
)


/*
Encrypt message with partner public key. Sign with own private key.
*/
func Encrypt(data []byte, publicKey string, signingPrivateKey string) ([]byte, error) {
	var binMessage = crypto.NewPlainMessage(data)

	publicKeyRing, err := keyRingFromArmored(publicKey)
	if err != nil {
		return []byte{}, err
	}

	signingKeyRing, err := keyRingFromArmored(signingPrivateKey)
	if err != nil {
		return []byte{}, err
	}

	pgpMessage, err := publicKeyRing.Encrypt(binMessage, signingKeyRing)
	if err != nil {
		return []byte{}, err
	}

	return pgpMessage.Data, nil
}

/*
Decrypt message with own private key. Verify with partner public key.
*/
func Decrypt(data []byte, privateKey string, verifyPublicKey string) ([]byte, error) {

	verifyKeyRing, err := keyRingFromArmored(verifyPublicKey)
	if err != nil {
		return []byte{}, err
	}

	privateKeyRing, err := keyRingFromArmored(privateKey)
	if err != nil {
		return []byte{}, err
	}

	var pgpMessage = crypto.NewPGPMessage(data)

	decryptedMessage, err := privateKeyRing.Decrypt(pgpMessage, verifyKeyRing, crypto.GetUnixTime())
	if err != nil {
		return []byte{}, err
	}

	privateKeyRing.ClearPrivateParams()

	//log.Println("decryptedMessage: ", decryptedMessage.GetString())
	return decryptedMessage.Data, err
}

/*
Takes a standard pgp key as a string and returns a KeyRing pointer
*/
func keyRingFromArmored(key string) (*crypto.KeyRing, error) {
	keyObj, err := crypto.NewKeyFromArmored(key)
	if err != nil {
		return nil, err
	}

	keyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return nil, err
	}

	return keyRing, nil
}

/*
Generates public and private pgp keys in standard string format (armored)
*/
func GenerateKeys(name, email string) (publicKey, privateKey string, err error) {

	ecKey, err := crypto.GenerateKey(name, email, "x25519", 0)
	if err != nil {
		log.Println(err)
		return
	}

	publicKey, err = ecKey.GetArmoredPublicKey()
	if err != nil {
		log.Println(err)
		return
	}

	privateKey, err = ecKey.Armor()
	if err != nil {
		log.Println(err)
		return
	}

	return
}

