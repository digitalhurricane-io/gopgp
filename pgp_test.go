package gopgp

import (
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
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
}