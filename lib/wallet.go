package lib

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

type HDWallet struct{}

const BIP_PATH = "m/44'/60'/0'/0/"

func (wallet *HDWallet) PrivateKeyToAddress(privateKeyHex string) (common.Address, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return common.Address{}, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}

func (wallet *HDWallet) GenerateAddressAndPrivateKey(seedPhrase string) (string, string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(seedPhrase, "Secret Passphrase")
	if err != nil {
		return "", "", err
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", "", err
	}

	publicKey := masterKey.PublicKey()
	if err != nil {
		return "", "", err
	}
	// childKey, err := publicKey.NewChildKey(0)
	// if err != nil {
	// 	return "", "", err
	// }
	childKey := publicKey
	ecdaPrivateKey, err := crypto.ToECDSA(childKey.Key)
	if err != nil {
		return "", "", err
	}
	ecdaPublicKey := ecdaPrivateKey.Public().(*ecdsa.PublicKey)
	privateKeyHex := fmt.Sprintf("%x", ecdaPrivateKey.D)
	publicKeyHex := fmt.Sprintf("%x", crypto.CompressPubkey(ecdaPublicKey))

	return publicKeyHex, privateKeyHex, nil
}

// GenerateRandomSeedPhrase generates a random valid HD wallet seed phrase.
func (wallet *HDWallet) GenerateRandomSeedPhrase() (string, error) {
	// Generate a new entropy (random 128 bits)
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}

	// Generate the mnemonic phrase from the entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}
