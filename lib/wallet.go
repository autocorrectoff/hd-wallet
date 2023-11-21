package lib

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-ethereum-hdwallet"

	"github.com/tyler-smith/go-bip39"
)

type HDWallet struct{}

type KeyPair struct {
	AddressHex    string
	PrivateKeyHex string
}

const BIP_PATH = "m/44'/60'/0'/0/%d"

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

func (wallet *HDWallet) GenerateKeyPairsFromSeedPhrase(mnemonic string, limit int) ([]KeyPair, error) {
	isValid := bip39.IsMnemonicValid(mnemonic)
	if !isValid {
		return nil, errors.New("invalid seed phrase")
	}
	w, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	keyPairs := []KeyPair{}
	for i := 0; i < limit; i++ {
		path, err := hdwallet.ParseDerivationPath(fmt.Sprintf(BIP_PATH, i))
		if err != nil {
			return nil, err
		}
		account, err := w.Derive(path, false)
		if err != nil {
			return nil, err
		}
		privateKeyHex, err := w.PrivateKeyHex(account)
		if err != nil {
			return nil, err
		}
		publicKeyHex := account.Address.Hex()
		keyPairs = append(keyPairs, KeyPair{AddressHex: publicKeyHex, PrivateKeyHex: privateKeyHex})
	}
	return keyPairs, nil
}

func (wallet *HDWallet) GenerateRandomSeedPhrase() string {
	// 128 bit = 12 word mnemonic; 256 bit = 24 word mnemonic;
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Println(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Println(err)
	}
	return mnemonic
}
