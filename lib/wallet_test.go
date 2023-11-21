package lib

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestPrivateKeyToAddress(t *testing.T) {
	wallet := HDWallet{}

	// Test a valid private key
	validPrivateKeyHex := "8fd8bacfb30ac9afdd88a90e6d9fc357860e3794ef9b9f7f9362a104a439f3d5"
	expectedAddress := "0x63Ce247a51D591e80268D4e2cA044a762d03e59c"
	expectedCommonAddress := common.HexToAddress(expectedAddress)

	address, err := wallet.PrivateKeyToAddress(validPrivateKeyHex)

	assert.NoError(t, err)
	assert.Equal(t, expectedCommonAddress, address)
}

func TestGenerateKeyPairsFromSeedPhrase(t *testing.T) {
	wallet := HDWallet{}

	// Test with valid data
	validMnemonic := "merry expose effort present crawl similar portion obtain song pool extend erosion"
	limit := 5

	keyPairs, err := wallet.GenerateKeyPairsFromSeedPhrase(validMnemonic, limit)

	expectedKeyPairs := []KeyPair{
		{"0x63Ce247a51D591e80268D4e2cA044a762d03e59c", "8fd8bacfb30ac9afdd88a90e6d9fc357860e3794ef9b9f7f9362a104a439f3d5"}, {"0x85ba13799DA3f2cA2b6Fb569A2FEF81B50cd57fE", "9ca9ff57d17e15cf16f77610177eaaec29daac629919442c0691ed689e683189"}, {"0x0fAb721E4CDA85c251cD743872b7538BfCCB906b", "208653e96ed9b5f1154f4ad86ec5d6e6bdefb1e8f075a8cdc33f74714c8938ad"}, {"0x44c606Cfd43F2795271f91451Fa98784d4BB184C", "6091d825a6fcc283e8404eed470bcdc582713bdc6e668edd2d051910cbd17165"}, {"0x3Fb4a03a956635d15afb97B6F87C8fBdc90bc882", "65f6d70145d875dee324ed62fb5855404c45e603d606422f95a787efbe88daa6"},
	}

	assert.NoError(t, err)
	assert.Len(t, keyPairs, limit)
	assert.True(t, testEq(expectedKeyPairs, keyPairs))
}

func TestGenerateRandomSeedPhrase(t *testing.T) {
	wallet := HDWallet{}

	seedPhrase := wallet.GenerateRandomSeedPhrase()

	assert.NotEmpty(t, seedPhrase)
}

func testEq(a, b []KeyPair) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
