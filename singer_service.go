package signer

import (
	"encoding/hex"
	"errors"
	"log"

	// "github.com/ubiq/go-ubiq/crypto"
	// "github.com/ethereum/go-ethereum/common"
	"fmt"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"github.com/ubiq/go-ubiq/crypto/secp256k1"

	// "github.com/btcsuite/btcd/btcec"
	crypto1 "github.com/ubiq/go-ubiq/crypto"
	// "github.com/ethereum/go-ethereum/hexutil"
	"github.com/ubiq/go-ubiq/common/hexutil"
	"golang.org/x/crypto/sha3"
)

type RateParams struct {
	Symbol   string
	Currency string
}

type SignerService struct {
	logger *log.Logger
}

func NewSignerService(logger *log.Logger) *SignerService {
	return &SignerService{
		logger: logger,
	}
}

// Http
func (s *SignerService) Sign(address string, amount string, nonce string) (string, error) {
	// key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	// if err != nil {
	// 	panic(err)
	// }
	//0x2BB32bBE01840DEb3d2512C74c4fdA7c1992993D
	// input pirvate key
	pkeyb, err := hex.DecodeString("")
	if err != nil {
		// s.logger.Fatalln(err)
		return "", err
	}

	// message := "TEST"
	// // Turn the message into a 32-byte hash
	// hash := solsha3.SoliditySHA3(solsha3.String(message))

	// types := []string{"address", "bytes1", "uint8[]", "bytes32", "uint256", "address[]", "uint32"}
	// values := []interface{}{
	//     "0x935F7770265D0797B621c49A5215849c333Cc3ce",
	//     "0xa",
	//     []uint8{128, 255},
	//     "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	//     "100000000000000000",
	//     []string{
	//         "0x13D94859b23AF5F610aEfC2Ae5254D4D7E3F191a",
	//         "0x473029549e9d898142a169d7234c59068EDcBB33",
	//     },
	//     123456789,
	// }

	types := []string{"address", "uint256", "uint256"}
	values := []interface{}{
		address,
		amount,
		nonce,
	}

	hash := solsha3.SoliditySHA3(types, values)
	// fmt.Println("message:", hex.EncodeToString(hash))

	types = []string{"string", "bytes32"}
	values = []interface{}{
		"\x19Ethereum Signed Message:\n32",
		hash,
	}
	// Prefix and then hash to mimic behavior of eth_sign
	prefixed := solsha3.SoliditySHA3(types, values)
	// sig, err := secp256k1.Sign(prefixed, math.PaddedBigBytes(key.D, 32))
	sig, err := secp256k1.Sign(prefixed, pkeyb)
	if err != nil {
		// panic(err)
		return "", err
	}
	s.logger.Printf("Process sign : %s, %s, %s ,%s", address, amount, nonce, hex.EncodeToString(sig))
	return hex.EncodeToString(sig), nil
}

func (s *SignerService) SignMessage(msg string, prv string) (string, error) {
	// key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	// if err != nil {
	// 	panic(err)
	// }
	//0x2BB32bBE01840DEb3d2512C74c4fdA7c1992993D
	pkeyb, err := hex.DecodeString(prv)
	if err != nil {
		// s.logger.Fatalln(err)
		return "", err
	}

	types := []string{"bytes"}
	values := []interface{}{
		msg,
	}
	hash := solsha3.SoliditySHA3(types, values)

	types = []string{"string", "bytes32"}
	values = []interface{}{
		"\x19Ethereum Signed Message:\n32",
		hash,
	}
	raw_hash := solsha3.SoliditySHA3(types, values)

	// sig, err := secp256k1.Sign(prefixed, math.PaddedBigBytes(key.D, 32))
	sig, err := secp256k1.Sign(raw_hash, pkeyb)
	if err != nil {
		// panic(err)
		return "", err
	}
	sig[64] += 27
	return hex.EncodeToString(sig), nil
}

func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto1.Keccak256([]byte(msg))
}

// func SigToPub(hash, sig []byte) (string, error) {
// 	btcsig := make([]byte, 65)
// 	btcsig[0] = sig[64] + 27
// 	copy(btcsig[1:], sig)

// 	pub, _, err := btcec.RecoverCompact(btcec.S256(), btcsig, hash)
// 	ret := hex.EncodeToString(pub)
// 	return ret, nil
// }

func Ecrecover(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}

func TextAndHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), string(data))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	return hasher.Sum(nil), msg
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func (s *SignerService) RecoverPubkey(msg string, sig string) (string, error) {
	s.logger.Printf("Process RecoverPubkey : %s, %s", msg, sig)

	hexdata, _ := hexutil.Decode(msg)

	hash, _ := TextAndHash(hexdata)

	// raw_hash := crypto1.Keccak256(prefixed)

	if len(sig) != 132 && !has0xPrefix(sig) {
		// s.logger.Fatalln("sig length error : ", sig)
		return "", errors.New("sig length error, must length  130 and 0x prefix")
	}

	hexsig, err := hex.DecodeString(sig[2:])
	if err != nil {
		// s.logger.Fatalln(err)
		return "", err
	}
	hexsig[64] -= 27
	// pksource, err := secp256k1.RecoverPubkey(signHash(raw_hash), hexsig);
	// if err != nil {
	// 	s.logger.Printf("Process RecoverPubkey error : %s, %s", msg, sig)
	// 	return "", err;
	// }
	// address := crypto.PubkeyToAddress(pksource).Hex()
	// pubkey, _ := crypto1.SigToPub(signHash(raw_hash), hexsig)
	pubkey, _ := crypto1.SigToPub(hash, hexsig)

	address := crypto1.PubkeyToAddress(*pubkey)
	return address.String(), nil
}
