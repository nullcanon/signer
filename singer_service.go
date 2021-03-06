package signer

import (
	"encoding/hex"
	"log"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
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
	pkeyb, err := hex.DecodeString("")
	if err != nil {
		s.logger.Fatalln(err)
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
		panic(err)
	}
	s.logger.Printf("Process sign : %s, %s, %s ,%s", address, amount, nonce, hex.EncodeToString(sig))
	return hex.EncodeToString(sig), nil
}
