package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/Soyunomas/taltun/pkg/crypto"
)

func main() {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}

	fmt.Printf("private_key = %q\n", hex.EncodeToString(kp.Private[:]))
	fmt.Printf("public_key = %q\n", hex.EncodeToString(kp.Public[:]))
}
