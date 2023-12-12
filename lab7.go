package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
	"github.com/fentec-project/gofe/innerprod/simple"
	"github.com/fentec-project/gofe/innerprod/fullysec"
)

func getNumberInput(l int, input string) []*big.Int {
	var temp int64

	sepStrings := strings.Split(input, " ")
	if !(len(sepStrings) == l) {
		panic(fmt.Sprintf("Length of unencrypted vector y (%v) is not equal to set vector length l (%v))", len(sepStrings), l))
	}
	arrayOutput := []*big.Int{}

	for i := 0; i < len(sepStrings); i++ {
		temp, _ = strconv.ParseInt(sepStrings[i], 10, 64)
		arrayOutput = append(arrayOutput, big.NewInt(temp))
	}
	return arrayOutput
}
func calcDotMatrix(numClients int, X data.Matrix, Y data.Matrix, bound *big.Int) *big.Int {
	dotProduct := big.NewInt(0)
	for i := 0; i < numClients; i++ {
		for j := 0; j < len(X[i]); j++{
			temp := big.NewInt(0)
			dotProduct.Add(dotProduct, temp.Mul(X[i][j], Y[i][j]))
		}
	}
	return dotProduct.Mod(dotProduct, bound)
}
func calcDot(xArray []*big.Int, yArray []*big.Int, bound *big.Int) *big.Int {
	dotProduct := big.NewInt(0)
	for i := 0; i < len(xArray); i++ {
		temp := big.NewInt(0)
		dotProduct.Add(dotProduct, temp.Mul(xArray[i], yArray[i]))
	}
	return dotProduct.Mod(dotProduct, bound)
}

func main() {
	fmt.Println("Enter vector length l: ")
	scanner := bufio.NewScanner(os.Stdin)
	var input string

	if scanner.Scan() {
		input = scanner.Text()
	}
	l, _ := strconv.Atoi(input) // length of input vectors
	bound := big.NewInt(1000)     // upper bound for input vector coordinates
	modulusLength := 2048       // bit length of prime modulus p

	fmt.Println("Enter test version (1 -- s-IND-CPA; 2 -- IND-CPA; 3 -- Multi-client (auto-generated matrix values for 2 clients); 4 -- Decentralized): ")
	if scanner.Scan() {
		input = scanner.Text()
	}
	testNumber, _ := strconv.Atoi(input)
	
	var x,y data.Vector
	if !(testNumber == 3) {
		fmt.Println("Enter Your unencrypted number vector (seperated by a blank space): ")
		if scanner.Scan() {
			input = scanner.Text()
		}
		yArray := getNumberInput(l, input)
		y = data.NewVector(yArray)

		fmt.Println("Enter Your encrypted number vector (seperated by a blank space): ")
		if scanner.Scan() {
			input = scanner.Text()
		}
		xArray := getNumberInput(l, input)
		x = data.NewVector(xArray)

		sanityDot := calcDot(xArray, yArray, bound)
		fmt.Println("Calculated dot on unencrypted data: ", sanityDot)
	}
	
	switch testNumber {
	case 1:
		startTime := time.Now()
		trustedEnt, _ := simple.NewDDHPrecomp(l, modulusLength, bound)
		msk, mpk, _ := trustedEnt.GenerateMasterKeys()
		fmt.Printf("Master key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		feKey, _ := trustedEnt.DeriveKey(msk, y)
		fmt.Printf("Function key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		enc := simple.NewDDHFromParams(trustedEnt.Params)
		cipher, _ := enc.Encrypt(x, mpk)
		fmt.Printf("Encryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		dec := simple.NewDDHFromParams(trustedEnt.Params)
		xy, _ := dec.Decrypt(cipher, feKey, y)
		fmt.Printf("Decryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		fmt.Printf("Decrypted vector: %v\n", xy)
	case 2:
		startTime := time.Now()
		trustedEnt, _ := fullysec.NewDamgardPrecomp(l, modulusLength, bound)
		msk, mpk, _ := trustedEnt.GenerateMasterKeys()
		fmt.Printf("Master key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		feKey, _ := trustedEnt.DeriveKey(msk, y)
		fmt.Printf("Function key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		enc := fullysec.NewDamgardFromParams(trustedEnt.Params)
		cipher, _ := enc.Encrypt(x, mpk)
		fmt.Printf("Encryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		dec := fullysec.NewDamgardFromParams(trustedEnt.Params)
		xy, _ := dec.Decrypt(cipher, feKey, y)
		fmt.Printf("Decryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		fmt.Printf("Decrypted vector: %v\n", xy)

	case 3:
		var X, Y data.Matrix
		numClients := 2
		sampler := sample.NewUniform(bound)
		X, _ = data.NewRandomMatrix(numClients, l, sampler)
		Y, _ = data.NewRandomMatrix(numClients, l, sampler)
		fmt.Println("Generated matrix x: ", X, " and y: ", Y)

		sanityMatrix := calcDotMatrix(numClients, X, Y, bound)
		fmt.Println("Calculated dot on unencrypted data: ", sanityMatrix)
		
		startTime := time.Now()
		multiDDH, _ := simple.NewDDHMultiPrecomp(numClients, l, modulusLength, bound)
		mpk, msk, _ := multiDDH.GenerateMasterKeys()
		fmt.Printf("Master key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		feKey, _ := multiDDH.DeriveKey(msk, Y)
		fmt.Printf("Function key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		// Different encryptors may reside on different machines.
		// We simulate this with the for loop below, where numClients
		// encryptors are generated.
		startTime = time.Now()
		encryptors := make([]*simple.DDHMultiClient, numClients)
		for i := 0; i < numClients; i++ {
			encryptors[i] = simple.NewDDHMultiClient(multiDDH.Params)
		}	
		// Each encryptor encrypts its own input vector X[i] with the
		// keys given to it by the trusted entity.
		ciphers := make([]data.Vector, numClients)
		for i := 0; i < numClients; i++ {
			cipher, _ := encryptors[i].Encrypt(X[i], mpk[i], msk.OtpKey[i])
			ciphers[i] = cipher
		}
		fmt.Printf("Encryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		// Ciphers are collected by decryptor, who then computes
		// inner product over vectors from all encryptors.
		startTime = time.Now()
		decryptor := simple.NewDDHMultiFromParams(numClients, multiDDH.Params)
		xy, _ := decryptor.Decrypt(ciphers, feKey, Y)
		fmt.Printf("Decryption time: %v ns\n", time.Since(startTime).Nanoseconds())
		fmt.Printf("Decrypted vector: %v\n", xy)

	case 4:
		//Decentralized FE is usually multi-client
		startTime := time.Now()
		clients := make([]*fullysec.DMCFEClient, l)
		pubKeys := make([]*bn256.G1, l)

		for i := 0; i < l; i++ {
			c, _ := fullysec.NewDMCFEClient(i)
			clients[i] = c
			pubKeys[i] = c.ClientPubKey
		}
		fmt.Printf("Client public key generation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		for i := 0; i < l; i++ {
			clients[i].SetShare(pubKeys)
		}
		fmt.Printf("Client private share generation time: %v ns\n", time.Since(startTime).Nanoseconds())
		
		label := "Partial key generation"
		ciphers := make([]*bn256.G1, l)
		keyShares := make([]data.VectorG2, l)

		startTime = time.Now()
		for i := 0; i < l; i++ {
			c, _ := clients[i].Encrypt(x[i], label)
			
			ciphers[i] = c
		}
		fmt.Printf("Client encryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		for i := 0; i < l; i++ {
			keyShare, _ := clients[i].DeriveKeyShare(y)

			keyShares[i] = keyShare
		}
		fmt.Printf("Client key derivation time: %v ns\n", time.Since(startTime).Nanoseconds())

		startTime = time.Now()
		bound.Mul(bound, bound)
		bound.Mul(bound, big.NewInt(int64(l))) // numClients * (coordinate_bound)^2
		xy, _ := fullysec.DMCFEDecrypt(ciphers, keyShares, y, label, bound)
		fmt.Printf("Decryption time: %v ns\n", time.Since(startTime).Nanoseconds())

		fmt.Printf("Decrypted vector: %v\n", xy)
	}
	
}
