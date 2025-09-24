package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
	Dp  string `json:"dp"`
	Dq  string `json:"dq"`
	Qi  string `json:"qi"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func main() {
	var (
		inputFile  = flag.String("in", "", "Input JWKS file")
		outputFile = flag.String("out", "", "Output private key file")
		createTest = flag.Bool("test", false, "Create test.jwks example file")
		showHelp   = flag.Bool("help", false, "Show help")
	)
	
	flag.Parse()
	
	if *showHelp || (len(os.Args) == 1) {
		showHelpText()
		return
	}
	
	if *createTest {
		createTestJWKS()
		return
	}
	
	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Error: Both -in and -out flags are required")
		showHelpText()
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("Error reading JWKS file: %v", err)
	}

	keys, err := parseJWKS(data)
	if err != nil {
		log.Fatalf("Error parsing JWKS: %v", err)
	}

	if len(keys) == 0 {
		log.Fatal("No keys found in JWKS")
	}

	var pemBlocks [][]byte
	keyCount := 0

	for i, key := range keys {
		if key.Kty != "RSA" {
			fmt.Printf("Skipping non-RSA key %d (type: %s)\n", i+1, key.Kty)
			continue
		}

		privateKey, err := jwkToRSAPrivateKey(key)
		if err != nil {
			fmt.Printf("Error converting key %d to RSA private key: %v\n", i+1, err)
			continue
		}

		keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			fmt.Printf("Error marshaling private key %d: %v\n", i+1, err)
			continue
		}

		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}

		if key.Kid != "" {
			block.Headers = map[string]string{
				"Kid": key.Kid,
			}
		}

		pemBlocks = append(pemBlocks, pem.EncodeToMemory(block))
		keyCount++
	}

	if keyCount == 0 {
		log.Fatal("No valid RSA private keys found")
	}

	var finalPem []byte
	for _, block := range pemBlocks {
		finalPem = append(finalPem, block...)
		finalPem = append(finalPem, '\n')
	}

	if err := ioutil.WriteFile(*outputFile, finalPem, 0600); err != nil {
		log.Fatalf("Error writing private key file: %v", err)
	}

	fmt.Printf("Exported %d private key(s) to %s\n", keyCount, *outputFile)
}

func showHelpText() {
	fmt.Println("JWKS Juggler : JWKS -> Private Key")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  jwksjuggler [OPTIONS]")
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("  -in <file>     Input JWKS file path (required for export)")
	fmt.Println("  -out <file>    Output private key file path (required for export)")
	fmt.Println("  -test          Create test.jwks example file")
	fmt.Println("  -help          Show this help message")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Export private keys from JWKS file:")
	fmt.Println("  jwks-export -in keys.jwks -out private-keys.pem")
	fmt.Println()
	fmt.Println("  # Create test JWKS file:")
	fmt.Println("  jwks-export -test")
	fmt.Println()
	fmt.Println("FEATURES:")
	fmt.Println("  • Supports various JWKS JSON formats")
	fmt.Println("  • Exports multiple RSA private keys")
	fmt.Println("  • Handles nested JSON structures")
	fmt.Println("  • Includes key IDs in PEM headers")
	fmt.Println("  • Only processes RSA keys (skips other types)")
}

func parseJWKS(data []byte) ([]JWK, error) {
	var result []JWK
	var rawData map[string]interface{}
	
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	
	keys := findKeys(rawData)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in JSON structure")
	}
	
	for _, keyData := range keys {
		keyJSON, err := json.Marshal(keyData)
		if err != nil {
			continue
		}
		
		var jwk JWK
		if err := json.Unmarshal(keyJSON, &jwk); err != nil {
			continue
		}
		
		if jwk.Kty != "" {
			result = append(result, jwk)
		}
	}
	
	return result, nil
}

func findKeys(data interface{}) []interface{} {
	var keys []interface{}
	
	switch v := data.(type) {
	case map[string]interface{}:
		if kty, exists := v["kty"]; exists && kty != nil {
			keys = append(keys, v)
		}
		
		for key, value := range v {
			if key == "keys" || key == "jwks" || key == "key_set" || key == "keySet" {
				if arr, ok := value.([]interface{}); ok {
					keys = append(keys, arr...)
				}
			} else {
				keys = append(keys, findKeys(value)...)
			}
		}
		
	case []interface{}:
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if kty, exists := itemMap["kty"]; exists && kty != nil {
					keys = append(keys, item)
				}
			}
			keys = append(keys, findKeys(item)...)
		}
	}
	
	return keys
}

func jwkToRSAPrivateKey(jwk JWK) (*rsa.PrivateKey, error) {
	n, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("error decoding n: %v", err)
	}

	e, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("error decoding e: %v", err)
	}

	d, err := base64URLDecode(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("error decoding d: %v", err)
	}

	p, err := base64URLDecode(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("error decoding p: %v", err)
	}

	q, err := base64URLDecode(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("error decoding q: %v", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D: new(big.Int).SetBytes(d),
		Primes: []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		},
	}, nil
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	for len(s)%4 != 0 {
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func createTestJWKS() {
	testJWKS := `{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "test-key-1",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWYzFOZznMeKwJ6xwz_FTp9AEhTFLT_J2S8CL5HFf3Vx4QXRPhNqxdD-zKMfwXXchmNKo6xvZJxGlHj-9YqLTIJ2MkcBPvVJjYhqJi3Uy4zG9MKJkpJgPg7Qvk8oRPzGHhAqJx1j8WxAvTYOt_wLHIZB2W1h6zYbQnN3DH-1qN6BVlR1P4Z4YH_8nBNGl7JQr0FEK7GtG0fP9ZGmxMm3Yk2r--4H5u8Qpf5FZLRBx5q4vgFYQE6I6kGf9jBqA",
      "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPBQxtS2vz3wA-pYMnkH2bNmWpQQRZ0w8LsGdqfgpbI-s9NlGNZl-3-uP1qF4Q8P9f9fZVq8hQZpM0QeKrWWlFBJ1vgpG_GJ5jKvf7Nv1sD_oP2EQ-7L2Q7hH3bYcfrOQmL",
      "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
      "dp": "G4sPXkc6Ya9y_oJF_mKJ0G2FvgHdD1hP8V5AjAjJhK1XKZF3kU9VFY8kHYT5Z8_Fq5tD0kO9-v1zHO9iZ8pB1XZHL8CkgG6TfIKlSJJ8j4J7YhQj6K-wYF9JhJk6LFzJVB9NOYQ5jK2f2RXKZHvNnI4XH9s3xGaIQpQx-BrpKgg",
      "dq": "s9lAH9fggBsoFR8Oac2R_egTQBPY4tJXOD6H0v_YU5M4JKME_wJLnOGdz4r4FJ6d3oZPh6R2YkzGDhkKxK8G7J6p1M6FYP8wUv3YjKZpuX2lZ5oYnCzUUIc9bKB_lNYT3K7XPzH_8mGoZHo9HJkY0YxqBJy4qH6lW6V5EgTzVQ",
      "qi": "TYWnOTe6HBc9VD6V7Mzq4K9Wx0lGkqJcC8-0e_tA8Z2gF4kZf7XrG7z5DJBCqF3J3J8OFoA7U8PKjQ0zFvdlLV2DGVz3lIHLdR0p6F5BVVR5EoVT8EqMH5QIqJyHNUcLlR3U9lKB8H7J6m2Q0A1yGIhBg-WZvGbI4pOq7xQ5"
    },
    {
      "kty": "RSA",
      "use": "enc",
      "kid": "test-key-2",
      "n": "sRJjz1mUHWsOGRuUZSvDv5dSFybmKC7EdPcS4mV7O6S0lDmr1jYoZhJ4eE9PqFqT5Qo2nF2NzX5S0dY6Rt2Qx7Nz1kHg5B3L0E7hF8MmQrV4W9Ks2Jd3G6aL1P0fI5yT8AJHG2qP9V4RcX1N2zK0Y3D8sL6F0nQm5tE4Bv7U9W",
      "e": "AQAB", 
      "d": "H4L2lD8NF6mOQrV1T7QvS3BnF9K4J2MxP0eE6gL8Y5rN0W2cQ9XvZ1kH4pO7mI3jR8wB5VsF0nL6Dt2Y9K1cG3Aa4jN7rP6xM8OsV5TqW4hF2EyR9K0bG1wN5Lz8XsV7Y0fMjQ4eT9IbU2PcH6JnG3oA1DkFvRt0eL5WmY8ZsQ",
      "p": "2nHH3-2bQ4fL8wV0X9NkY6rT7oP1M5jK3E4dG0yV8C2qF5nW6hOz1uL9kS8R7mA3B4xP0eQ5fG2jV8tN6EcJ1KLML9RqW4sT0yX6PnF5GhV8OaB3CdQ7LmR0eJ4N9YtUV2xKfP8G1",
      "q": "yV8M0fL2tR9QwN6uB4eS7hG3oA1kJ5nD2cV7rP8YmQ4xB0eJ6hL3fG9sT1NtK4yW8CmO7vE5pRqX2jF0dY3GhV9KsL8N6QrT1PcB4mY5WxE2AaF7G0yV8JnD3oP1MkR5zQ",
      "dp": "F3G8mE7hY4jK2NtQ1cV0xL5fP9RqW6oS8dG3nA0yB2eJ7vM1KlT4uC6rE8YmQ5sN0fL3hG9wV8JpO7tR2xKfD1G4nA5BmY0eS6hL7oP8QrT9vE2cF1",
      "dq": "mY3F0dJ6hS8GvA1NtL4rE2yQ9wV7nB5cP0eK8oT1xG4jH7mL6fS3RqY2uE5hN9WxV8CmO0dG7tP1KlB4eJ5nA2fMjQ6yW8SrT3oV9LcH1GkF8N0ePqX7mY4sL5hG2jB9wV",
      "qi": "sT1nG4eJ7mL0dY6hF8CpO9wV2xK5fP3RqW8oS7dG1nA4yB6eJ0vM2KlT5uC9rE1YmQ8sN3fL0hG4wV7JpO1tR5xKfD2G8nA0BmY3eS1hL9oP7QrT6vE5cF4G"
    }
  ]
}`

	if err := ioutil.WriteFile("test.jwks", []byte(testJWKS), 0644); err != nil {
		log.Fatalf("Error creating test.jwks: %v", err)
	}

	fmt.Println("Created test.jwks file")
	fmt.Println("Usage: ./jwks-export -in test.jwks -out output-key.pem")
}
