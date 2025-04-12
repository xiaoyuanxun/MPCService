package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	// 替换为你docker-compose中用到的服务名
	nodeNames = []string{
		"Berlin_node",
		"Bristol_node",
		"Data_provider1",
		"Leuven_node",
		"Ljubljana_node",
		"Madrid_node",
		"Manager",
		"Paris_node",
		"Rome_node",
	}
)

func main() {
	rootCAFile := "RootCA.crt"
	rootCAKeyFile := "RootCA.key"

	rootCAData, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("Failed to read root CA file: %v", err)
	}
	rootCAKeyData, err := os.ReadFile(rootCAKeyFile)
	if err != nil {
		log.Fatalf("Failed to read root CA key file: %v", err)
	}

	block, _ := pem.Decode(rootCAData)
	block2, _ := pem.Decode(rootCAKeyData)

	rootCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root CA certificate: %v", err)
	}
	rootCAKey, err := x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root CA private key: %v", err)
	}

	for i, name := range nodeNames {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key for %s: %v", name, err)
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				CommonName: name,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			DNSNames:              []string{name, "localhost"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			BasicConstraintsValid: true,
		}

		cert, err := x509.CreateCertificate(rand.Reader, &template, rootCA, privateKey.Public(), rootCAKey)
		if err != nil {
			log.Fatalf("Failed to create certificate for %s: %v", name, err)
		}

		certOut, err := os.Create(fmt.Sprintf("%s.crt", name))
		if err != nil {
			log.Fatalf("Failed to write certificate for %s: %v", name, err)
		}
		defer certOut.Close()
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

		keyOut, err := os.OpenFile(fmt.Sprintf("%s.key", name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to write key for %s: %v", name, err)
		}
		defer keyOut.Close()
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

		fmt.Printf("✅ Created certificate for %s\n", name)
	}
}
