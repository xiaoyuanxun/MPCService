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

var nodeNames = []string{
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

func main() {
	// 读取 RootCA
	rootCAFile := "RootCA.crt"
	rootKeyFile := "RootCA.key"

	rootCAData, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("❌ Failed to read RootCA.crt: %v", err)
	}
	rootKeyData, err := os.ReadFile(rootKeyFile)
	if err != nil {
		log.Fatalf("❌ Failed to read RootCA.key: %v", err)
	}

	caBlock, _ := pem.Decode(rootCAData)
	keyBlock, _ := pem.Decode(rootKeyData)

	rootCA, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		log.Fatalf("❌ Failed to parse RootCA certificate: %v", err)
	}
	rootKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Fatalf("❌ Failed to parse RootCA private key: %v", err)
	}

	for i, name := range nodeNames {
		fmt.Printf("🔐 Generating cert for %s...\n", name)

		// 生成节点私钥
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("❌ Failed to generate key for %s: %v", name, err)
		}

		// 创建证书模板
		template := x509.Certificate{
			SerialNumber: big.NewInt(int64(1000 + i)),
			Subject: pkix.Name{
				CommonName: name,
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames:    []string{name, "localhost"},
		}

		// 签发证书
		certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCA, &privateKey.PublicKey, rootKey)
		if err != nil {
			log.Fatalf("❌ Failed to create certificate for %s: %v", name, err)
		}

		// 保存证书
		certFile, err := os.Create(fmt.Sprintf("%s.crt", name))
		if err != nil {
			log.Fatalf("❌ Failed to write cert for %s: %v", name, err)
		}
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certFile.Close()

		// 保存私钥
		keyFile, err := os.Create(fmt.Sprintf("%s.key", name))
		if err != nil {
			log.Fatalf("❌ Failed to write key for %s: %v", name, err)
		}
		pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		keyFile.Close()

		fmt.Printf("✅ Certificate for %s created.\n", name)
	}
}
