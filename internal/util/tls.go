package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	netHttp "net"
	"time"
)

// GenerateSelfSignedCertificate generates a certificate to the provided ip
// address. Self-signed certificates should not be used in production. This
// function is for development and debugging purposes only.
func GenerateSelfSignedCertificate(ip string) (*tls.Certificate, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	keyUsage := x509.KeyUsageDigitalSignature
	ips := netHttp.ParseIP(ip)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Axis.com"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []netHttp.IP{ips},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certBuffer := new(bytes.Buffer)
	err = pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyBuffer := new(bytes.Buffer)
	err = pem.Encode(keyBuffer, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certBuffer.Bytes(), keyBuffer.Bytes())
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
