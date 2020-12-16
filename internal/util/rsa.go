package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"

	"github.com/form3tech-oss/jwt-go"
)

const KEY_PATH = "keys"

// GetPrivateKeys retrieves private keys from file if they exist,
// otherwise a new private key is generated and stored on disk and returned.
// It will look into the directory KEY_PATH located in the provided directory.
func GetPrivateKeys(dir string) ([]*rsa.PrivateKey, error) {
	privateKeyPath := filepath.Join(dir, KEY_PATH)

	if !dirExist(privateKeyPath) {
		logger.Info("Directory %q does not exist. Creating it...", privateKeyPath)
		err := os.Mkdir(privateKeyPath, os.ModePerm)
		if err != nil {
			logger.Info(err.Error())
			return nil, err
		}
		logger.Info("Created directory %q.", privateKeyPath)
	}

	privateKeys, err := loadKeys(privateKeyPath)
	if err != nil {
		logger.Info(err.Error())
		return nil, err
	}

	if len(privateKeys) > 0 {
		logger.Info("Using existing private key.")
		return privateKeys, nil
	}

	// No key stored on file - generate and store a new key

	privateKey, err := generateKey()
	if err != nil {
		logger.Info(err.Error())
		return nil, err
	}
	logger.Info("Generated new private key.")

	filename := filepath.Join(privateKeyPath, fmt.Sprintf("id_rsa_%s", time.Now().Format("2006_01_02T15_04_05")))
	err = storePrivateKeyOnFile(privateKey, filename)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	logger.Info("Stored new private key. Saved as %q.", filename)

	return []*rsa.PrivateKey{privateKey}, nil
}

// dirExist returns true if the provided dirname is a directory and exist.
func dirExist(dirname string) bool {
	info, err := os.Stat(dirname)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// loadKeys read RSA private keys from file. If no keys exist in the provided
// path, an empty slice is returned.
func loadKeys(privateKeyPath string) ([]*rsa.PrivateKey, error) {
	files, err := ioutil.ReadDir(privateKeyPath)
	if err != nil {
		logger.Info(err.Error())
		return nil, err
	}
	// Sort all files according to modification timestamp in descending order
	// Latest modified first
	sort.SliceStable(
		files,
		func(i, j int) bool {
			return files[i].ModTime().After(files[j].ModTime())
		},
	)

	privateKeys := []*rsa.PrivateKey{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}
		if strings.HasSuffix(file.Name(), "pub") {
			continue
		}
		filename := filepath.Join(privateKeyPath, file.Name())
		priv, err := parsePrivateKey(filename)
		if err != nil {
			logger.Info("Ignoring file %q, due to: %s", file.Name(), err.Error())
			continue
		}

		privateKeys = append(privateKeys, priv)
	}

	return privateKeys, nil
}

// parsePrivateKey reads a private key from file and returns
// an rsa private key
func parsePrivateKey(path string) (*rsa.PrivateKey, error) {
	signBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pvk, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, err
	}

	return pvk, nil
}

// generateKey generate a new RSA key
func generateKey() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return priv, nil
}

// storePrivateKeyOnFile stores the provided key on the provided path. Since
// this file should not be accessible by others (read/write/execute) this is
// stored with the permission 600 (600 is used instead of 400 since otherwise
// the file can't be deleted by the user running the application on windows).
func storePrivateKeyOnFile(key *rsa.PrivateKey, path string) error {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	err := ioutil.WriteFile(path, pemdata, 0o600)

	return err
}

// GetKid retrieves the key ID (kid) from the private key
// The kid is used to map a jwt with matching jwk
func GetKid(key *rsa.PrivateKey) (string, error) {
	keyData, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		logger.Error("Could not marshal public key", err.Error())
		return "", err
	}
	hash := sha1.New()
	_, _ = hash.Write(keyData)
	checksum := hash.Sum(nil)
	return fmt.Sprintf("%x", checksum), nil
}
