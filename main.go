package main

/*
Functionality we need:

- One Click to Generate Encryption Key used for restic, and encrypt that key with 5 keys, which will require 3 keys to decrypt
- One Click to Output Encrpytion Key used in restic for decrypting data


*/
import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bodaay/multikey/multikey"
	"github.com/bodaay/multikey/multikey/keys"
	"github.com/sethvargo/go-password/password"
)

const numberOfRandomEncKeysGenerated = 5
const minNumberOfKeysToDecrypt = 3
const randomPlainTextResticPasswordLength = 32
const pubKeyExtension = "kPubKey"
const priKeyExtension = "kPriKey"
const passwordKeyExtension = "kMulKey"

func printUsage(execName string) {
	fmt.Printf("Usage To Generate Encryption Key Files: %s Generate DestinationFolder\n", execName)
	fmt.Printf("Usage To Generate Encrypted Random Restic Password: %s Encrypt DestinationFolder PublicKey1FilePath PublicKey2FilePath PublicKey3FilePath PublicKey4FilePath PublicKey5FilePath\n", execName)
	fmt.Printf("Usage To Get Back Decrypted Restic Password: %s Decrypt ResticEncryptedKeyFile PirvateKey1FilePath PirvateKey2FilePath PirvateKey3FilePath\n", execName)

}

func FolderExists(folderName string) bool {
	if _, err := os.Stat(folderName); !os.IsNotExist(err) {
		return true
	}
	return false
}
func publicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}
func privateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// BytesToPrivateKey bytes to private key
func bytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		// log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// BytesToPublicKey bytes to public key
func bytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		// log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

// func publicKeyToHexEncodedString(pub *rsa.PublicKey) (string, error) {
// 	pbytes, err := publicKeyToBytes(pub)
// 	if err != nil {
// 		return "", err
// 	}
// 	return hex.EncodeToString(pbytes), nil
// }
// func privateKeyToHexEncodedString(priv *rsa.PrivateKey) string {
// 	pbytes := privateKeyToBytes(priv)
// 	return hex.EncodeToString(pbytes)
// }
func main() {
	execName := filepath.Base(os.Args[0])

	if len(os.Args) < 3 {
		printUsage(execName)
		os.Exit(0)
	}
	command := strings.ToLower(os.Args[1])
	destinationPath := os.Args[2]
	if command == "generate" {
		// destinationPath := os.Args[2]
		//verify destination path is correct
		if !FolderExists(destinationPath) {
			err := os.MkdirAll(destinationPath, os.ModePerm)
			if err != nil {
				panic(err)
			}

		}
		os.MkdirAll(path.Join(destinationPath, "key1"), os.ModePerm)
		os.MkdirAll(path.Join(destinationPath, "key2"), os.ModePerm)
		os.MkdirAll(path.Join(destinationPath, "key3"), os.ModePerm)
		os.MkdirAll(path.Join(destinationPath, "key4"), os.ModePerm)
		os.MkdirAll(path.Join(destinationPath, "key5"), os.ModePerm)
		PubKey1FileName := path.Join(destinationPath, "key1", fmt.Sprintf("Pubkey.%s", pubKeyExtension))
		PubKey2FileName := path.Join(destinationPath, "key2", fmt.Sprintf("Pubkey.%s", pubKeyExtension))
		PubKey3FileName := path.Join(destinationPath, "key3", fmt.Sprintf("Pubkey.%s", pubKeyExtension))
		PubKey4FileName := path.Join(destinationPath, "key4", fmt.Sprintf("Pubkey.%s", pubKeyExtension))
		PubKey5FileName := path.Join(destinationPath, "key5", fmt.Sprintf("Pubkey.%s", pubKeyExtension))

		PriKey1FileName := path.Join(destinationPath, "key1", fmt.Sprintf("Prikey.%s", priKeyExtension))
		PriKey2FileName := path.Join(destinationPath, "key2", fmt.Sprintf("Prikey.%s", priKeyExtension))
		PriKey3FileName := path.Join(destinationPath, "key3", fmt.Sprintf("Prikey.%s", priKeyExtension))
		PriKey4FileName := path.Join(destinationPath, "key4", fmt.Sprintf("Prikey.%s", priKeyExtension))
		PriKey5FileName := path.Join(destinationPath, "key5", fmt.Sprintf("Prikey.%s", priKeyExtension))

		//generate the 5 keys

		//Key 1
		priKey1, pubKey1, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			panic(err)
		}
		pubKey1Bytes, err := publicKeyToBytes(pubKey1)
		if err != nil {
			panic(err)
		}
		priKey1Bytes := privateKeyToBytes(priKey1)
		err = ioutil.WriteFile(PubKey1FileName, pubKey1Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(PriKey1FileName, priKey1Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}

		//Key 2
		priKey2, pubKey2, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			panic(err)
		}
		pubKey2Bytes, err := publicKeyToBytes(pubKey2)
		if err != nil {
			panic(err)
		}
		priKey2Bytes := privateKeyToBytes(priKey2)
		err = ioutil.WriteFile(PubKey2FileName, pubKey2Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(PriKey2FileName, priKey2Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}

		//Key 3
		priKey3, pubKey3, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			panic(err)
		}
		pubKey3Bytes, err := publicKeyToBytes(pubKey3)
		if err != nil {
			panic(err)
		}
		priKey3Bytes := privateKeyToBytes(priKey3)
		err = ioutil.WriteFile(PubKey3FileName, pubKey3Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(PriKey3FileName, priKey3Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		//Key 4
		priKey4, pubKey4, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			panic(err)
		}
		pubKey4Bytes, err := publicKeyToBytes(pubKey4)
		if err != nil {
			panic(err)
		}
		priKey4Bytes := privateKeyToBytes(priKey4)
		err = ioutil.WriteFile(PubKey4FileName, pubKey4Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(PriKey4FileName, priKey4Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		//Key 5
		priKey5, pubKey5, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			panic(err)
		}
		pubKey5Bytes, err := publicKeyToBytes(pubKey5)
		if err != nil {
			panic(err)
		}
		priKey5Bytes := privateKeyToBytes(priKey5)
		err = ioutil.WriteFile(PubKey5FileName, pubKey5Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(PriKey5FileName, priKey5Bytes, os.ModePerm)
		if err != nil {
			panic(err)
		}

		// var pubs []*rsa.PublicKey
		// pubs = append(pubs, pubKey1)
		// pubs = append(pubs, pubKey2)
		// pubs = append(pubs, pubKey3)
		// pubs = append(pubs, pubKey4)
		// pubs = append(pubs, pubKey5)
		// mkEncryptedSecret, err := multikey.Encrypt([]byte(radomResticPassword), pubs, minNumberOfKeysToDecrypt)
		// if err != nil {
		// 	panic(err)
		// }
		// err = ioutil.WriteFile(ResticEncryptedKeyFile, []byte(mkEncryptedSecret), os.ModePerm)
		// if err != nil {
		// 	panic(err)
		// }
		// fmt.Println(radomResticPassword)

	} else if command == "encrypt" {
		ResticEncryptedKeyFile := path.Join(destinationPath, fmt.Sprintf("password.key.%s", passwordKeyExtension))
		//Read Public Keys from files
		pubKey1FileName := os.Args[3]
		pubKey2FileName := os.Args[4]
		pubKey3FileName := os.Args[5]
		pubKey4FileName := os.Args[6]
		pubKey5FileName := os.Args[7]

		//Key 1
		pubKey1Bytes, err := ioutil.ReadFile(pubKey1FileName)
		if err != nil {
			panic(err)
		}
		pubKey1PubRSA, err := bytesToPublicKey(pubKey1Bytes)
		if err != nil {
			panic(err)
		}

		//Key 2
		pubKey2Bytes, err := ioutil.ReadFile(pubKey2FileName)
		if err != nil {
			panic(err)
		}
		pubKey2PubRSA, err := bytesToPublicKey(pubKey2Bytes)
		if err != nil {
			panic(err)
		}

		//Key 3
		pubKey3Bytes, err := ioutil.ReadFile(pubKey3FileName)
		if err != nil {
			panic(err)
		}
		pubKey3PubRSA, err := bytesToPublicKey(pubKey3Bytes)
		if err != nil {
			panic(err)
		}

		//Key 4
		pubKey4Bytes, err := ioutil.ReadFile(pubKey4FileName)
		if err != nil {
			panic(err)
		}
		pubKey4PubRSA, err := bytesToPublicKey(pubKey4Bytes)
		if err != nil {
			panic(err)
		}

		//Key 5
		pubKey5Bytes, err := ioutil.ReadFile(pubKey5FileName)
		if err != nil {
			panic(err)
		}
		pubKey5PubRSA, err := bytesToPublicKey(pubKey5Bytes)
		if err != nil {
			panic(err)
		}

		// chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyzåäö" + "0123456789" + "!@#$%^&*")
		// length := randomPlainTextResticPasswordLength
		// var b strings.Builder
		// for i := 0; i < length; i++ {
		// 	b.WriteRune(chars[rand.Intn(len(chars))])
		// }
		res, err := password.Generate(32, 10, 10, false, true)
		if err != nil {
			log.Fatal(err)
		}
		radomResticPassword := res // E.g. "ExcbsVQs"

		var pubs []*rsa.PublicKey
		pubs = append(pubs, pubKey1PubRSA)
		pubs = append(pubs, pubKey2PubRSA)
		pubs = append(pubs, pubKey3PubRSA)
		pubs = append(pubs, pubKey4PubRSA)
		pubs = append(pubs, pubKey5PubRSA)

		mkEncryptedSecret, err := multikey.Encrypt([]byte(radomResticPassword), pubs, minNumberOfKeysToDecrypt)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(ResticEncryptedKeyFile, []byte(mkEncryptedSecret), os.ModePerm)
		if err != nil {
			panic(err)
		}
		fmt.Println(radomResticPassword)

	} else if command == "decrypt" {
		resticKeyFile := os.Args[2]
		resticEncKey, err := ioutil.ReadFile(resticKeyFile)
		if err != nil {
			panic(err)
		}
		priKey1FileName := os.Args[3]
		priKey2FileName := os.Args[4]
		priKey3FileName := os.Args[5]

		//Key 1
		priKey1Bytes, err := ioutil.ReadFile(priKey1FileName)
		if err != nil {
			panic(err)
		}
		priKey1PriRSA, err := bytesToPrivateKey(priKey1Bytes)
		if err != nil {
			panic(err)
		}

		//Key 2
		priKey2Bytes, err := ioutil.ReadFile(priKey2FileName)
		if err != nil {
			panic(err)
		}
		priKey2PriRSA, err := bytesToPrivateKey(priKey2Bytes)
		if err != nil {
			panic(err)
		}

		//Key 3
		priKey3Bytes, err := ioutil.ReadFile(priKey3FileName)
		if err != nil {
			panic(err)
		}
		priKey3PriRSA, err := bytesToPrivateKey(priKey3Bytes)
		if err != nil {
			panic(err)
		}
		var privs []*rsa.PrivateKey
		privs = append(privs, priKey1PriRSA)
		privs = append(privs, priKey2PriRSA)
		privs = append(privs, priKey3PriRSA)
		plainTxtSecret, err := multikey.Decrypt(string(resticEncKey), privs)
		if err != nil {
			panic(err)
		}
		plainTxtSecretString := string(plainTxtSecret)
		fmt.Println(plainTxtSecretString)
	}
}
