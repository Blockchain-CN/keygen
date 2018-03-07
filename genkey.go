// Copyright 2018 Blockchain-CN . All rights reserved.
// https://github.com/Blockchain-CN

package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

var basicPath string

func init() {
	basicPath = "./"
}

// GenRsaKey 生成Rsa密钥
func GenRsaKey(bits int, user string) error {
	p, err := genFilder(user)
	if err != nil {
		return err
	}
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	pvk := path.Join(p, "private.pem")
	file, err := os.Create(pvk)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	pbk := path.Join(p, "public.pem")
	file, err = os.Create(pbk)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func genFilder(user string, basePath ...string) (string, error) {
	for _, v := range basePath {
		basicPath = v
	}
	userPath := GetUserPath(user)
	return userPath, os.MkdirAll(userPath, os.ModePerm)
}

// getKey 获取密钥[]byte
func getKey(p string) ([]byte, error) {
	privateKey, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	return block.Bytes, nil
}

//GetKeyMd5 get the key-file, input the key-file's path
func GetKeyMd5(p string) (s string, err error) {
	key, err := getKey(p)
	if err != nil {
		return
	}
	s = base64.StdEncoding.EncodeToString(key)
	return
}

//GetUserPath Get user's basic path by using the name
func GetUserPath(user string) string {
	return path.Join(basicPath, "keypool", user)
}
