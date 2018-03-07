// Copyright 2018 Lothar . All rights reserved.
// https://github.com/Blockchain-CN

package keygen

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"path"
)

// Signature 通过用户名获取公钥、私钥,返回的公钥和加密结果都是经过base64编码的,pb:公钥md5，c:加密签名md5
func Signature(user string, data []byte) (pb, c string, err error) {
	pvKeyPath := path.Join(GetUserPath(user), "private.pem")
	pbKeyPath := path.Join(GetUserPath(user), "public.pem")
	pvKey, err := getKey(pvKeyPath)
	if err != nil {
		return
	}
	pbKey, err := getKey(pbKeyPath)
	if err != nil {
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(pvKey)
	if err != nil {
		return
	}
	hashMD5 := md5.New()
	hashMD5.Write(data)
	Digest := hashMD5.Sum(nil)
	ciphertext, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.MD5, Digest)
	pb = base64.StdEncoding.EncodeToString(pbKey)
	c = base64.StdEncoding.EncodeToString(ciphertext)
	return
}

// Signature2 直接输入私钥返回签名,结果都是经过base64编码的,pv:私钥md5, c:加密签名md5
func Signature2(pv string, data []byte) (c string, err error) {
	pvKey, err := base64.StdEncoding.DecodeString(pv)
	if err != nil {
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(pvKey)
	if err != nil {
		return
	}
	hashMD5 := md5.New()
	hashMD5.Write(data)
	Digest := hashMD5.Sum(nil)
	ciphertext, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.MD5, Digest)
	return base64.StdEncoding.EncodeToString(ciphertext), err
}

// Verify 验证发布信息属否有效 pb:公钥md5，c:加密签名md5
func Verify(pb, c string, data []byte) error {
	pbKey, err := base64.StdEncoding.DecodeString(pb)
	if err != nil {
		return err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return err
	}
	pubv, err := x509.ParsePKIXPublicKey(pbKey)
	if err != nil {
		return err
	}
	pub := pubv.(*rsa.PublicKey)
	hashMD5 := md5.New()
	hashMD5.Write(data)
	Digest := hashMD5.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, crypto.MD5, Digest, ciphertext)
}
