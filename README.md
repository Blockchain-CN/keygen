# keygen
Asymmetric encryption algorithm impliment.
使用rsa生成公钥和私钥，使用私钥进行信息签名，公钥验证结果
``` go
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5.
func SignPKCS1v15(rand io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error)

// VerifyPKCS1v15 verifies an RSA PKCS#1 v1.5 signature.
func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
```

## rsa生成算法
原生rsa "crypto/rsa"

## 函数功能
#### 用户注册函数
在keypool目录下注册一个${user}文件夹,并在其中生成公钥、私钥
``` go
func GenRsaKey(bits int, user string) error

// 使用
GenRsaKey(bits, "路达")
```

#### 获取密钥md5
通过用户获得用户目录，并根据目录，获取其中文件的密钥md5，公钥私钥都可以
``` go
func GetUserPath(user string) string
func GetKeyMd5(p string) (s string, err error)

// 使用
pbKeyPath := path.Join(GetUserPath("路达"), "public.pem")
pb, err:= GetKeyMd5(pbKeyPath)
```

#### 用户数据签名
根据用户名／或者直接输入私钥进行数据签名
``` go
func Signature(user string, data []byte) (pb, c string, err error) 
func Signature2(pv string, data []byte) (c string, err error) 

// 使用1
pb, ciphertext, err := Signature("路达", []byte("向优格特转账1000000"))
// 使用2
pv, err:= GetKeyMd5(path.Join(GetUserPath("路达"), "private.pem"))
pb, err:= GetKeyMd5(path.Join(GetUserPath("路达"), "public.pem"))
ciphertext, err := Signature2(pv, []byte("向优格特转账1000000"))
```

#### 用户数据验证
根据用户id(公钥)进行${签名}到${传输数据}的验证
``` go
func Verify(pb, c string, data []byte) error

// 使用
err := Verify(pb, ciphertext, []byte("向优格特转账1000000"))
```
