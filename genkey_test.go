package keygen

import (
	"encoding/base64"
	"fmt"
	"log"
	"path"
	"testing"
)

func TestGenFilder(t *testing.T) {
	p, err := genFilder("111")
	if err != nil {
		println(err.Error())
	}
	println(p)
	// Output: keypool/111
}

func TestGenRsaKey(t *testing.T) {
	bits := 1024
	if err := GenRsaKey(bits, "路达"); err != nil {
		log.Fatal("fail密钥文件生成失败！", err)
	}
	log.Println("密钥文件生成成功！")
	// Output: 2018/01/23 10:37:48 密钥文件生成成功！
}

func TestSignature(t *testing.T) {
	pub, ciphertext, err := Signature("路达", []byte("向优格特转账1000000"))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	fmt.Println(string(pub))
	fmt.Println(ciphertext)
	// Output: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsQ7el11/SLdEe2XWCJzdRXBsKRqTLfV9oOghF6gv9OI32KzJFADaTExWChADIeJgwr9CgTivgY7iduLc/TdSb1zh57gIApyNmBtavW5B5w/Nb3OP4aAQs3CZy50Y3pkzeinLpoPY4v8/bM2bQHGBuAk+9hLnW6wKKkDrthL+CQwIDAQAB
	// Output: Vp+XWdLJZ1QYy+0j6HtTca9VvOzGJ70g3fQauPp78mmaLNX7L+mGJDYoM0DF5SG+PdPR1crUB14p9Yww+JPaY7nKouhcFvg8odMDXZ+9gExlwH+DvruEJH4O2h6bv4oxSisgvlT1fXqu9TuicUBgKeppC1mcE11nPxJ1jaOZAUQ=
}

func TestVerify(t *testing.T) {
	data := "向优格特转账1000000"
	pb, ciphertext, err := Signature("路达", []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	pbKey, err := base64.StdEncoding.DecodeString(pb)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	pbKey = pbKey[:]
	pb = base64.StdEncoding.EncodeToString(pbKey)
	err = Verify(pb, ciphertext, []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	// Output: pass
}

func TestGetKeyMd5(t *testing.T) {
	pvKeyPath := path.Join(GetUserPath("路达"), "private.pem")
	pbKeyPath := path.Join(GetUserPath("路达"), "public.pem")
	pv, err := GetKeyMd5(pvKeyPath)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	println("私钥：", pv)
	pb, err := GetKeyMd5(pbKeyPath)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	println("公钥：", pb)
	// Output: 私钥： MIICXQIBAAKBgQCsQ7el11/SLdEe2XWCJzdRXBsKRqTLfV9oOghF6gv9OI32KzJFADaTExWChADIeJgwr9CgTivgY7iduLc/TdSb1zh57gIApyNmBtavW5B5w/Nb3OP4aAQs3CZy50Y3pkzeinLpoPY4v8/bM2bQHGBuAk+9hLnW6wKKkDrthL+CQwIDAQABAoGAfk4YdSx5QW3+ipP/KLMASFM0MFCju9/s+Eq0ji6RI9U3oWsCrLz/Rs8TUmLfAB4L2IbQfPlUCm6TinFJSs0SOQ1cBZ4ub0xxGue4ejBhw53hBMvTCE5ozF0jkPakPv35ciLM1V0VvKehGuL2bunK8C1Aqoh6NQfoMimVGl8Dh6ECQQDau31QGwArYTVxgRZ66LLxKETQ8j9k9kkRLoGlQDBrxQWeaJ/MPtYfljkawM5JaIy45OvQOSB+XlykTOVMFT29AkEAyZ1tKnFyWZ4NE3kXAiJPgl10s2E3m8HyVmFqvGFrT6Aef6lpQNluBQNinNmnNjNC3YpRHOtG8HBMmVBbm5O//wJBALU9Cz130fEfz+envZfD/plh83tqbmraw3pQHa5ufHCfxOMX7+iN3GA52kE3pvYeghOl41saKrlquLqO2KPtKcUCQA66xaL4LtaFSYdGrXumbhCkK0Z/r8RdYwsUiuvAYkqq9A93nQzz1angGXBEJoc7L4Nn+40VU1V1nuMEj+zJ2pkCQQCE0qJYkk7KokCUYqR3dy8MiaWzurb5+4UaVrgja7cWMrw/waRDNdSU4iLSB6Mdc0kUT+ZQEPaZbyL40B0BDywb
	// Output: 公钥： MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsQ7el11/SLdEe2XWCJzdRXBsKRqTLfV9oOghF6gv9OI32KzJFADaTExWChADIeJgwr9CgTivgY7iduLc/TdSb1zh57gIApyNmBtavW5B5w/Nb3OP4aAQs3CZy50Y3pkzeinLpoPY4v8/bM2bQHGBuAk+9hLnW6wKKkDrthL+CQwIDAQAB

}

func TestVerify2(t *testing.T) {
	data := "向优格特转账1000000"
	pv, err := GetKeyMd5(path.Join(GetUserPath("路达"), "private.pem"))
	ciphertext, err := Signature2(pv, []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	pb, err := GetKeyMd5(path.Join(GetUserPath("路达"), "public.pem"))
	pbKey, err := base64.StdEncoding.DecodeString(pb)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	pbKey = pbKey[:]
	pb2 := base64.StdEncoding.EncodeToString(pbKey)
	err = Verify(pb2, ciphertext, []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	// Output: pass
}
