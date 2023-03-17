package client

import (
	"crypto/hmac"
	"crypto/md5"
	"time"

	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
)

type CtAuth struct {
	EncryptKey string `yaml:"encrypt_key"`
	AccessKey  string `yaml:"access_key"`
}

func (ca CtAuth) NeedCtAuth() bool {
	return ca.EncryptKey != "" && ca.AccessKey != ""
}

func (ca CtAuth) GenCtAuthHeader(method string, uri string, contentType string) map[string]string {
	rs := make(map[string]string)

	curTime := time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	akMd5Str := fmt.Sprintf("%x", md5.Sum([]byte(ca.AccessKey)))
	ak := base64.StdEncoding.EncodeToString([]byte(akMd5Str))
	h := hmac.New(func() hash.Hash { return sha256.New() }, []byte(ca.EncryptKey))
	_, err := io.WriteString(h, ak)
	if err != nil {
		fmt.Println("err encode ctcdn api.")
		return rs
	}
	sk := base64.StdEncoding.EncodeToString(h.Sum(nil))

	rs["Date"] = curTime
	signStr := fmt.Sprintf("%s\n\n%s\n%s\n%s", method, contentType, curTime, uri)
	h1 := hmac.New(func() hash.Hash { return sha256.New() }, []byte(sk))
	_, err = io.WriteString(h1, signStr)
	if err != nil {
		fmt.Println("err encode ctcdn api.")
		return rs
	}
	signature := base64.StdEncoding.EncodeToString(h1.Sum(nil))

	rs["authorization"] = fmt.Sprintf("CTYUN %s:%s", ca.AccessKey, signature)
	rs["content-type"] = contentType
	return rs
}
