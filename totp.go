// Google Authenticator (TOTP) implementation in Go
// https://ru.wikipedia.org/wiki/Google_Authenticator 

package main

import "os"
import "fmt"
import "strings"
import "encoding/base32"
import "encoding/binary"
import "crypto/sha1"
import "crypto/hmac"
import "time"
import "bytes"


func main() {
	// decode secret from base32
	var secret string = os.Args[1]
	secret = strings.ReplaceAll(secret, " ", "")
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// calc number intervals
	var intervals uint64 = uint64(time.Now().Unix() / 30)
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, intervals)

	// get HMAC-SHA1 hash
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	hash := mac.Sum(nil)

	offset := hash[19] & 15

	// 4 bytes starting at the offset
	truncatedHash := hash[offset:offset+4]

	// unpack bytest into unsigned integer
	bbb := []byte(truncatedHash)
	buf := bytes.NewBuffer(bbb)
	var truncated_offset_int uint32
	err = binary.Read(buf, binary.BigEndian, &truncated_offset_int)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Set the first bit of truncatedHash to zero
	result := (truncated_offset_int & 0x7fffffff) % 1000000

	fmt.Println(result)
}