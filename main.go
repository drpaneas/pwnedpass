package main

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// passToHash() encrypts your "password" with SHA-1 and returns it in hex
func passToHash(password string) string {
	hash := sha1.New()                     // Returnes a new hash.Hash computing the SHA1 checksum
	hash.Write([]byte(password))           // `Write` expects bytes
	byteHash := hash.Sum(nil)              // This gets the finalized hash result as a byte slice uint8
	hexHash := fmt.Sprintf("%x", byteHash) // Use the `%x` format verb to convert a hash results to a hex string
	hexHash = strings.ToUpper(hexHash)     // Make the hash upper case
	return hexHash
}

// getPassList() fetches the API response and and error in case of a problem
// Read: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
func getPassList(hash string) ([]string, error) {
	APIURL := fmt.Sprintf("%s%s", "https://api.pwnedpasswords.com/range/", hash)

	// Construct a *http.Request with a GET method against the APIURL
	req, err := http.NewRequest(http.MethodGet, APIURL, nil)
	if err != nil {
		return nil, err
	}

	// Create an HTTP Client to handle this *http.Request
	client := http.DefaultClient

	// Make the actual request using the client and get server's *http.Response
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read only the body part of the *http.Response (as an array of bytes)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := fmt.Sprintf("%#v", string(body)) // Convert bytes into string

	// Split the body string into sub-strings on every carriage return and newline character
	// creating an array of strings (password hashes)
	bodyStrArray := strings.Split(bodyStr, `\r\n`)
	return bodyStrArray, nil
}

// isPwned() checks if your "pass" is included in the "list" of pwned password
// and it returns how many times it has been hacked
func isPwned(list []string, pass string) (bool, string) {
	for _, value := range list {
		if strings.Contains(value, pass) {
			return true, value
		}
	}
	return false, ""
}

func main() {
	password := os.Args[1] // Use the first positional parameter as the password

	// Calculate the SHA-1 hash of your password
	hash := passToHash(password)

	// Query they API using the first 5 characters of it
	passList, err := getPassList(hash[0:5])
	if err != nil {
		log.Fatal(err)
	}

	// Test (locally) if your password is hacked by passing the rest of it
	pwned, result := isPwned(passList, hash[5:])
	if pwned {
		s := strings.Split(result, ":")
		times := s[1] // isolate the part after the ':'
		fmt.Printf("Your password have been PWNED %s times\n", times)
	} else {
		fmt.Printf("You are not PWNED\n")
	}
}
