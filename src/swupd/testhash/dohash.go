// Hack to generate swupd hashes, without xattrs.
//
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s name1 name2 ...\n", os.Args[0])
		return
	}
	if len(os.Args) == 2 {
		r, err := Hashcalc(os.Args[1])
		if err != nil {
			fmt.Printf("%s\n", r)
		} else {
			fmt.Fprintf(os.Stderr, "Error %s for %s\n", err, os.Args[1])
		}
	} else {
		for _, filename := range os.Args[1:] {
			r, err := Hashcalc(filename)
			if err != nil {
				fmt.Printf("%s\t%s\n", filename, r)
			} else {
				fmt.Fprintf(os.Stderr, "Error %s for %s\n", err, filename)
			}
		}
	}
}

// Hashcalc returns the swupd hash for the given file
func Hashcalc(filename string) (string, error) {
	var info syscall.Stat_t
	var err error
	var data []byte
	if err = syscall.Lstat(filename, &info); err != nil {
		return "", fmt.Errorf("Error stating file '%s' %v\n", filename, err)
	}
	// Get magic constants out of /usr/include/bits/stat.h
	switch info.Mode & 0170000 {
	case 0100000: // Regular file
		data, err = ioutil.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("Read error for '%s' %v\n", filename, err)
		}
	case 0040000: // Directory
		info.Size = 0
		data = []byte("DIRECTORY") // fixed magic string
	case 0120000:
		info.Mode = 0
		target, err := os.Readlink(filename)
		if err != nil {
			return "", fmt.Errorf("Error readlink file '%s' %v\n", filename, err)
		}
		data = []byte(target)
	default:
		return "", fmt.Errorf("%s is not a file, directory or symlink %o", filename, info.Mode&0170000)
	}
	r := genHash(info, data)
	return r, nil
}

// genHash generates hash string from butchered Stat_t and data
// Expects that its callers have validated the arguments
func genHash(info syscall.Stat_t, data []byte) string {
	key := hmacComputeKey(info)
	result := hmacSha256ForData(key, data)
	return string(result[:])
}

// hmacSha256ForData returns an array of 64 ascii hex digits
func hmacSha256ForData(key []byte, data []byte) []byte {
	var result [64]byte

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	hex.Encode(result[:], mac.Sum(nil))
	return result[:]
}

// This is what I want to have for the key
// type updatestat struct {
// 	st_mode uint64
// 	st_uid  uint64
// 	st_gid  uint64
// 	st_rdev uint64
// 	st_size uint64
// }

// set fills in a buffer with an int in little endian order
func set(out []byte, in int64) {
	for i := range out {
		out[i] = byte(in & 0xff)
		in >>= 8
	}
}

// hmacComputeKey returns what should be an ascii string as an array of byte
// it is really ugly to be compatible with the C implementation. It is not portable
// as the C version isn't portable.
// The syscall.Stat_t has been butchered
func hmacComputeKey(info syscall.Stat_t) []byte {
	// Create the key
	updatestat := [40]byte{}
	set(updatestat[0:8], int64(info.Mode))
	set(updatestat[8:16], int64(info.Uid))
	set(updatestat[16:24], int64(info.Gid))
	// 24:32 is rdev, but this is always zero
	set(updatestat[24:32], 0)
	set(updatestat[32:40], info.Size)
	// fmt.Printf("key is %v\n", updatestat)
	key := hmacSha256ForData(updatestat[:], nil)
	return key
}
