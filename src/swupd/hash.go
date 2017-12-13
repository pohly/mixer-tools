// Copyright 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package swupd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/sys/unix"
)

type hashval int

var AllZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hashes is a global map of indices to hashes
var Hashes = []*string{&AllZeroHash}
var invHash = map[string]hashval{AllZeroHash: 0}

// internHash adds only new hashes to the Hashes slice and returns the index at
// which they are located
func internHash(hash string) hashval {
	if key, ok := invHash[hash]; ok {
		return key
	}
	Hashes = append(Hashes, &hash)
	key := hashval(len(Hashes) - 1)
	invHash[hash] = key
	return key
}

func (h hashval) String() string {
	return *Hashes[int(h)]
}

// HashEquals trivial equality function for hashval
func HashEquals(h1 hashval, h2 hashval) bool {
	return h1 == h2
}

func Hashcalc(filename string) string {
	key, err := hmac_compute_key(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stating file '%s' %v\n", filename, err)
		return ""
	}
	// Only handle files for now..
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error for '%s' %v\n", filename, err)
		return ""
	}
	result := hmac_sha256_for_data(key, data)
	return string(result[:])
}

// hmac_sha256_for_data returns an ascii string of hex digits
func hmac_sha256_for_data(key []byte, data []byte) []byte {
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

// return what should be an ascii string as an array of byte
func hmac_compute_key(filename string) ([]byte, error) {
	// Create the key
	updatestat := [40]byte{}
	var info unix.Stat_t
	if err := unix.Stat(filename, &info); err != nil {
		return nil, err
	}
	set(updatestat[24:32], 0)
	set(updatestat[0:8], int64(info.Mode))
	set(updatestat[8:16], int64(info.Uid))
	set(updatestat[16:24], int64(info.Gid))
	// 24:32 is rdev, but this is always zero
	set(updatestat[32:40], int64(info.Size))
	// fmt.Printf("key is %v\n", updatestat)
	key := hmac_sha256_for_data(updatestat[:], nil)
	return key, nil
}
