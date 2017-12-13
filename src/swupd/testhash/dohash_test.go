package main

import (
	"os"
	"syscall"
	"testing"
)

const (
	Dir  = 0040000
	Reg  = 0100000
	Link = 0120000
)

func TestGenHash(t *testing.T) {
	testCases := []struct {
		info   syscall.Stat_t
		data   []byte
		result string
	}{
		{syscall.Stat_t{Mode: (Dir + 0755)},
			[]byte("DIRECTORY"), directoyhash},
		{syscall.Stat_t{Mode: (Dir + 01777)},
			[]byte("DIRECTORY"), "d93a5e9129361e28b9e244fe422234e3a1794b001a082aeb78e16fd881673a2b"},
		{syscall.Stat_t{Mode: Reg + 0644, Uid: 1000, Gid: 1000},
			[]byte(""), "b85f1dc2c2317a20f47a36d3257313b131124ffa6d4f19bb060d43014fd386b0"},
	}

	for _, tc := range testCases {
		r := genHash(tc.info, tc.data)
		if r != tc.result {
			t.Errorf("Unexpected result %s for %v", r, tc)
		}
	}
}

const (
	// hash for a rwxr-xr-x root owned directory
	directoyhash = "6c27df6efcd6fc401ff1bc67c970b83eef115f6473db4fb9d57e5de317eba96e"
	missinghash  = ""
)

func TestHashcalc(t *testing.T) {
	testCases := []struct {
		filename string
		result   string
	}{
		{"/", directoyhash},
		{"/does not exist", missinghash},
		{"/usr", directoyhash},
		{"/usr/share/doc/systemd/LICENSE.GPL2", "d9d34a1e44f3684286dd07c6a9e1747a1307e4421cd5d70f71a548c446a9ca54"},
		{"/dev/null", ""},
	}

	for _, tc := range testCases {
		r, _ := Hashcalc(tc.filename)
		if r != tc.result {
			t.Errorf("Expected %s for hash of %s, got %s", tc.result, tc.filename, r)
		}
	}

	// test cases for files which may or may not exist
	testCases = []struct {
		filename string
		result   string
	}{
		{"/etc/protocols", "cfc5cc64ea94da67920936286d5f37152a46bbf908d383fc5d50d0ecde2ddc3e"},
		{"/usr/share/defaults/etc/protocols", "cfc5cc64ea94da67920936286d5f37152a46bbf908d383fc5d50d0ecde2ddc3e"},
	}
	for _, tc := range testCases {
		if _, err := os.Stat(tc.filename); os.IsNotExist(err) {
			continue
		}
		r, _ := Hashcalc(tc.filename)
		if r != tc.result {
			t.Errorf("Expected %s for hash of %s, got %s", tc.result, tc.filename, r)
		}
	}

}
