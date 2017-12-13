package swupd

import (
	"os"
	"testing"
)

func TestCreateFileFromPath(t *testing.T) {
	Hashes = []*string{}
	invHash = make(map[string]hashval)
	path := "testdata/manifest.good"
	expected := File{
		Name: path,
		Type: typeFile,
	}

	var fh string
	var err error
	fh = Hashcalc(expected.Name)

	if err = expected.setHash(fh); err != nil {
		t.Fatal(err)
	}

	m := Manifest{}
	var fi os.FileInfo
	if fi, err = os.Lstat(path); err != nil {
		t.Fatal(err)
	}

	err = m.createFileRecord(path, fi, nil)
	if err != nil {
		t.Error(err)
	}

	newFile := m.Files[0]
	if newFile.Name != expected.Name ||
		newFile.Type != expected.Type ||
		!HashEquals(newFile.Hash, expected.Hash) {
		t.Error("created File did not match expected")
	}
}

func TestAddFilesFromChroot(t *testing.T) {
	rootPath := "testdata/testbundle"
	m := Manifest{}
	if err := m.addFilesFromChroot(rootPath); err != nil {
		t.Error(err)
	}

	if len(m.Files) == 0 {
		t.Error("No files added from chroot")
	}
}

func TestAddFilesFromChrootNotExist(t *testing.T) {
	rootPath := "testdata/nowhere"
	m := Manifest{}
	if err := m.addFilesFromChroot(rootPath); err == nil {
		t.Errorf("addFilesFromChroot did not fail on missing root")
	}
}

func TestExists(t *testing.T) {
	if !exists("testdata/manifest.good") {
		t.Error("exists() did not return true for existing file")
	}

	if exists("testdata/nowhere") {
		t.Error("exists() returned true for non-existant file")
	}
}

func TestDirExistsWithPerm(t *testing.T) {
	testCases := []struct {
		testname string
		name     string
		perm     os.FileMode
		expected bool
	}{
		{"valid", "testdata", 0755, true},
		{"nonexistent", "nowhere", 0755, false},
		{"badperm", "testdata", 0700, false},
	}

	for _, tc := range testCases {
		t.Run(tc.testname, func(t *testing.T) {
			if dirExistsWithPerm(tc.name, tc.perm) != tc.expected {
				t.Errorf("dirExistsWithPerm returned %v when %v expected",
					exists, tc.expected)
			}
		})
	}
}
