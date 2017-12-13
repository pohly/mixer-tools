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
	"fmt"
	"os"
	"path/filepath"
)

// createFileRecord creates a manifest File entry from a file
// this function sets the Name, Info, Type, and Hash fields
// the Version field is additionally set using the global toVersion variable
func (m *Manifest) createFileRecord(root string, fi os.FileInfo, err error) error {
	var file *File
	file = &File{
		Name: root,
		Info: fi,
	}

	var fh string
	switch mode := fi.Mode(); {
	case mode.IsRegular():
		file.Type = typeFile
		fh = Hashcalc(file.Name)
	case mode.IsDir():
		file.Type = typeDirectory
		fh = "19cb945a2ce72a00335960767c100f27cbdf0e7e58664ae24e856870be117ccd"
	case mode&os.ModeSymlink != 0:
		file.Type = typeLink
		fh = Hashcalc(file.Name)
	default:
		return fmt.Errorf("%v is an unsupported file type", file.Name)
	}

	if err = file.setHash(fh); err != nil {
		return err
	}

	m.Files = append(m.Files, file)

	return nil
}

func (m *Manifest) addFilesFromChroot(rootPath string) error {
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		return err
	}

	if err := filepath.Walk(rootPath, m.createFileRecord); err != nil {
		return err
	}

	return nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

func dirExistsWithPerm(path string, perm os.FileMode) bool {
	var err error
	var info os.FileInfo
	if info, err = os.Stat(path); err != nil {
		// assume it doesn't exist here
		return false
	}

	// check if it is a directory or the perms don't match
	if !info.Mode().IsDir() || info.Mode().Perm() != perm {
		return false
	}

	return true
}
