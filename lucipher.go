	/*
	Author: code34 nicolas_boiteux@yahoo.fr
	Copyright (C) 2017-2018 Nicolas BOITEUX

	LUCIPHER - RC34 Command line tool to cipher / uncipher file
	
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>. 
	*/

	package main

	import "io/ioutil"
	import "encoding/hex"
	import "rc34"
	import "bytes"
	import "flag"
	import "os"
	import "fmt"

	func check(e error) {
	    if e != nil {
	        panic(e)
	        os.Exit(-1)
	    }
	}

	func cipher(passPtr string, srcPtr string, dstPtr string) {
		dat, err := ioutil.ReadFile(srcPtr)
		check (err)
		dat = bytes.Trim(dat, "\xef\xbb\xbf")
		key := []byte(passPtr)
		newkey, err := rc34.NewCipher(key)
		check (err)
		newkey.XorKeyStreamGeneric(dat,dat)
		newfile := []byte(hex.EncodeToString(dat))
		ioutil.WriteFile(dstPtr, newfile , 0777)
		newkey.Reset()
	}

	func uncipher(passPtr string, srcPtr string, dstPtr string) {
		dat, err := ioutil.ReadFile(srcPtr)
		check (err)
		dst := make([]byte, hex.DecodedLen(len(dat)))
		hex.Decode(dst,dat)
		key := []byte(passPtr)
		newkey, err := rc34.NewCipher(key)
		check (err)
		newkey.XorKeyStreamGeneric(dst,dst)
		newfile := []byte(dst)
		ioutil.WriteFile(dstPtr, newfile , 0777)
		newkey.Reset()
	}

	func version() {
		fmt.Printf("LUCIPHER v 0.1 - github.com/code34")
		os.Exit(0)
	}

	func main() {
		passPtr := flag.String("p", "", "Passphrase from 1 to 256 Bytes")
		srcPtr := flag.String("s", "", "Source file")
		dstPtr := flag.String("d", "", "Destination file")
		uncipherPtr := flag.Bool("u", false, "Uncipher a file")
		versionPtr := flag.Bool("v", false, "Version")
		flag.Parse()

		keylen := len(*passPtr)
		if keylen > 256 { os.Exit(-1) }
		if *versionPtr { version() }

		if *uncipherPtr {
			uncipher(*passPtr, *srcPtr, *dstPtr)
		} else {
			cipher(*passPtr, *srcPtr, *dstPtr)
		}
	}