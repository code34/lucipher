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
	import "fmt"
	import "bytes"
	import "flag"

	func check(e error) {
	    if e != nil {
	        panic(e)
	    }
	}

	func main() {
		passPtr := flag.String("p", "", "Passphrase from 1 to 256 Bytes")
		srcPtr := flag.String("s", "", "Source file")
		dstPtr := flag.String("d", "", "Destination file")
		cipherPtr := flag.Bool("uncipher", false, "Uncipher a file")

		flag.Parse()

		dat, err := ioutil.ReadFile(*srcPtr)
		check (err)

		if !*cipherPtr {
			hex.Decode(dat,dat)
		} 

		dat = bytes.Trim(dat, "\xef\xbb\xbf")
		fmt.Printf("%d \n", dat)
		key := []byte(*passPtr)

		newkey, err := rc34.NewCipher(key)
		check (err)

		newkey.XorKeyStreamGeneric(dat,dat)
		
		if *cipherPtr {
			newfile := []byte(hex.EncodeToString(dat))
			ioutil.WriteFile(*dstPtr, newfile , 0777)
		} else {
			newfile := []byte(dat)
			ioutil.WriteFile(*dstPtr, newfile , 0777)
		}
		newkey.Reset()
	}