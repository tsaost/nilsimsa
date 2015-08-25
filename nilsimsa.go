// Package nilsimsa is a Go implemenation of Nilsimsa, ported from
// code.google.com/p/py-nilsimsa
// but follows the conventions establish by the md5 package in the standard lib
// 
// The Java implementaition at 
// https://github.com/weblyzard/nilsimsa/
// blob/master/src/main/java/com/weblyzard/lib/string/nilsimsa/Nilsimsa.java
// was also consulted.
//
// There is a discussion about using hash to score string similarities
// http://stackoverflow.com/questions/4323977/string-similarity-score-hash
//
//
// Copyright 2015 Sheng-Te Tsao. All rights reserved.
// Use of this source code is governed by the same BSD-style
// license that is used by the Go standard library
// 
// 
// From http://en.wikipedia.org/wiki/Nilsimsa_Hash
// 
// Nilsimsa is an anti-spam focused locality-sensitive hashing algorithm
// originally proposed the cmeclax remailer operator in 2001[1] and then
// reviewed by Damiani et al. in their 2004 paper titled,
// "An Open Digest-based Technique for Spam Detection".[2]
// 
// The goal of Nilsimsa is to generate a hash digest of an email message such
// that the digests of two similar messages are similar to each other.
// In comparison with cryptographic hash functions such as SHA-1 or MD5,
// making a small modification to a document does not substantially change
// the resulting hash of the document. The paper suggests that the Nilsimsa
// satisfies three requirements:
// 
//  1. The digest identifying each message should not vary significantly (sic)
// 	for changes that can be produced automatically.
//  2. The encoding must be robust against intentional attacks.
//  3. The encoding should support an extremely low risk of false positives.
// 
// Subsequent testing[3] on a range of file types identified the Nilsimsa hash
// as having a significantly higher false positive rate when compared to other
// similarity digest schemes such as TLSH, Ssdeep and Sdhash.
// 
// Nilsimsa similarity matching was taken in consideration by Jesse Kornblum
// when developing the fuzzy hashing in 2006,[4] that used the algorithms of
// spamsum by Andrew Tridgell (2002).[5]
// 
// References:
// 
// [1] http://web.archive.org/web/20050707005338/
//	   http://ixazon.dynip.com/~cmeclax/nilsimsa-0.2.4.tar.gz
// [2] http://spdp.di.unimi.it/papers/pdcs04.pdf
// [3] https://www.academia.edu/7833902/TLSH_-A_Locality_Sensitive_Hash
// [4] http://jessekornblum.livejournal.com/242493.html
// [5] http://dfrws.org/2006/proceedings/12-Kornblum.pdf
// 
// 
// From  http://blog.semanticlab.net/tag/nilsimsa/
// 
// An Open Digest-based Technique for Spam Detection
// 
// Damiani, E. et al., 2004. An Open Digest-based Technique for Spam Detection. 
// In in Proceedings of the 2004 International Workshop on Security
// in Parallel and Distributed Systems. pp. 15-17.
// 	
// Summary
// 
// This paper discusses the Nilsimsa open digest hash algorithm which is
// frequently used for Spam detection. The authors describe the computation of
// the 32-byte code, discuss different attack scenarios and measures to
// counter them.
// 	
// Digest computation
// 
//  1. Slide a five character window through the input text and compute all
//     eight possible tri-grams for each window (e.g. "igram" yields "igr",
//     "gra", "ram", "ira", "iam", "grm", ...)
// 
//  2. Hash these trigrams using a hash function h() which maps every tri-gram
//     to one of 256 accumulators and increment the corresponding
//     accumulator. Nilsimsa uses the Trans53 hash function for hashing.
// 	 
//  3. At the end of the process described below, compute the expected value
//     of the accumulators and set the bits which correspond to each accumulator 
// 	either to (1) if it exceeds this threshold or (o) otherwise.
// 
// Similarity computation
// 
// The Nilsimsa similarity is computed based on the bitwise difference between
// two Nilsimsa hashes. Documents are considered similar if they exceed a
// pre-defined similarity value.
// 
//  1. >24 similar bits - conflict probability: 1.35E-4
// 	(suggestions by Nilsimsa's original designer)
// 
//  2. >54 similar bits - conflict probability: 7.39E-12
//     (suggested by the article's authors)
// 
// Attacks
// 
// Spammers can apply multiple techniques to prevent Nilsimsa from detecting
// duplicates:
// 
//  1. Random addition: requires >300% of additional text to prevent detection.
//  2. Thesaurus substitutions: require >20% of replaced text
//  3. Perceptive substitution (security > s3cur1ty): requires >15%
// 	of the text to be altered
//  4. Aimed attacks (i.e. attacks which specifically target Nilsimsa):
// 	~10% of the text needs to be altered
// 
// Aimed attacks manipulate Nilsimsa's accumulators by adding words which
// introduce new tri-grams that specifically alter the hash value. Although
// these attacks are relatively effective, they can be easily circumvented by
// computing the Nilsimsa hash twice with different hash functions.
package nilsimsa

import (
	"strconv"
	"fmt"
	"hash"
)

// The size of an Nilsimsa hash in bytes.
const Size = 32

// The blocksize of Nilsimsa in bytes (not sure what values is best...?)
const BlockSize = 8


type digest struct {
	count int           // number of characters that we have come across
	acc [256]int        // 256-bit vector to hold the results of the digest
    c0, c1, c2, c3 byte // last 4 characters from previous call to Write
}

// New create a new Nilsimsa hash diget
func New() hash.Hash {
	d := new(digest)
	// Note that no memory is allocate other than the struct itself.
	// It is better to embedd last4Array into the struct itself since
	// it's maximum size is know already
//	d.last4  = d.last4Array[:0] //creating the slice by re-slicing last4Array
	return d
}

func (d *digest) Reset() {
	// It is probably faster to just call New() again rather than to
	// re-use an existing struct by calling New() because presumably
	// the compiler does a better job of zeroing the whole struct than
	// doing the manual zeroing via copy(d.acc, zero)
	d.count = 0
//	d.last4 = d.last4[:0] // Re-slice to reset size to 0 but reuse the storage
    copy(d.acc[:], zero)  // resumably faster than re-allocation?
}

var zero = make([]int, 256)

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Sum(in []byte) []byte {
	digest := ComputeDigest(&d.acc, d.count)
	return append(in, digest[:]...)
}

// ComputeDigest uses a threshold (mean of the accumulator)
// to computes the Nilsimsa digest 
func ComputeDigest(acc *[256]int, count int) [Size]byte {
	trigrams := 0
	if count == 3 {
		trigrams = 1
	} else if count == 4 {
		trigrams = 4
	} else if count > 4 {  // > 4 chars -> 8 for each char
		trigrams = 8 * count - 28
	}
	// threshhold is the mean of the acc buckets
	threshold := trigrams / 256

	var digest [Size]byte
	for i := uint(0); i < 256; i++ {
		if acc[i] > threshold {
			digest[i >> 3] += 1 << (i & 7) // equivalent to i/8, 2**(i mod 7)
		}
	}
	// Reverse the digest
	for i, j := 0, 31; i < j; i++ {
        digest[i], digest[j] = digest[j], digest[i]
		j--
    }
	return digest
}

// Update the Nilsimsa accumulator with the data contained in
// chunk using a 5 bytes sliding window.
//
// In general it is easier to just use Sum(data []byte)
func Update(chunk []byte, count int, c0, c1, c2, c3 byte,
	acc *[256]int) (int, byte, byte, byte, byte) {
	for _, c4 := range chunk {
		count++
		if count > 4 { // seen at least 5, so have full 5 bytes window
			// These and c4 form the 5 bytes sliding window
            acc[tran53(c4, c0, c1, 0)]++
			acc[tran53(c4, c0, c2, 1)]++
			acc[tran53(c4, c1, c2, 2)]++
			acc[tran53(c4, c0, c3, 3)]++
			acc[tran53(c4, c1, c3, 4)]++
			acc[tran53(c4, c2, c3, 5)]++
			// duplicate hashes, used to maintain 8 trigrams per character
			acc[tran53(c3, c0, c4, 6)]++
			acc[tran53(c3, c2, c4, 7)]++
			// Drop off c3 and put c4 at the front of the sliding window
			c0, c1, c2, c3 = c4, c0, c1, c2
		} else if count > 3 { // seen at least 4 bytes
			acc[tran53(c4, c0, c1, 0)]++
			acc[tran53(c4, c0, c2, 1)]++
			acc[tran53(c4, c1, c2, 2)]++
			c0, c1, c2, c3 = c4, c0, c1, c2
		} else if count > 2 { // seen at least 3 bytes
			acc[tran53(c4, c0, c1, 0)]++
			c0, c1, c2 = c4, c0, c1
		} else if count > 1 {
			c0, c1 = c4, c0
		} else {
			c0 = c4
		}
	}

	// Return the slinding window which should be save by the caller.
	// It ok to save values that have not been set because they will not be
	// used due to check for counter > x inside the loop
	return count, c0, c1, c2, c3
}


/* This version is obsolete after the introduction of the Update() function
   following the pattern used in package hash/crc32
func Sum(data []byte) [Size]byte {
	// There is no need to allocate on the heap using array := [4]byte and
	// then create the slice using last4 := array[:] because this is
	// done by the compiler automatically through escape analysis
	// http://grokbase.com/t/gg/golang-nuts/142cqce51f/
	// go-nuts-allocation-optimization-stack-vs-heap
	//
	// last4 := make([]byte, 0, 4)
	// acc := [256]int
	// count, _ := update(data, 0, acc, last4)
	//
	// Now that both accArray and last4Array are embedded into digest struct
	// there is reason not to use New() directly and just call Write().
	// Escape analysis should create the digest struct on the stack rather
	// than allocating it on the heap
	d := New()
	d.Write(data)
	return ComputeDigest(&d.acc, d.count)
}
*/

// Write computes the hash of all of the trigrams in the chunk
// using a sliding window of length 5
// 
// It is part of the hash.Hash interface
func (d *digest) Write(chunk []byte) (int, error) {
	// Load up sliding window with values from values set by previous Write.
	// it is ok even if some of the values are not valid because by checking for
	// count > x inside the loop the invalid values are not being used
	d.count, d.c0, d.c1, d.c2, d.c3 = Update(chunk, d.count,
		d.c0, d.c1, d.c2, d.c3, &d.acc)
	return len(chunk), nil
}

// Sum returns the Nilsimsa digest of the data.
// Like Sum() for MD5, it returns [Size]byte by value rather than a slice.
// This way the return value does not need to be allocated on the head
// so there is no garbage collection later.
//
// To use the result as a slice when using it as as a function parameter,
// simply re-slice it using the digist[:] syntax
// See http://blog.golang.org/go-slices-usage-and-internals
// and search for: "slicing" an existing slice or array
func Sum(data []byte) [Size]byte {
	var acc [256]int
	count, _, _, _, _ := Update(data, 0, 0, 0, 0, 0, &acc)
	return ComputeDigest(&acc, count)
}


// HexSum returns the Nilsimsa digest of the data as a hex string
func HexSum(data []byte) string {
	return fmt.Sprintf("%x", Sum(data))
}

var tran = [256]byte {
	0x2,  0xD6, 0x9E, 0x6F, 0xF9, 0x1D, 0x04, 0xAB,
	0xD0, 0x22, 0x16, 0x1F, 0xD8, 0x73, 0xA1, 0xAC,
    0X3B, 0x70, 0x62, 0x96, 0x1E, 0x6E, 0x8F, 0x39,
	0x9D, 0x05, 0x14, 0x4A, 0xA6, 0xBE, 0xAE, 0x0E,
    0XCF, 0xB9, 0x9C, 0x9A, 0xC7, 0x68, 0x13, 0xE1,
	0x2D, 0xA4, 0xEB, 0x51, 0x8D, 0x64, 0x6B, 0x50,
    0X23, 0x80, 0x03, 0x41, 0xEC, 0xBB, 0x71, 0xCC,
	0x7A, 0x86, 0x7F, 0x98, 0xF2, 0x36, 0x5E, 0xEE,
    0X8E, 0xCE, 0x4F, 0xB8, 0x32, 0xB6, 0x5F, 0x59,
	0xDC, 0x1B, 0x31, 0x4C, 0x7B, 0xF0, 0x63, 0x01,
    0X6C, 0xBA, 0x07, 0xE8, 0x12, 0x77, 0x49, 0x3C,
	0xDA, 0x46, 0xFE, 0x2F, 0x79, 0x1C, 0x9B, 0x30,
    0XE3, 0x00, 0x06, 0x7E, 0x2E, 0x0F, 0x38, 0x33,
	0x21, 0xAD, 0xA5, 0x54, 0xCA, 0xA7, 0x29, 0xFC,
    0X5A, 0x47, 0x69, 0x7D, 0xC5, 0x95, 0xB5, 0xF4,
	0x0B, 0x90, 0xA3, 0x81, 0x6D, 0x25, 0x55, 0x35,
    0XF5, 0x75, 0x74, 0x0A, 0x26, 0xBF, 0x19, 0x5C,
	0x1A, 0xC6, 0xFF, 0x99, 0x5D, 0x84, 0xAA, 0x66,
    0X3E, 0xAF, 0x78, 0xB3, 0x20, 0x43, 0xC1, 0xED,
	0x24, 0xEA, 0xE6, 0x3F, 0x18, 0xF3, 0xA0, 0x42,
    0X57, 0x08, 0x53, 0x60, 0xC3, 0xC0, 0x83, 0x40,
	0x82, 0xD7, 0x09, 0xBD, 0x44, 0x2A, 0x67, 0xA8,
    0X93, 0xE0, 0xC2, 0x56, 0x9F, 0xD9, 0xDD, 0x85,
	0x15, 0xB4, 0x8A, 0x27, 0x28, 0x92, 0x76, 0xDE,
    0XEF, 0xF8, 0xB2, 0xB7, 0xC9, 0x3D, 0x45, 0x94,
	0x4B, 0x11, 0x0D, 0x65, 0xD5, 0x34, 0x8B, 0x91,
    0X0C, 0xFA, 0x87, 0xE9, 0x7C, 0x5B, 0xB1, 0x4D,
	0xE5, 0xD4, 0xCB, 0x10, 0xA2, 0x17, 0x89, 0xBC,
    0XDB, 0xB0, 0xE2, 0x97, 0x88, 0x52, 0xF7, 0x48,
	0xD3, 0x61, 0x2C, 0x3A, 0x2B, 0xD1, 0x8C, 0xFB,
    0XF1, 0xCD, 0xE4, 0x6A, 0xE7, 0xA9, 0xFD, 0xC4,
	0x37, 0xC8, 0xD2, 0xF6, 0xDF, 0x58, 0x72, 0x4E,
}

// tran53 implementats the tran53 hash function, which is an
// accumulator for a transition n between the chars a, b, c
func tran53(a, b, c, n byte) byte {
	return ((tran[(a+n) & 0xff]^tran[b]*(n+n+1)) + tran[0xff&c^tran[n]]) & 0xff
}

// Shortcut to compute the Hamming distance between two bit vector
// representations of integers.
//
// popc - population count
// popc[x] = number of 1's in binary representation of x
// popc[a ^b] = hamming distance from a to b
var popc = [256]byte {
    0x00, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x03,
	0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
	0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x06, 0x06, 0x07,
	0x01, 0x02, 0x02, 0x03, 0x02, 0x03, 0x03, 0x04,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x06, 0x06, 0x07,
	0x02, 0x03, 0x03, 0x04, 0x03, 0x04, 0x04, 0x05,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x06, 0x06, 0x07,
	0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x05, 0x06,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x06, 0x06, 0x07,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x06, 0x06, 0x07,
	0x05, 0x06, 0x06, 0x07, 0x06, 0x07, 0x07, 0x08,
}



// BitsDiffSlice compares two Nilsimsa digests slices and
// return the number of bits that differ.
func BitsDiffSlice(n1, n2 []byte) byte {
	var bits byte
	for i := 0; i < Size; i++ {
		bits += popc[0xff & n1[i] ^ n2[i]];
	}
	return 128 - bits;
}

// BitsDiff compares two Nilsimsa digest arrays and
// return the number of bits that differ.
func BitsDiff(n1, n2 *[Size]byte) byte {
	var bits byte
	for i := 0; i < Size; i++ {
		bits += popc[0xff & n1[i] ^ n2[i]];
	}
	return 128 - bits;
}

// BitsDiffHex compares two Nilsimsa digests hex strings and
// return the number of bits that differ 
func BitsDiffHex(n1, n2 string) byte {
	var bits byte
	if len(n1) != Size * 2 {
		panic("len(n1) != 64")
	}
	if len(n2) != 32 * 2 {
		panic("len(n2) != 64")
	}
	for i, j := 0, 2 ; i < Size * 2; j += 2 {
		x, err := strconv.ParseInt(n1[i:j], 16, 16)
		if err != nil {
			panic(err)
		}
		y, err := strconv.ParseInt(n2[i:j], 16, 16)
		if err != nil {
			panic(err)
		}
		bits += popc[0xff & x ^ y];
		i = j
	}
	return 128 - bits;
}
