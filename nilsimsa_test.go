package nilsimsa

import (
	"testing"
	"fmt"
	"io"
)

// tests the nilsimsa hash by choosing a random test file
// computes the nilsimsa digest and compares to the true
// value stored in the pickled sid_to_nil dictionary
func TestNilsimsa(t *testing.T) {
	x := HexSum([]byte{})
	if x != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf(x)
	}

	x = HexSum([]byte("abcdefgh"))
	if x != "14c8118000000000030800000004042004189020001308014088003280000078" {
		t.Fatalf(x)
	}

	// Doing it the long way using incremental update
	d := New()
	io.WriteString(d, "abcd")
	io.WriteString(d, "efgh")
	x = fmt.Sprintf("%x", d.Sum(nil))
	if x != "14c8118000000000030800000004042004189020001308014088003280000078" {
		t.Fatalf(x)
	}

	io.WriteString(d, "ijk")
	x = fmt.Sprintf("%x", d.Sum(nil))
	if x != "14c811840010000c0328200108040630041890200217582d4098103280000078" {
		t.Fatalf(x)
	}

	digest1 := Sum([]byte("abcdefghijk"))
	digest2 := Sum([]byte("abcdefgh"))
	bitsDiff := BitsDiff(&digest1, &digest2)
	if bitsDiff != 109 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}

	d.Reset()
	io.WriteString(d, "abcdefghijk")
	s1 := d.Sum(nil)
	d.Reset()
	io.WriteString(d, "abcdefgh")
	s2 := d.Sum(nil)
	bitsDiff = BitsDiffSlice(s1, s2)
	if bitsDiff != 109 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}

	x1 := HexSum([]byte("abcdefghijk"))
	x2 := HexSum([]byte("abcdefgh"))
	bitsDiff = BitsDiffHex(x1, x2)
	if bitsDiff != 109 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}

	x1 = HexSum([]byte("return diff.NewSequenceMatcherFromFiles" +
		"(srcPath, dstPath)"))
	x2 = HexSum([]byte("return diff.NewSequenceMatcherFromFiles" +
		"(dstPath, srcPath)"))
	if x1 != "8beb55d08d78fed441ede9301390b49b716a11af3962db70b24540338cb70035"{
		t.Fatalf(x1)
	}
	if x2 != "8a5355d09968f8d451efeb309919949b73e211af7952c970f245403b8cb7a035"{
		t.Fatalf(x2)
	}
	bitsDiff = BitsDiffHex(x1, x2)
	if bitsDiff != 96 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}

	x1 = HexSum([]byte("return diff.XYZ"))
	x2 = HexSum([]byte("return diff.NewSequenceMatcherFromFiles" +
		"(dstPath, srcPath)"))
	if x1 != "84125570884ae840f042ea400400009a721891002011a071225247f7a5241018"{
		t.Fatalf(x1)
	}
	if x2 != "8a5355d09968f8d451efeb309919949b73e211af7952c970f245403b8cb7a035"{
		t.Fatalf(x2)
	}
	bitsDiff = BitsDiffHex(x1, x2)
	if bitsDiff != 35 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}

	digest1 = Sum([]byte("C.setTabChangeCallbackWrapper(h.ih())"))
	digest2 = Sum([]byte("C.setTabChangeCallbackWrapper(ih)"))
	bitsDiff = BitsDiff(&digest1, &digest2)
	if bitsDiff != 40 {
		t.Fatalf("bitsDiff(%d)", bitsDiff)
	}
}

func TestNilsimsa2(t *testing.T) {
	nilsimsaJavaimplementation := `
package com.weblyzard.lib.string.nilsimsa;

import java.util.*;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Computes the Nilsimsa hash for the given string.
 * @author Albert Weichselbraun <albert.weichselbraun@htwchur.ch>
 *                              <weichselbraun@weblyzard.com>
 *
 * This class is a translation of the Python implementation by Michael Itz
 * to the Java language <http://code.google.com/p/py-nilsimsa>.
 *
 * Original C nilsimsa-0.2.4 implementation by cmeclax:
 * <http://ixazon.dynip.com/~cmeclax/nilsimsa.html>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 dated June, 2007.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */
public class Nilsimsa {

    private int count    = 0;            // num characters seen
    private int[] acc    = new int[256]; // accumulators for the digest
    private int[] lastch = new int[4];   // the last four seen characters

    // pre-defined transformation arrays
    private static final byte[] TRAN = Nilsimsa._getByteArray(
        "02D69E6FF91D04ABD022161FD873A1AC" +
        "3B7062961E6E8F399D05144AA6BEAE0E" +
        "CFB99C9AC76813E12DA4EB518D646B50" +
        "23800341ECBB71CC7A867F98F2365EEE" +
        "8ECE4FB832B65F59DC1B314C7BF06301" +
        "6CBA07E81277493CDA46FE2F791C9B30" +
        "E300067E2E0F383321ADA554CAA729FC" +
        "5A47697DC595B5F40B90A3816D255535" +
        "F575740A26BF195C1AC6FF995D84AA66" +
        "3EAF78B32043C1ED24EAE63F18F3A042" +
        "57085360C3C0834082D709BD442A67A8" +
        "93E0C2569FD9DD8515B48A27289276DE" +
        "EFF8B2B7C93D45944B110D65D5348B91" +
        "0CFA87E97C5BB14DE5D4CB10A21789BC" +
        "DBB0E2978852F748D3612C3A2BD18CFB" +
        "F1CDE46AE7A9FDC437C8D2F6DF58724E");

    // pre-defined array for the computation of the bitwise difference
    // between two nilsimsa strings.
    private static final byte[] POPC = Nilsimsa._getByteArray(
        "00010102010202030102020302030304" +
        "01020203020303040203030403040405" +
        "01020203020303040203030403040405" +
        "02030304030404050304040504050506" +
        "01020203020303040203030403040405" +
        "02030304030404050304040504050506" +
        "02030304030404050304040504050506" +
        "03040405040505060405050605060607" +
        "01020203020303040203030403040405" +
        "02030304030404050304040504050506" +
        "02030304030404050304040504050506" +
        "03040405040505060405050605060607" +
        "02030304030404050304040504050506" +
        "03040405040505060405050605060607" +
        "03040405040505060405050605060607" +
        "04050506050606070506060706070708");


    public Nilsimsa() {
        reset();
    }

    /**
     * Updates the Nilsimsa digest using the given String
     * @param s: the String data to consider in the update
     */
    public void update(String s)  {
        for (int ch: s.toCharArray()) {
            count ++;
            // incr accumulators for triplets
            if (lastch[1] > -1) {
                acc[ _tran3(ch, lastch[0], lastch[1], 0) ] ++;
            }
        if (lastch[2] > -1) {
            acc[ _tran3(ch, lastch[0], lastch[2], 1)] ++;
            acc[ _tran3(ch, lastch[1], lastch[2], 2)] ++;
        }
        if (lastch[3] > -1) {
            acc[ _tran3(ch, lastch[0], lastch[3], 3)] ++;
            acc[ _tran3(ch, lastch[1], lastch[3], 4)] ++;
            acc[ _tran3(ch, lastch[2], lastch[3], 5)] ++;
            acc[ _tran3(lastch[3], lastch[0], ch, 6)] ++;
            acc[ _tran3(lastch[3], lastch[2], ch, 7)] ++;
        }
        // adjust lastch
        for(int i=3; i>0; i-- ) {
        lastch[i]=lastch[i-1];
        }
        lastch[0] = ch;
        }
    }

    /**
     * resets the Hash computation
     */
    private void reset() {
        count = 0;
        Arrays.fill(acc, (byte) 0);
        Arrays.fill(lastch, -1);
    }

    /*
     * Converts the given hexString to a byte array.
     * @param hexString: the hexString to convert
     * @return the corresponding byte array
     */
    private static byte[] _getByteArray( String hexString ) {
        try {
            return Hex.decodeHex( hexString.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Accumulator for a transition n between the chars a, b, c
     */
    private int _tran3(int a, int b, int c, int n) {
        int i = (c)^TRAN[n];
        return (((TRAN[(a+n)&255]^TRAN[b&0xff]*(n+n+1))+TRAN[i&0xff])&255);
    }

    /**
     * @return the digest for the current Nilsimsa object.
     */
    public byte[] digest() {
        int total = 0;
        int threshold;
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte)0);

        if (count == 3) {
            total = 1;
        } else if (count == 4) {
            total = 4;
        } else if (count > 4) {
            total = 8 * count - 28;
        }
        threshold = total / 256;

        for (int i=0; i<256; i++) {
            if (acc[i] > threshold) {
                digest[ i>>3 ] += 1 << (i&7);
            }
        }
        ArrayUtils.reverse( digest );
        return digest;
    }

    /**
     * @return a String representation of the current state of
     *      the Nilsimsa object.
     */
    public String hexdigest() {
        return Hex.encodeHexString( digest() );
    }

    /**
     * Compute the Nilsimsa digest for the given String.
     * @param s: the String to hash
     * @return the Nilsimsa digest.
     */
    public byte[] digest(String s) {
        reset();
        update(s);
        return digest();
    }

    /**
     * Compute the Nilsimsa hexDigest for the given String.
     * @param s: the String to hash
     * @return the Nilsimsa hexdigest.
     */

    public String hexdigest(String s) {
        return Hex.encodeHexString( digest(s) );
    }

    /**
     * Compares a Nilsimsa object to the current one and
     * return the number of bits that differ.
     * @param cmp: the comparison object
     * @return the number of bits the strings differ.
     */
    public int compare(Nilsimsa cmp) {
        byte bits = 0;
        int j;
        byte[] n1 = digest();
        byte[] n2 = cmp.digest();

        for (int i=0; i<32; i++) {
            j = 255 & n1[i] ^ n2[i];
            bits += POPC[ j ];
        }
        return 128 - bits;
    }
}
`
	x := HexSum([]byte(nilsimsaJavaimplementation))
	if x != "4c900d44043f014c40f40040d8201000f246227123b28864013040008240204a" {
		t.Fatalf(x)
	}
}


func TestNilsimsa3(t *testing.T) {
    list := [...]string{
        "a",
        "ab",
        "abc",
        "abcd",
        "abcde",
        "abcdef",
        "abcdefg",
        "abcdefgh",
        "abcdefghi",
        "abcdefghij",
        "abcdefghijk",
        "abcdefghijkl",
        "abcdefghijklm",
        "abcdefghijklmn",
        "abcdefghijklmno",
        "abcdefghijklmnop",
        "abcdefghijklmnopq",
        "abcdefghijklmnopqr",
        "abcdefghijklmnopqrs",
        "abcdefghijklmnopqrst",
        "abcdefghijklmnopqrstu",
        "abcdefghijklmnopqrstuv",
        "abcdefghijklmnopqrstuvw",
        "abcdefghijklmnopqrstuvwx",
        "abcdefghijklmnopqrstuvwxy",
        "abcdefghijklmnopqrstuvwxyz",
	}

    results := [...]string{
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0040000000000000000000000000000000000000000000000000000000000000",
        "0440000000000000000000000000000000100000000000000008000000000000",
        "0440008000000000000000000000000000100020001200000008001200000050",
        "04c0018000000000000000000000000004188020001200000088001280000058",
        "04c8118000000000030000000000002004188020001208004088001280000078",
        "14c8118000000000030800000004042004189020001308014088003280000078",
        "14c8118400000000030800010804043004189020021318094098003280000078",
        "14c81184000000000308200108040430041890200217580d4098103280000078",
        "14c811840010000c0328200108040630041890200217582d4098103280000078",
        "14c811840010000ca328200108044630041890200a17586d4298103280000078",
        "14ca11850010000ca328200188044630041898200a17586dc2d8103284000078",
        "14ca11850030004ca3a8200188044630041898200a17586dc2d8107284000078",
        "14ca11850032004ca3a8284188044730041898200a17586dc2d8107384000078",
        "94ca11850432005ca3a828418804473004199c200a17586dc2d8107384004178",
        "94ca11850433005ca3a82841880447341419be200a17586dc2d8107384004178",
        "94ca11850433005ca3a82841a88457341419be201a17586dc6d8107384084178",
        "94ca11850533005ca3b82841a88657361419be201a17586dc6d8107384084178",
        "94ca11850533005ca3b82841aa8657371419be201a17587dc6d81077840c4178",
        "94ca15850533005ca3b92841aa8657371419be201a17587dd6d81077844cc178",
        "94ca15850533005ca3b92849aa8657371419be201a17587fd6d81077844cc978",
        "94ca15850533045cabb92869aa8657371419bea01a17587fd6f81077c44cc978",
        "94ca95850533045cabb93869aa8657371499beb01a17587fd6f8107fc44cc978",
        "94ca95850733045cabb93869aa8657373499beb01a17587fd6f9107fc54cc978",
        "94ca95850773045cabb93869ba8657373499beb81a17587fd6f9107fc54cc978",
	}

    compareResults := [...]byte {
        128,
        127,
        125,
        120,
        120,
        120,
        120,
        120,
        123,
        122,
        122,
        121,
        124,
        123,
        121,
        123,
        122,
        124,
        123,
        123,
        125,
        122,
        123,
        124,
        125,
	}

    step3CompareResults := [...]byte{
        116,
        104,
        109,
        111,
        111,
        113,
        114,
        116,
	}

    if len(list) != len(results) {
		panic("len(list) != len(results)")
	}
    for i, x := range(list) {
        hex := HexSum([]byte(x))
		if hex != results[i] {
			t.Fatalf(hex)
		}
	}

    if len(list) != len(compareResults) + 1 {
		panic("len(list) != len(compareResults) + 1")
	}
    last := Sum([]byte(list[0]))
    for i, x := range list[1:] {
		sum := Sum([]byte(x))
		bits := BitsDiff(&sum, &last)
		if bits != compareResults[i] {
			t.Fatalf("%x", bits)
		}
        last = sum
	}

    j := 0
    last = Sum([]byte(list[0]))
    for i := 4; i < len(list); i += 3 {
		sum := Sum([]byte(list[i]))
		bits := BitsDiff(&sum, &last)
		if bits != step3CompareResults[j] {
			t.Fatalf("%x", bits)
		}
        last = sum
        j += 1
	}
}

