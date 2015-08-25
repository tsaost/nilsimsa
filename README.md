Package nilsimsa is a Go implemenation of Nilsimsa, ported from
code.google.com/p/py-nilsimsa
but follows the conventions establish by the md5 package in the standard lib

The Java implementaition at 
https://github.com/weblyzard/nilsimsa/
blob/master/src/main/java/com/weblyzard/lib/string/nilsimsa/Nilsimsa.java
was also consulted.

There is a discussion about using hash to score string similarities
http://stackoverflow.com/questions/4323977/string-similarity-score-hash


Copyright 2015 Sheng-Te Tsao. All rights reserved.
Use of this source code is governed by the same BSD-style
license that is used by the Go standard library


From http://en.wikipedia.org/wiki/Nilsimsa_Hash

Nilsimsa is an anti-spam focused locality-sensitive hashing algorithm
originally proposed the cmeclax remailer operator in 2001[1] and then
reviewed by Damiani et al. in their 2004 paper titled,
"An Open Digest-based Technique for Spam Detection".[2]

The goal of Nilsimsa is to generate a hash digest of an email message such
that the digests of two similar messages are similar to each other.
In comparison with cryptographic hash functions such as SHA-1 or MD5,
making a small modification to a document does not substantially change
the resulting hash of the document. The paper suggests that the Nilsimsa
satisfies three requirements:

 1. The digest identifying each message should not vary significantly (sic)
	for changes that can be produced automatically.
 2. The encoding must be robust against intentional attacks.
 3. The encoding should support an extremely low risk of false positives.

Subsequent testing[3] on a range of file types identified the Nilsimsa hash
as having a significantly higher false positive rate when compared to other
similarity digest schemes such as TLSH, Ssdeep and Sdhash.

Nilsimsa similarity matching was taken in consideration by Jesse Kornblum
when developing the fuzzy hashing in 2006,[4] that used the algorithms of
spamsum by Andrew Tridgell (2002).[5]

References:

[1] http://web.archive.org/web/20050707005338/
	   http://ixazon.dynip.com/~cmeclax/nilsimsa-0.2.4.tar.gz
[2] http://spdp.di.unimi.it/papers/pdcs04.pdf
[3] https://www.academia.edu/7833902/TLSH_-A_Locality_Sensitive_Hash
[4] http://jessekornblum.livejournal.com/242493.html
[5] http://dfrws.org/2006/proceedings/12-Kornblum.pdf


From  http://blog.semanticlab.net/tag/nilsimsa/

An Open Digest-based Technique for Spam Detection

Damiani, E. et al., 2004. An Open Digest-based Technique for Spam Detection. 
In in Proceedings of the 2004 International Workshop on Security
in Parallel and Distributed Systems. pp. 15-17.
	
Summary

This paper discusses the Nilsimsa open digest hash algorithm which is
frequently used for Spam detection. The authors describe the computation of
the 32-byte code, discuss different attack scenarios and measures to
counter them.
	
Digest computation

 1. Slide a five character window through the input text and compute all
    eight possible tri-grams for each window (e.g. "igram" yields "igr",
    "gra", "ram", "ira", "iam", "grm", ...)

 2. Hash these trigrams using a hash function h() which maps every tri-gram
    to one of 256 accumulators and increment the corresponding
    accumulator. Nilsimsa uses the Trans53 hash function for hashing.
	 
 3. At the end of the process described below, compute the expected value
    of the accumulators and set the bits which correspond to each accumulator 
	either to (1) if it exceeds this threshold or (o) otherwise.

Similarity computation

The Nilsimsa similarity is computed based on the bitwise difference between
two Nilsimsa hashes. Documents are considered similar if they exceed a
pre-defined similarity value.

 1. >24 similar bits - conflict probability: 1.35E-4
	(suggestions by Nilsimsa's original designer)

 2. >54 similar bits - conflict probability: 7.39E-12
    (suggested by the article's authors)

Attacks

Spammers can apply multiple techniques to prevent Nilsimsa from detecting
duplicates:

 1. Random addition: requires >300% of additional text to prevent detection.
 2. Thesaurus substitutions: require >20% of replaced text
 3. Perceptive substitution (security > s3cur1ty): requires >15%
	of the text to be altered
 4. Aimed attacks (i.e. attacks which specifically target Nilsimsa):
	~10% of the text needs to be altered

Aimed attacks manipulate Nilsimsa's accumulators by adding words which
introduce new tri-grams that specifically alter the hash value. Although
these attacks are relatively effective, they can be easily circumvented by
computing the Nilsimsa hash twice with different hash functions.
