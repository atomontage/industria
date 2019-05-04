#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2019 Göran Weinholt <goran@weinholt.se>
;; SPDX-License-Identifier: MIT
#!r6rs

(import
  (industria bytevectors)
  (industria crypto eddsa)
  (industria base64)
  (srfi :64 testing)
  (rnrs))

;;; Section 7 of RFC8032

(define (test secret public msg sig)
  (let* ((secret (uint->bytevector secret (endianness big) 32))
         (key (make-ed25519-private-key secret))
         (public (uint->bytevector public (endianness big) 32))
         (pubkey (make-ed25519-public-key public))
         (sig (uint->bytevector sig (endianness big) 64))
         (bad-sig (make-bytevector 64 0)))
    (test-equal public (ed25519-public-key-value (ed25519-private->public key)))
    (test-equal sig (ed25519-sign key msg))
    (test-assert (ed25519-verify pubkey msg sig))
    (test-assert (not (ed25519-verify pubkey msg bad-sig)))))

(test-begin "ed25519-rfc8032-test1")
(let ((secret #x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60)
      (public #xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a)
      (msg #vu8())
      (sig #xe5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b))
  (test secret public msg sig))
(test-end)

(test-begin "ed25519-rfc8032-test2")
(let ((secret #x4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb)
      (public #x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c)
      (msg #vu8(#x72))
      (sig #x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00))
  (test secret public msg sig))
(test-end)

(test-begin "ed25519-rfc8032-test3")
(let ((secret #xc5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7)
      (public #xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025)
      (msg #vu8(#xaf #x82))
      (sig #x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a))
  (test secret public msg sig))
(test-end)

(test-begin "ed25519-rfc8032-test1024")
(let ((secret #xf5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5)
      (public #x278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e)
      (msg #vu8(#x08 #xb8 #xb2 #xb7 #x33 #x42 #x42 #x43 #x76 #x0f #xe4 #x26 #xa4 #xb5 #x49 #x08
                #x63 #x21 #x10 #xa6 #x6c #x2f #x65 #x91 #xea #xbd #x33 #x45 #xe3 #xe4 #xeb #x98
                #xfa #x6e #x26 #x4b #xf0 #x9e #xfe #x12 #xee #x50 #xf8 #xf5 #x4e #x9f #x77 #xb1
                #xe3 #x55 #xf6 #xc5 #x05 #x44 #xe2 #x3f #xb1 #x43 #x3d #xdf #x73 #xbe #x84 #xd8
                #x79 #xde #x7c #x00 #x46 #xdc #x49 #x96 #xd9 #xe7 #x73 #xf4 #xbc #x9e #xfe #x57
                #x38 #x82 #x9a #xdb #x26 #xc8 #x1b #x37 #xc9 #x3a #x1b #x27 #x0b #x20 #x32 #x9d
                #x65 #x86 #x75 #xfc #x6e #xa5 #x34 #xe0 #x81 #x0a #x44 #x32 #x82 #x6b #xf5 #x8c
                #x94 #x1e #xfb #x65 #xd5 #x7a #x33 #x8b #xbd #x2e #x26 #x64 #x0f #x89 #xff #xbc
                #x1a #x85 #x8e #xfc #xb8 #x55 #x0e #xe3 #xa5 #xe1 #x99 #x8b #xd1 #x77 #xe9 #x3a
                #x73 #x63 #xc3 #x44 #xfe #x6b #x19 #x9e #xe5 #xd0 #x2e #x82 #xd5 #x22 #xc4 #xfe
                #xba #x15 #x45 #x2f #x80 #x28 #x8a #x82 #x1a #x57 #x91 #x16 #xec #x6d #xad #x2b
                #x3b #x31 #x0d #xa9 #x03 #x40 #x1a #xa6 #x21 #x00 #xab #x5d #x1a #x36 #x55 #x3e
                #x06 #x20 #x3b #x33 #x89 #x0c #xc9 #xb8 #x32 #xf7 #x9e #xf8 #x05 #x60 #xcc #xb9
                #xa3 #x9c #xe7 #x67 #x96 #x7e #xd6 #x28 #xc6 #xad #x57 #x3c #xb1 #x16 #xdb #xef
                #xef #xd7 #x54 #x99 #xda #x96 #xbd #x68 #xa8 #xa9 #x7b #x92 #x8a #x8b #xbc #x10
                #x3b #x66 #x21 #xfc #xde #x2b #xec #xa1 #x23 #x1d #x20 #x6b #xe6 #xcd #x9e #xc7
                #xaf #xf6 #xf6 #xc9 #x4f #xcd #x72 #x04 #xed #x34 #x55 #xc6 #x8c #x83 #xf4 #xa4
                #x1d #xa4 #xaf #x2b #x74 #xef #x5c #x53 #xf1 #xd8 #xac #x70 #xbd #xcb #x7e #xd1
                #x85 #xce #x81 #xbd #x84 #x35 #x9d #x44 #x25 #x4d #x95 #x62 #x9e #x98 #x55 #xa9
                #x4a #x7c #x19 #x58 #xd1 #xf8 #xad #xa5 #xd0 #x53 #x2e #xd8 #xa5 #xaa #x3f #xb2
                #xd1 #x7b #xa7 #x0e #xb6 #x24 #x8e #x59 #x4e #x1a #x22 #x97 #xac #xbb #xb3 #x9d
                #x50 #x2f #x1a #x8c #x6e #xb6 #xf1 #xce #x22 #xb3 #xde #x1a #x1f #x40 #xcc #x24
                #x55 #x41 #x19 #xa8 #x31 #xa9 #xaa #xd6 #x07 #x9c #xad #x88 #x42 #x5d #xe6 #xbd
                #xe1 #xa9 #x18 #x7e #xbb #x60 #x92 #xcf #x67 #xbf #x2b #x13 #xfd #x65 #xf2 #x70
                #x88 #xd7 #x8b #x7e #x88 #x3c #x87 #x59 #xd2 #xc4 #xf5 #xc6 #x5a #xdb #x75 #x53
                #x87 #x8a #xd5 #x75 #xf9 #xfa #xd8 #x78 #xe8 #x0a #x0c #x9b #xa6 #x3b #xcb #xcc
                #x27 #x32 #xe6 #x94 #x85 #xbb #xc9 #xc9 #x0b #xfb #xd6 #x24 #x81 #xd9 #x08 #x9b
                #xec #xcf #x80 #xcf #xe2 #xdf #x16 #xa2 #xcf #x65 #xbd #x92 #xdd #x59 #x7b #x07
                #x07 #xe0 #x91 #x7a #xf4 #x8b #xbb #x75 #xfe #xd4 #x13 #xd2 #x38 #xf5 #x55 #x5a
                #x7a #x56 #x9d #x80 #xc3 #x41 #x4a #x8d #x08 #x59 #xdc #x65 #xa4 #x61 #x28 #xba
                #xb2 #x7a #xf8 #x7a #x71 #x31 #x4f #x31 #x8c #x78 #x2b #x23 #xeb #xfe #x80 #x8b
                #x82 #xb0 #xce #x26 #x40 #x1d #x2e #x22 #xf0 #x4d #x83 #xd1 #x25 #x5d #xc5 #x1a
                #xdd #xd3 #xb7 #x5a #x2b #x1a #xe0 #x78 #x45 #x04 #xdf #x54 #x3a #xf8 #x96 #x9b
                #xe3 #xea #x70 #x82 #xff #x7f #xc9 #x88 #x8c #x14 #x4d #xa2 #xaf #x58 #x42 #x9e
                #xc9 #x60 #x31 #xdb #xca #xd3 #xda #xd9 #xaf #x0d #xcb #xaa #xaf #x26 #x8c #xb8
                #xfc #xff #xea #xd9 #x4f #x3c #x7c #xa4 #x95 #xe0 #x56 #xa9 #xb4 #x7a #xcd #xb7
                #x51 #xfb #x73 #xe6 #x66 #xc6 #xc6 #x55 #xad #xe8 #x29 #x72 #x97 #xd0 #x7a #xd1
                #xba #x5e #x43 #xf1 #xbc #xa3 #x23 #x01 #x65 #x13 #x39 #xe2 #x29 #x04 #xcc #x8c
                #x42 #xf5 #x8c #x30 #xc0 #x4a #xaf #xdb #x03 #x8d #xda #x08 #x47 #xdd #x98 #x8d
                #xcd #xa6 #xf3 #xbf #xd1 #x5c #x4b #x4c #x45 #x25 #x00 #x4a #xa0 #x6e #xef #xf8
                #xca #x61 #x78 #x3a #xac #xec #x57 #xfb #x3d #x1f #x92 #xb0 #xfe #x2f #xd1 #xa8
                #x5f #x67 #x24 #x51 #x7b #x65 #xe6 #x14 #xad #x68 #x08 #xd6 #xf6 #xee #x34 #xdf
                #xf7 #x31 #x0f #xdc #x82 #xae #xbf #xd9 #x04 #xb0 #x1e #x1d #xc5 #x4b #x29 #x27
                #x09 #x4b #x2d #xb6 #x8d #x6f #x90 #x3b #x68 #x40 #x1a #xde #xbf #x5a #x7e #x08
                #xd7 #x8f #xf4 #xef #x5d #x63 #x65 #x3a #x65 #x04 #x0c #xf9 #xbf #xd4 #xac #xa7
                #x98 #x4a #x74 #xd3 #x71 #x45 #x98 #x67 #x80 #xfc #x0b #x16 #xac #x45 #x16 #x49
                #xde #x61 #x88 #xa7 #xdb #xdf #x19 #x1f #x64 #xb5 #xfc #x5e #x2a #xb4 #x7b #x57
                #xf7 #xf7 #x27 #x6c #xd4 #x19 #xc1 #x7a #x3c #xa8 #xe1 #xb9 #x39 #xae #x49 #xe4
                #x88 #xac #xba #x6b #x96 #x56 #x10 #xb5 #x48 #x01 #x09 #xc8 #xb1 #x7b #x80 #xe1
                #xb7 #xb7 #x50 #xdf #xc7 #x59 #x8d #x5d #x50 #x11 #xfd #x2d #xcc #x56 #x00 #xa3
                #x2e #xf5 #xb5 #x2a #x1e #xcc #x82 #x0e #x30 #x8a #xa3 #x42 #x72 #x1a #xac #x09
                #x43 #xbf #x66 #x86 #xb6 #x4b #x25 #x79 #x37 #x65 #x04 #xcc #xc4 #x93 #xd9 #x7e
                #x6a #xed #x3f #xb0 #xf9 #xcd #x71 #xa4 #x3d #xd4 #x97 #xf0 #x1f #x17 #xc0 #xe2
                #xcb #x37 #x97 #xaa #x2a #x2f #x25 #x66 #x56 #x16 #x8e #x6c #x49 #x6a #xfc #x5f
                #xb9 #x32 #x46 #xf6 #xb1 #x11 #x63 #x98 #xa3 #x46 #xf1 #xa6 #x41 #xf3 #xb0 #x41
                #xe9 #x89 #xf7 #x91 #x4f #x90 #xcc #x2c #x7f #xff #x35 #x78 #x76 #xe5 #x06 #xb5
                #x0d #x33 #x4b #xa7 #x7c #x22 #x5b #xc3 #x07 #xba #x53 #x71 #x52 #xf3 #xf1 #x61
                #x0e #x4e #xaf #xe5 #x95 #xf6 #xd9 #xd9 #x0d #x11 #xfa #xa9 #x33 #xa1 #x5e #xf1
                #x36 #x95 #x46 #x86 #x8a #x7f #x3a #x45 #xa9 #x67 #x68 #xd4 #x0f #xd9 #xd0 #x34
                #x12 #xc0 #x91 #xc6 #x31 #x5c #xf4 #xfd #xe7 #xcb #x68 #x60 #x69 #x37 #x38 #x0d
                #xb2 #xea #xaa #x70 #x7b #x4c #x41 #x85 #xc3 #x2e #xdd #xcd #xd3 #x06 #x70 #x5e
                #x4d #xc1 #xff #xc8 #x72 #xee #xee #x47 #x5a #x64 #xdf #xac #x86 #xab #xa4 #x1c
                #x06 #x18 #x98 #x3f #x87 #x41 #xc5 #xef #x68 #xd3 #xa1 #x01 #xe8 #xa3 #xb8 #xca
                #xc6 #x0c #x90 #x5c #x15 #xfc #x91 #x08 #x40 #xb9 #x4c #x00 #xa0 #xb9 #xd0))
      (sig #x0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03))
  (test secret public msg sig))
(test-end)

(test-begin "ed25519-rfc8032-sha-abc")
(let ((secret #x833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42)
      (public #xec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf)
      (msg #vu8(#xdd #xaf #x35 #xa1 #x93 #x61 #x7a #xba #xcc #x41 #x73 #x49 #xae #x20 #x41 #x31
                #x12 #xe6 #xfa #x4e #x89 #xa9 #x7e #xa2 #x0a #x9e #xee #xe6 #x4b #x55 #xd3 #x9a
                #x21 #x92 #x99 #x2a #x27 #x4f #xc1 #xa8 #x36 #xba #x3c #x23 #xa3 #xfe #xeb #xbd
                #x45 #x4d #x44 #x23 #x64 #x3c #xe8 #x0e #x2a #x9a #xc9 #x4f #xa5 #x4c #xa4 #x9f))
      (sig #xdc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704))
  (test secret public msg sig))
(test-end)

;; RFC 8410
(test-begin "ed25519-x509")

(let ((key-bv (base64-decode
               "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC")))
  (test-assert (eddsa-private-key-from-bytevector key-bv)))

(let-values ([(_ key-bv)
              (get-delimited-base64 (open-string-input-port
                                     "
-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----
"))])
  (test-assert (eddsa-private-key-from-bytevector key-bv)))
(test-end)

(let* ((key-bv (base64-decode
                "MC4CAQAwBQYDK2VwBCIEIMXP7muEznG1QOjramAKvMe4noISM/YEXmOrGRcuQEix"))
       (key (eddsa-private-key-from-bytevector key-bv)))
  ;; openssl genpkey -algorithm ed25519 -outform PEM -out test25519.pem
  ;; openssl pkey -inform PEM -in test25519.pem -text -noout
  (test-assert (ed25519-private-key? key))
  (test-equal #vu8(#xae #x43 #x02 #x56 #x10 #x04 #x3a #x68 #x24 #xe1 #xce #x20 #x19 #xa6 #x8e
                   #x75 #x1c #x5f #xde #x75 #x1b #xc3 #xc1 #xd0 #xef #xe9 #xbd #x6d #x37 #xa8
                   #xa5 #x56)
              (ed25519-public-key-value (ed25519-private->public key))))

(exit (if (zero? (test-runner-fail-count (test-runner-get))) 0 1))
