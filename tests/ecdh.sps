#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2019 Göran Weinholt <goran@weinholt.se>
;; SPDX-License-Identifier: MIT
#!r6rs

(import
  (rnrs (6))
  (industria bytevectors)
  (industria crypto ecdh)
  (srfi :64 testing))

;; Tests from RFC 7748
(test-begin "ecdh-x25519_x448")

(test-equal
 (uint->bytevector #xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552)
 (X25519 (uint->bytevector #xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4)
         (uint->bytevector #xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c)))

(test-equal
 (uint->bytevector #x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957)
 (X25519 (uint->bytevector #x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d)
         (uint->bytevector #xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493)))

(test-equal
 (uint->bytevector #xce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f)
 (X448 (uint->bytevector #x3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3)
       (uint->bytevector #x06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086)))

(test-equal
 (uint->bytevector #x884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d)
 (X448 (uint->bytevector #x203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f)
       (uint->bytevector #x0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db)))

(let ()
  (define (loop-test f init n)
    (do ((i 0 (+ i 1))
         (k init (f k u))
         (u init k))
        ((fx=? i n) k)))
  (let ((init (uint->bytevector #x0900000000000000000000000000000000000000000000000000000000000000)))
    (test-equal (uint->bytevector #x422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079)
                (loop-test X25519 init 1))
    #;
    (test-equal (uint->bytevector #x684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51)
                (loop-test X25519 init 1000))
    #;
    (test-equal (uint->bytevector #x7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424)
                (loop-test X25519 init 1000000)))
  (let ((init (uint->bytevector #x0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)))
    (test-equal (uint->bytevector #x3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113)
                (loop-test X448 init 1))
    #;
    (test-equal (uint->bytevector #xaa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38)
                (loop-test X448 init 1000))
    #;
    (test-equal (uint->bytevector #x077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37)
                (loop-test X25519 init 1000000))))

(test-end)

(test-begin "ecdh")

(let ((test-a #x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a)
      (test-K_A #x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a)
      (test-b #x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb)
      (test-K_B #xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f)
      (test-K #x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742))
  (let ((K (ecdh-curve25519 (uint->bytevector test-a)
                            (uint->bytevector test-K_B))))
    (test-equal (uint->bytevector test-K) K))
  (let ((K (ecdh-curve25519 (uint->bytevector test-b)
                            (uint->bytevector test-K_A))))
    (test-equal (uint->bytevector test-K) K)))

(let ((test-a #x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b)
      (test-K_A #x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0)
      (test-b #x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d)
      (test-K_B #x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609)
      (test-K #x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d))
  (let ((K (ecdh-curve448 (uint->bytevector test-a)
                          (uint->bytevector test-K_B))))
    (test-equal (uint->bytevector test-K) K))
  (let ((K (ecdh-curve448 (uint->bytevector test-b)
                          (uint->bytevector test-K_A))))
    (test-equal (uint->bytevector test-K) K)))

(let-values ([(a K_A) (make-ecdh-curve25519-secret)]
             [(b K_B) (make-ecdh-curve25519-secret)])
  (test-equal (ecdh-curve25519 a K_B)
              (ecdh-curve25519 b K_A)))

(test-end)

(exit (if (zero? (test-runner-fail-count (test-runner-get))) 0 1))
