;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2019 Göran Weinholt <goran@weinholt.se>
;; SPDX-License-Identifier: MIT
#!r6rs

;; Procedures that read and write SSH private keys

(library (industria ssh private-keys)
  (export
    get-ssh-private-key)
  (import
    (rnrs (6))
    (industria base64)
    (industria crypto dsa)
    (industria crypto ec)
    (industria crypto ecdsa)
    (industria crypto eddsa)
    (industria crypto rsa))

(define (get-ssh-private-key p)
  (let-values (((type data) (get-delimited-base64 p)))
    (cond ((string=? type "DSA PRIVATE KEY")
           (dsa-private-key-from-bytevector data))
          ((string=? type "RSA PRIVATE KEY")
           (rsa-private-key-from-bytevector data))
          ((string=? type "EC PRIVATE KEY")
           (ecdsa-sha-2-private-key-from-bytevector data))
          ((string=? type "OPENSSH PRIVATE KEY")
           (openssh-private-key-from-bytevector data))
          (else
           (error 'get-ssh-private-key "Unsupported key type" type p)))))

;; Read an OpenSSH private key. Needed for Ed25519 keys. OpenSSH
;; private keys are documented in the OpenSSH source distribution, in
;; PROTOCOL.key.
(define (openssh-private-key-from-bytevector data)
  (error 'openssh-private-key-from-bytevector
         "Not implemented"))

)
