#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2010, 2018, 2019 Göran Weinholt <goran@weinholt.se>

;; Permission is hereby granted, free of charge, to any person obtaining a
;; copy of this software and associated documentation files (the "Software"),
;; to deal in the Software without restriction, including without limitation
;; the rights to use, copy, modify, merge, publish, distribute, sublicense,
;; and/or sell copies of the Software, and to permit persons to whom the
;; Software is furnished to do so, subject to the following conditions:

;; The above copyright notice and this permission notice shall be included in
;; all copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
;; THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
;; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
;; DEALINGS IN THE SOFTWARE.
#!r6rs

(import (rnrs)
        (srfi :64 testing)
        (industria crypto eddsa)
        (industria crypto dsa)
        (industria crypto entropy)
        (industria ssh algorithms)
        (industria ssh kex-dh-gex) ;to recognize kex-dh-gex-request
        (industria ssh kex-ecdh)   ;to recognize kex-ecdh-init
        (industria ssh kexdh)      ;to recognize kexdh-init
        (industria ssh transport)
        (industria ssh private-keys)
        (industria base64))

(test-begin "ssh-kex")

(define (print . x) (for-each display x) (newline))

(define (parse-dsa-key s)
  (let-values (((type bv) (get-delimited-base64
                           (open-string-input-port s))))
    (dsa-private-key-from-bytevector bv)))

(define (parse-openssh-key s)
  (let ((privkey* (get-ssh-private-keys
                   (open-string-input-port s))))
    (openssh-private-key-private (car privkey*))))

(define server-dsa-key
  (parse-dsa-key
   "-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCsWqA7PlEkryVmODG5kEUyFQX7NydZZ6+NZu33gnRyMRYiEEvc
XQHuwpPS89snjwnkkPhv4RFN+4sLiu+5T0MbZ4qZ/fq7Heec2A4/DK9n8qzSdVBg
6hkNZsB0AQIC/xI+MlYsQ1ZS7mLAPT6m+zjFYo0sbZUJNbGCRX6m/iibrwIVAMk7
LJkmuIKCTyP/a9m21hXYyqJXAoGAPU+js+GrtDB5FRAUWt3Cbrzdcv/Orj6F37on
THG1iYf8FAl6Fj/uxvKasgIYeMgFQhhMKu+p9pRNfAWIYSVuUqtVVsPKc68aEucP
+OcCynJ0V16eb2fGdC3c4yzwHIXeEHM7bkNS/tiLQaace+ogtjrSENd5GquuA3OQ
LbSrAt8CgYBdZc7hocR3mTReopmBZ6V41RDDdK0JYQ4BW0r9nGH20ciH0QbsMf3D
J907A8afiPaxVWzwd326Yeit5VdRiEut32PMRILcbqveGTdhvBD8RJSrDuwW+06P
K2NBpZ7bW3ncxXT0QMNVjvLdHh4+3C4z3PNhOlUIE8fIIBfZxCWv8AIUJlYxaPDf
WAhaSeMnKo/oDbb2ICI=
-----END DSA PRIVATE KEY-----"))

(define server-ed25519-key
  (parse-openssh-key
   "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBlMyd5J2/JAPrA7Mgq3g83ABLSno3C4pZM2em4FEjwQAAAAJjI5ByPyOQc
jwAAAAtzc2gtZWQyNTUxOQAAACBlMyd5J2/JAPrA7Mgq3g83ABLSno3C4pZM2em4FEjwQA
AAAEBQEI+BsPGbatSg6ywmqolDIenx/EFad5V+GLLafT9QumUzJ3knb8kA+sDsyCreDzcA
EtKejcLilkzZ6bgUSPBAAAAAD3dlaW5ob2x0QHRlYXBvdAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----"))

;; The kexinit data is just part of the signed data here
(define (dummy-kexinit client?)
  (call-with-bytevector-output-port
    (lambda (p)
      (put-kexinit p (make-kexinit (make-random-bytevector 16)
                                   '("diffie-hellman-group14-sha1")
                                   '("ssh-dss")
                                   '("aes128-ctr") '("aes128-ctr")
                                   '("hmac-sha1") '("hmac-sha1")
                                   '("none") '("none")
                                   '() '() client? 0)))))
(define dummy-kexinit-client (dummy-kexinit #t))
(define dummy-kexinit-server (dummy-kexinit #f))
(define dummy-init-data (list 'host-key-algorithm "ssh-dss"
                              'V_S (string->utf8 "SSH-2.0-Server")
                              'V_C (string->utf8 "SSH-2.0-Client")
                              'I_C dummy-kexinit-client
                              'I_S dummy-kexinit-server))
(define dummy-init-data/ed25519
  `(host-key-algorithm "ssh-ed25519" ,@(cddr dummy-init-data)))

(define (no-attacker)
  (let ((seen-kexdh-init? #f))
    (lambda (name x)
      (cond ((and (not seen-kexdh-init?)
                  (or (kexdh-init? x)
                      (kex-dh-gex-request? x)
                      (kex-ecdh-init? x)))
             ;; Filter out the first KEX packet
             ;; (print ";; Server ignores " x)
             (set! seen-kexdh-init? #t)
             #f)
            (else x)))))

(define (queue name attacker)
  (let ((q '()))
    (case-lambda
      ((x)
       ;; The "attacker" can be used to simulate an active attacker
       (let ((x* (attacker name x)))
         (when x*
           ;; (print ";; Packet to " name ": " x*)
           (set! q (append q (list (attacker name x)))))))
      (()
       (and (not (null? q))
            (let ((x (car q))) (set! q (cdr q)) x))))))

(define (compare k1 k2)
  (unless (and (list? k1) (list? k2))
    (error 'text-kex "The key exchange did not run to completion"
           k1 k2))
  (let ((key1 (car k1)) (key2 (car k2)))
    (and (or (and (dsa-public-key? key1) (dsa-public-key=? key1 key2))
             (and (ed25519-public-key? key1) (ed25519-public-key=? key1 key2)))
         (equal? (cadr k1) (cadr k2))
         (equal? (caddr k1) (caddr k2)))))

(define (test-kex kexalg server-key attacker)
  ;; TODO: try starting the client twice. this is needed so that
  ;; misguessed KEXes don't require a new dh secret.
  (let* ((cq (queue 'client attacker))
         (sq (queue 'server attacker))
         (client (make-key-exchanger kexalg #t sq))
         (server (make-key-exchanger kexalg #f cq))
         (init-data (if (dsa-private-key? server-key)
                        dummy-init-data
                        dummy-init-data/ed25519)))
    ;; Initialize the client
    (client 'start #f)
    (client 'start #f)                  ;simulate misguessed KEX
    (client 'init init-data)
    ;; Initialize the server
    (server 'start #f)
    (server 'init init-data)
    (server 'private-key server-key)
    ;; Run the server and the client against each other
    (let lp ((cstatus 'c-kex-failed) (sstatus 's-kex-failed))
      (cond ((cq) => (lambda (p)
                       (lp (client 'packet p) sstatus)))
            ((sq) => (lambda (p)
                       (lp cstatus (server 'packet p))))
            (else (compare cstatus sstatus))))))

(test-assert (test-kex "diffie-hellman-group1-sha1" server-dsa-key (no-attacker)))
(test-assert (test-kex "diffie-hellman-group14-sha1" server-dsa-key (no-attacker)))

(test-assert (test-kex "diffie-hellman-group-exchange-sha256" server-dsa-key (no-attacker)))
(test-assert (test-kex "diffie-hellman-group-exchange-sha1" server-dsa-key (no-attacker)))

(test-assert (test-kex "curve25519-sha256@libssh.org" server-dsa-key (no-attacker)))
(test-assert (test-kex "curve25519-sha256@libssh.org" server-ed25519-key (no-attacker)))

(test-end)

(exit (if (zero? (test-runner-fail-count (test-runner-get))) 0 1))
