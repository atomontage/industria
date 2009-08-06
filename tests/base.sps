#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009 Göran Weinholt <goran@weinholt.se>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
#!r6rs

(import (weinholt text base64)
        (srfi :78 lightweight-testing)
        (rnrs))

(define (string->base64 x)
  (base64-encode (string->utf8 x)))

;; From RFC 4658

(check (string->base64 "") => "")

(check (string->base64 "f") => "Zg==")

(check (string->base64 "fo") => "Zm8=")

(check (string->base64 "foo") => "Zm9v")

(check (string->base64 "foob") => "Zm9vYg==")

(check (string->base64 "fooba") => "Zm9vYmE=")

(check (string->base64 "foobar") => "Zm9vYmFy")

;; ad-hoc

(define (base64-linewrapped str)
  (let-values (((bv) (string->utf8 str))
               ((p extract) (open-string-output-port)))
    (base64-encode bv p 0 (bytevector-length bv) 76 #f base64-alphabet)
    (extract)))

(check (base64-linewrapped
        "My name is Ozymandias, king of kings:\n\
         Look on my works, ye Mighty, and despair!")
       =>
       "TXkgbmFtZSBpcyBPenltYW5kaWFzLCBraW5nIG9mIGtpbmdzOgpMb29rIG9uIG15IHdvcmtzLCB5\n\
        ZSBNaWdodHksIGFuZCBkZXNwYWlyIQ==")

;; ascii armor

(let-values (((p extract) (open-string-output-port))
             ((str) "Crusoe's Law: With every new C++ standard, its syntax\n\
                     asymptotically approaches that of a PERL regex."))
  (put-delimited-base64 p "TEST" (string->utf8 str))
  (let-values (((type str*) (get-delimited-base64 (open-string-input-port
                                                   (string-append
                                                    "This is garbage\n"
                                                    (extract))))))
    (check type => "TEST")
    (check (utf8->string str*) => str)))

(check-report)