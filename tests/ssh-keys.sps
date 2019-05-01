#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2019 Göran Weinholt <goran@weinholt.se>
;; SPDX-License-Identifier: MIT
#!r6rs

(import
  (industria base64)
  (industria bytevectors)
  (industria crypto dsa)
  (industria crypto ecdsa)
  (industria crypto eddsa)
  (industria crypto rsa)
  (industria ssh public-keys)
  (industria ssh private-keys)
  (industria strings)
  (srfi :64 testing)
  (rnrs))

(test-begin "ssh-public-key-dsa")
(define test:dsa-private-key
  "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQDO32eujlOk4a+kTW/0VOpfzd6him3yA3+dRWYNaIH5MyWcPVGIdz9XR0E8UVxE
XklBT94UWvAAWRN+8WXdTi3ODXbP3a5kOW5LPhqtLXEAE9u3lsCVLPIzjADwwQ9KQGFge+
5D0ONwCIXigi+iXGqe9ZyNiAfIYRYK8mSjZ9HDwQAAABUAike2Dgbn8lCRu9lPpQjB5uNq
HYsAAACAHElH2BTmVJY6Gjw7DXDveAWFuE1IZYnAZ/jB9dAVfAzsc9XKJOpO1tR4nbGfXZ
Zvyi4W8+xB2NQ95m27BMFTDe72Q3UrsF2081ngZJImot+xnVMFCtwlvjL3VTGKA1kSCVdG
p0E7asLLLxssVDuCiy0sHByyv/7pOx8M5uOgMTIAAACAeHbPoP8cWiEAWzsdL584/pzbUm
q8GC80bj/JW9P9raxIwXQyKRbya1jg9CY+EMHEzjcvA3oKlYce3ytnoI/yY4SyggLfgddy
9b4tm55HfPX/ZRWrA6XeR3tUA1GJ+kMDyUT7fL1h3xbLKptzBiHS9TCQafoWI61lWgiK88
m5MiMAAAHoGIY5qxiGOasAAAAHc3NoLWRzcwAAAIEAzt9nro5TpOGvpE1v9FTqX83eoYpt
8gN/nUVmDWiB+TMlnD1RiHc/V0dBPFFcRF5JQU/eFFrwAFkTfvFl3U4tzg12z92uZDluSz
4arS1xABPbt5bAlSzyM4wA8MEPSkBhYHvuQ9DjcAiF4oIvolxqnvWcjYgHyGEWCvJko2fR
w8EAAAAVAIpHtg4G5/JQkbvZT6UIwebjah2LAAAAgBxJR9gU5lSWOho8Ow1w73gFhbhNSG
WJwGf4wfXQFXwM7HPVyiTqTtbUeJ2xn12Wb8ouFvPsQdjUPeZtuwTBUw3u9kN1K7BdtPNZ
4GSSJqLfsZ1TBQrcJb4y91UxigNZEglXRqdBO2rCyy8bLFQ7gostLBwcsr/+6TsfDObjoD
EyAAAAgHh2z6D/HFohAFs7HS+fOP6c21JqvBgvNG4/yVvT/a2sSMF0MikW8mtY4PQmPhDB
xM43LwN6CpWHHt8rZ6CP8mOEsoIC34HXcvW+LZueR3z1/2UVqwOl3kd7VANRifpDA8lE+3
y9Yd8WyyqbcwYh0vUwkGn6FiOtZVoIivPJuTIjAAAAFELPtbj6IdACmDbIBiBRWI6NHpWh
AAAAD3dlaW5ob2x0QHRlYXBvdAECAwQ=
-----END OPENSSH PRIVATE KEY-----")
(define test:dsa-public-key
  "AAAAB3NzaC1kc3MAAACBAM7fZ66OU6Thr6RNb/RU6l/N3qGKbfIDf51FZg1ogfkzJZw9UYh3P1dHQTxRXEReSUFP3hRa8ABZE37xZd1OLc4Nds/drmQ5bks+Gq0tcQAT27eWwJUs8jOMAPDBD0pAYWB77kPQ43AIheKCL6Jcap71nI2IB8hhFgryZKNn0cPBAAAAFQCKR7YOBufyUJG72U+lCMHm42odiwAAAIAcSUfYFOZUljoaPDsNcO94BYW4TUhlicBn+MH10BV8DOxz1cok6k7W1HidsZ9dlm/KLhbz7EHY1D3mbbsEwVMN7vZDdSuwXbTzWeBkkiai37GdUwUK3CW+MvdVMYoDWRIJV0anQTtqwssvGyxUO4KLLSwcHLK//uk7Hwzm46AxMgAAAIB4ds+g/xxaIQBbOx0vnzj+nNtSarwYLzRuP8lb0/2trEjBdDIpFvJrWOD0Jj4QwcTONy8DegqVhx7fK2egj/JjhLKCAt+B13L1vi2bnkd89f9lFasDpd5He1QDUYn6QwPJRPt8vWHfFssqm3MGIdL1MJBp+hYjrWVaCIrzybkyIw==")
(define test:dsa-fingerprint
  "SHA256:2FmQyHaPI2arc7v6Z0IIO6suQWRRxdxv7eBpp2uMx0o")
(define test:dsa-random-art
  '("+---[DSA 1024]----+"
    "| .o.+o....       |"
    "| o   o+.o.       |"
    "|o    . ..oo      |"
    "| ..   +oo*..     |"
    "|.  o +.oS.+      |"
    "|. o . o  + o     |"
    "| . o o E= o      |"
    "|. . o +.o*       |"
    "|+o  .=+B+..      |"
    "+----[SHA256]-----+"
    ""))
(let ((key (get-ssh-public-key
            (open-bytevector-input-port
             (base64-decode test:dsa-public-key)))))
  (test-assert (dsa-public-key? key))
  (test-equal test:dsa-fingerprint (ssh-public-key-fingerprint key))
  (test-equal test:dsa-random-art
              (string-split (ssh-public-key-random-art key) #\newline))
  (test-equal "ssh-dss" (ssh-public-key-algorithm key))
  (let* ((privkey* (get-ssh-private-keys
                    (open-string-input-port test:dsa-private-key)))
         (pk0 (car privkey*)))
    (test-assert (null? (cdr privkey*)))
    (test-assert (openssh-private-key? pk0))
    (test-equal "weinholt@teapot" (openssh-private-key-comment pk0))
    (test-assert (dsa-public-key=?
                  key (openssh-private-key-public pk0)))
    (test-assert (dsa-public-key=?
                  key (dsa-private->public (openssh-private-key-private pk0))))
    (test-assert
     (let*-values ([(Hm) (make-bytevector 32 0)]
                   [(r s)
                    (dsa-create-signature Hm (openssh-private-key-private pk0))])
       (dsa-verify-signature Hm key r s)))))
(test-end)

(test-begin "ssh-public-key-rsa")
(define test:rsa-private-key
  "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAoPGJ+lCuf06TBgASF0wx97af2IO4iD7NxWh5NOpPg1L4aiV1GqGX
CLVA15Wk5ty2kqD8Rl/zNPfdNqWnc9Thjl9TFqUzfVQuWi7Xv9j7fBuF07OnxDnS92Whce
9RkQu4EC0Tu8xe879CeaYCZ8mYiT5tSr8MgLf/y8U78Q+NHh5Mm0uJNt3SaS/TEpsvu+5a
FDLpTTHrmqQ743d/AzOhxVoupn+iO/OnN9HKa1Nswv6KMLXXubIrS8uiOZVV3eWimaZFKQ
z3eMK1cbsGYDvzZ856Qy6ndi0d3bv3mkxtIfegEP1y5wRgkjHe+zyKKcRPqd9fQHyVnlJq
jtxZ0AfmTQAAA8iqDmYQqg5mEAAAAAdzc2gtcnNhAAABAQCg8Yn6UK5/TpMGABIXTDH3tp
/Yg7iIPs3FaHk06k+DUvhqJXUaoZcItUDXlaTm3LaSoPxGX/M09902padz1OGOX1MWpTN9
VC5aLte/2Pt8G4XTs6fEOdL3ZaFx71GRC7gQLRO7zF7zv0J5pgJnyZiJPm1KvwyAt//LxT
vxD40eHkybS4k23dJpL9MSmy+77loUMulNMeuapDvjd38DM6HFWi6mf6I786c30cprU2zC
/oowtde5sitLy6I5lVXd5aKZpkUpDPd4wrVxuwZgO/NnznpDLqd2LR3du/eaTG0h96AQ/X
LnBGCSMd77PIopxE+p319AfJWeUmqO3FnQB+ZNAAAAAwEAAQAAAQAwOpFlYH4aCjrGpojF
UID8wU4/PKG0ulVBXeBMehafvOJSNK1V8Kxo4J/wupgy0lsnr3RJxoEEE27H7HY0oMuCtZ
AZjiHS4cIOJlFi3Svncfv1h7WzeLx+hIcPtG6V75QVzNxH/6NImbza5WN9JI1AO2PW7U9a
10ihEJa40zcvmd0HCGs8ooVgMlmTiQrIdDhELYn1HsNgfhbE+l8l9FbevWMG82f1lBZpXJ
rQVD89z5Dnhx9FR98+1EfkfBK4spsdmlH/Yh0ihL9TY+vPM55Sce26FlUNrHEJEBzEb4gt
3EaI+PcMCsKl7U1Nj05F7cZkIuHGtsiHwOKxeEYYLMrFAAAAgFNxVKmMJFVgWP6nMoxqZ/
iP5ZHwiLQ08l3FGVlNOAnPmC9hF+JhPg4Q5YJzNm+7PHzTiQ5BUtaQJfntVeysR8JH1Hit
PTwMMtnpnFiY0vP0wekNyiDKBcStbkumLiLXK0q560v6TLxZApyNtICep1XZ1CQs2YxQUH
tCGpiNbwmzAAAAgQDULOwPH4AgKSnMCkJXX0RtK7esp6DxSjAzmkkTqCp8dtHmneuQ49a3
CUYdK3BpmYEatttoVZNSxtd7Xd9HaYdg5By5JOSNSFZa8QVS50zpJl7ZoI+2YDftnS3WLb
/RTtq1RHJKAWcBXzswMk7zAiCfUox6nI7V1tuQHSl556gQzwAAAIEAwi+nhPmcDpUscgcZ
w2UO9zAS3+e2BIEo+MXjWPVkqzRGo4LAovYqUALqkkRyxWZutZQbIcK95T7lLYkOCr4UFp
ybrynKDwMZ4ZyaIPrxLx5a1X49FYGcGJl+N3j7I9ES0p2Ez7JFcJryXXWjQJxKo/9zCg6Q
JxBTe5TrpiR7RiMAAAAPd2VpbmhvbHRAdGVhcG90AQIDBA==
-----END OPENSSH PRIVATE KEY-----")
(define test:rsa-public-key
  "AAAAB3NzaC1yc2EAAAADAQABAAABAQCg8Yn6UK5/TpMGABIXTDH3tp/Yg7iIPs3FaHk06k+DUvhqJXUaoZcItUDXlaTm3LaSoPxGX/M09902padz1OGOX1MWpTN9VC5aLte/2Pt8G4XTs6fEOdL3ZaFx71GRC7gQLRO7zF7zv0J5pgJnyZiJPm1KvwyAt//LxTvxD40eHkybS4k23dJpL9MSmy+77loUMulNMeuapDvjd38DM6HFWi6mf6I786c30cprU2zC/oowtde5sitLy6I5lVXd5aKZpkUpDPd4wrVxuwZgO/NnznpDLqd2LR3du/eaTG0h96AQ/XLnBGCSMd77PIopxE+p319AfJWeUmqO3FnQB+ZN")
(define test:rsa-fingerprint
  "SHA256:0Z4UTY8qOXZnRvUMi0WY1wwGLhl8DPSEly+NwREAqgw")
(define test:rsa-random-art
  '("+---[RSA 2048]----+"
    "|        .+*O*OB+ |"
    "|       . .oB@B.=o|"
    "|  E   . . =o**o o|"
    "|   o .   = =o o  |"
    "|    o   S = +.   |"
    "|       . + +     |"
    "|                 |"
    "|                 |"
    "|                 |"
    "+----[SHA256]-----+"
    ""))
(let ((key (get-ssh-public-key
            (open-bytevector-input-port
             (base64-decode test:rsa-public-key)))))
  (test-assert (rsa-public-key? key))
  (test-equal test:rsa-fingerprint (ssh-public-key-fingerprint key))
  (test-equal test:rsa-random-art
              (string-split (ssh-public-key-random-art key) #\newline))
  (test-equal "ssh-rsa" (ssh-public-key-algorithm key))
  (let* ((privkey* (get-ssh-private-keys
                    (open-string-input-port test:rsa-private-key)))
         (pk0 (car privkey*)))
    (test-assert (null? (cdr privkey*)))
    (test-assert (openssh-private-key? pk0))
    (test-equal "weinholt@teapot" (openssh-private-key-comment pk0))
    (test-assert (rsa-public-key=?
                  key (openssh-private-key-public pk0)))
    (test-assert (rsa-public-key=?
                  key (rsa-private->public (openssh-private-key-private pk0))))
    (let* ([Hm (make-bytevector 32 #xaa)]
           [sig (rsa-pkcs1-encrypt-digest 'sha-256 Hm
                                          (openssh-private-key-private pk0))]
           [H-signed (rsa-pkcs1-decrypt-digest sig key)])
      (test-equal Hm (cadr H-signed)))))
(test-end)

;;; TODO: test the other curves
(test-begin "ssh-public-key-ecdsa")
(define test:ecdsa-private-key
  "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTCZzjDr8umTwFzL+BCRLope/6vxh/0
oXUcIUWaGhIp2DZWII6IYckt3SC6zOBdcKEtHp+rrNh0kyLmmOobFs5DAAAAqNiZk6nYmZ
OpAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMJnOMOvy6ZPAXMv
4EJEuil7/q/GH/ShdRwhRZoaEinYNlYgjohhyS3dILrM4F1woS0en6us2HSTIuaY6hsWzk
MAAAAgb4s/21Ce60DxDN3d4C+ENXEXesZP4rDdQEetFdWmOrUAAAAPd2VpbmhvbHRAdGVh
cG90AQ==
-----END OPENSSH PRIVATE KEY-----")
(define test:ecdsa-public-key
  "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMJnOMOvy6ZPAXMv4EJEuil7/q/GH/ShdRwhRZoaEinYNlYgjohhyS3dILrM4F1woS0en6us2HSTIuaY6hsWzkM=")
(define test:ecdsa-fingerprint
  "SHA256:D3iUDf2b7OQDscxjj8ASvH9SnIlHRaZsqB1u6WjscCI")
(define test:ecdsa-random-art
  '("+---[ECDSA 256]---+"
    "|        .. .o    |"
    "|         *.o.    |"
    "|     .  = =o     |"
    "|      o* +o .    |"
    "|      o+S* * o   |"
    "|     .o=+o& =    |"
    "|  E o =o.=.O     |"
    "|   . *  o o =    |"
    "|      .  o   .   |"
    "+----[SHA256]-----+"
    ""))
(let ((key (get-ssh-public-key
            (open-bytevector-input-port
             (base64-decode test:ecdsa-public-key)))))
  (test-assert (ecdsa-public-key? key))
  (test-equal test:ecdsa-fingerprint (ssh-public-key-fingerprint key))
  (test-equal test:ecdsa-random-art
              (string-split (ssh-public-key-random-art key) #\newline))
  (test-equal "ecdsa-sha2-nistp256" (ssh-public-key-algorithm key))
  (let* ((privkey* (get-ssh-private-keys
                    (open-string-input-port test:ecdsa-private-key)))
         (pk0 (car privkey*)))
    (test-assert (null? (cdr privkey*)))
    (test-assert (openssh-private-key? pk0))
    (test-equal "weinholt@teapot" (openssh-private-key-comment pk0))
    (test-assert (ecdsa-public-key=?
                  key (openssh-private-key-public pk0)))
    (test-assert (ecdsa-public-key=?
                  key (ecdsa-private->public (openssh-private-key-private pk0))))
    (let*-values ([(msg) (make-bytevector 32 #xaa)]
                  [(r s)
                   (ecdsa-create-signature msg (openssh-private-key-private pk0))])
      (test-assert (ecdsa-verify-signature msg key r s)))))
(test-end)

(test-begin "ssh-public-key-ed25519")
(define test:ed25519-private-key
  "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBlMyd5J2/JAPrA7Mgq3g83ABLSno3C4pZM2em4FEjwQAAAAJjI5ByPyOQc
jwAAAAtzc2gtZWQyNTUxOQAAACBlMyd5J2/JAPrA7Mgq3g83ABLSno3C4pZM2em4FEjwQA
AAAEBQEI+BsPGbatSg6ywmqolDIenx/EFad5V+GLLafT9QumUzJ3knb8kA+sDsyCreDzcA
EtKejcLilkzZ6bgUSPBAAAAAD3dlaW5ob2x0QHRlYXBvdAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----")
(define test:ed25519-public-key
  "AAAAC3NzaC1lZDI1NTE5AAAAIGUzJ3knb8kA+sDsyCreDzcAEtKejcLilkzZ6bgUSPBA")
(define test:ed25519-fingerprint
  "SHA256:E2IEEdTzPYA574hx59EuT6Jt6Ge8fnbFAEVzVL4qUWw")
(define test:ed25519-random-art
  '("+--[ED25519 256]--+"
    "|   .==.o   o+.o..|"
    "|     .* . . .o . |"
    "|      o=.+ . E  .|"
    "|    ....=.+ +   .|"
    "|     + =So o o . |"
    "|    . . =.o . +  |"
    "|       = = . o   |"
    "|      o * + o    |"
    "|     ..=o+ .     |"
    "+----[SHA256]-----+"
    ""))
(let ((key (get-ssh-public-key
            (open-bytevector-input-port
             (base64-decode test:ed25519-public-key)))))
  (test-assert (eddsa-public-key? key))
  (test-equal test:ed25519-fingerprint (ssh-public-key-fingerprint key))
  (test-equal test:ed25519-random-art
              (string-split (ssh-public-key-random-art key) #\newline))
  (test-equal "ssh-ed25519" (ssh-public-key-algorithm key))
  (let* ((privkey* (get-ssh-private-keys
                    (open-string-input-port test:ed25519-private-key)))
         (pk0 (car privkey*)))
    (test-assert (null? (cdr privkey*)))
    (test-assert (openssh-private-key? pk0))
    (test-equal "weinholt@teapot" (openssh-private-key-comment pk0))
    (test-assert (ed25519-public-key=?
                  key (openssh-private-key-public pk0)))
    (test-assert (ed25519-public-key=?
                  key (ed25519-private->public (openssh-private-key-private pk0))))
    (let* ([msg (make-bytevector 32 #xaa)]
           [sig (ed25519-sign (openssh-private-key-private pk0) msg)])
      (test-assert (ed25519-verify key msg sig)))))
(test-end)

(exit (if (zero? (test-runner-fail-count (test-runner-get))) 0 1))
