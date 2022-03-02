---
title: Traces of EDHOC
docname: draft-ietf-lake-traces-latest
abbrev:

ipr: trust200902
cat: info

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
- name: Göran Selander
  surname: Selander
  org: Ericsson
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: goran.selander@ericsson.com
- name: John Preuß Mattsson
  initials: J
  surname: Preuß Mattsson
  org: Ericsson
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.mattsson@ericsson.com
- name: Marek Serafin
  initials: M
  surname: Serafin
  org: ASSA ABLOY
  abbrev: ASSA ABLOY
  street:
  country: Poland
  email: marek.serafin@assaabloy.com

normative:

informative:

  I-D.ietf-lake-edhoc:
  RFC8949:

  CborMe:
    target: http://cbor.me/
    title: CBOR Playground
    author:
      -
        ins: C. Bormann
    date: May 2018

--- abstract

This document contains some example traces of Ephemeral Diffie-Hellman Over COSE (EDHOC).

--- middle

# Introduction

EDHOC {{I-D.ietf-lake-edhoc}} is a lightweight authenticated key exchange protocol designed for highly constrained settings. This document contains annotated traces of EDHOC protocol runs, with input, output and intermediate processing results to simplify testing of implementations.

The traces in this draft are valid for versions -11 and -12 of {{I-D.ietf-lake-edhoc}}, with the additional modification in https://github.com/lake-wg/edhoc/pull/205.

A more extensive test vector suite and related code that was used to generate trace 1 can be found at: https://github.com/lake-wg/edhoc/tree/master/test-vectors-11.
The test vector for trace 2 can be found at: https://github.com/lake-wg/edhoc/tree/master/test-vectors-11/p256.

# Setup

EDHOC is run between an Initiator (I) and a Responder (R). The private/public key pairs and credentials of I and R required to produce the protocol messages are shown in the traces when needed for the calculations.

EDHOC messages and intermediate results are encoded in CBOR {{RFC8949}} and can therefore be displayed in CBOR diagnostic notation using, e.g., the CBOR playground {{CborMe}}, which makes them easy to parse for humans.

NOTE 1. The same name is used for hexadecimal byte strings and their CBOR encodings. The traces contain both the raw byte strings and the corresponding CBOR encoded data items.

NOTE 2. If not clear from the context, remember that CBOR sequences and CBOR arrays assume CBOR encoded data items as elements.

NOTE 3. When the protocol transporting EDHOC messages does not inherently provide correlation across all messages, like CoAP, then some messages typically are prepended with connection identifiers and potentially a message_1 indicator (see Section 3.4.1 and Appendix A.3 of {{I-D.ietf-lake-edhoc}}). Those bytes are not included in the traces in this document.


# Authentication with static DH, CCS identified by 'kid'

In this example I and R are authenticated with ephemeral-static Diffie-Hellman (METHOD = 3). Both I and R support cipher suite 0, which determines the algorithms:

* EDHOC AEAD algorithm = AES-CCM-16-64-128
* EDHOC hash algorithm = SHA-256
* EDHOC MAC length in bytes (Static DH) = 8
* EDHOC key exchange algorithm (ECDH curve) = X25519
* EDHOC signature algorithm = EdDSA
* Application AEAD algorithm = AES-CCM-16-64-128
* Application hash algorithm = SHA-256

The public keys are represented as raw public keys (RPK), encoded in an CWT Claims Set (CCS) and identified by the COSE header parameter 'kid'.


## message_1

Both endpoints are authenticated with static DH, i.e. METHOD = 3:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
03
~~~~~~~~
{: artwork-align="left"}

I selects cipher suite 0. A single cipher suite is encoded as an int:

~~~~~~~~
SUITES_I (CBOR Data Item) (1 bytes)
00
~~~~~~~~

I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
X (Raw Value) (Initiator's ephemeral private key) (32 bytes)
b3 11 19 98 cb 3f 66 86 63 ed 42 51 c7 8b e6 e9 5a 4d a1 27 e4 f6 fe
e2 75 e8 55 d8 d9 df d8 ed
~~~~~~~~

~~~~~~~~
G_X (Raw Value) (Initiator's ephemeral public key) (32 bytes)
3a a9 eb 32 01 b3 36 7b 8c 8b e3 8d 91 e5 7a 2b 43 3e 67 88 8c 86 d2
ac 00 6a 52 08 42 ed 50 37
~~~~~~~~
~~~~~~~~
G_X (CBOR Data Item) (Initiator's ephemeral public key) (34 bytes)
58 20 3a a9 eb 32 01 b3 36 7b 8c 8b e3 8d 91 e5 7a 2b 43 3e 67 88 8c
86 d2 ac 00 6a 52 08 42 ed 50 37
~~~~~~~~
I selects its connection identifier C_I to be the int 12:

~~~~~~~~
C_I (Raw Value) (Connection identifier chosen by I) (int)
12
~~~~~~~~
~~~~~~~~
C_I (CBOR Data Item) (Connection identifier chosen by I) (1 bytes)
0c
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_1 (CBOR Sequence) (0 bytes)
~~~~~~~~

I constructs message_1:

    message_1 =
    (
     3,
     0,
     h'3AA9EB3201B3367B8C8BE38D91E57A2B433E67888C86D2AC006A520842ED5037',
     12
    )

~~~~~~~~
message_1 (CBOR Sequence) (37 bytes)
03 00 58 20 3a a9 eb 32 01 b3 36 7b 8c 8b e3 8d 91 e5 7a 2b 43 3e 67
88 8c 86 d2 ac 00 6a 52 08 42 ed 50 37 0c
~~~~~~~~

## message_2

R creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Y (Raw Value) (Responder's ephemeral private key) (32 bytes)
bd 86 ea f4 06 5a 83 6c d2 9d 0f 06 91 ca 2a 8e c1 3f 51 d1 c4 5e 1b
43 72 c0 cb e4 93 ce f6 bd
~~~~~~~~
~~~~~~~~
G_Y (Raw Value) (Responder's ephemeral public key) (32 bytes)
25 54 91 b0 5a 39 89 ff 2d 3f fe a6 20 98 aa b5 7c 16 0f 29 4e d9 48
01 8b 41 90 f7 d1 61 82 4e
~~~~~~~~
~~~~~~~~
G_Y (CBOR Data Item) (Responder's ephemeral public key) (34 bytes)
58 20 25 54 91 b0 5a 39 89 ff 2d 3f fe a6 20 98 aa b5 7c 16 0f 29 4e
d9 48 01 8b 41 90 f7 d1 61 82 4e
~~~~~~~~

PRK_2e is specified in Section 4.1.1 of {{I-D.ietf-lake-edhoc}}.

First, the ECDH shared secret G_XY is computed from G_X and Y, or G_Y and X:

~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
6d 26 60 ec 2b 30 15 d9 3f e6 5d ae a5 12 74 bd 5b 1e bb ad 9b 62 4e
67 0e 79 a6 55 e3 0e c3 4d
~~~~~~~~

Then, PRK_2e is calculated using Extract() determined by the EDHOC hash algorithm:

    PRK_2e = Extract(salt, G_XY) =
           = HMAC-SHA-256(salt, G_XY)

where salt is the zero-length byte string:

~~~~~~~~
salt (Raw Value) (0 bytes)
~~~~~~~~
~~~~~~~~
PRK_2e (Raw Value) (32 bytes)
d1 d0 11 a5 9a 6d 10 57 5e b2 20 c7 65 2e 6f 98 c4 17 a5 65 e4 e4 5c
f5 b5 01 06 95 04 3b 0e b7
~~~~~~~~

Since METHOD = 3, R authenticates using static DH.

R's static key pair for use with the EDHOC key exchange algorithm is based on
the same curve as for the ephemeral keys, X25519:

~~~~~~~~
R (Raw Value) (Responder's private authentication key) (32 bytes)
52 8b 49 c6 70 f8 fc 16 a2 ad 95 c1 88 5b 2e 24 fb 15 76 22 72 79 2a
a1 cf 05 1d f5 d9 3d 36 94
~~~~~~~~
~~~~~~~~
G_R (Raw Value) (Responder's public authentication key) (32 bytes)
e6 6f 35 59 90 22 3c 3f 6c af f8 62 e4 07 ed d1 17 4d 07 01 a0 9e cd
6a 15 ce e2 c6 ce 21 aa 50
~~~~~~~~

PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with static DH (METHOD = 3), PRK_3e2m is derived
from G_RX using Extract() with the EDHOC hash algorithm:

    PRK_3e2m = Extract(PRK_2e, G_RX) =
             = HMAC-SHA-256(PRK_2e, G_RX)

where G_RX is the ECDH shared secret calculated from G_X and R, or G_R and X.

~~~~~~~~
G_RX (Raw Value) (ECDH shared secret) (32 bytes)
b5 8b 40 34 26 c0 3d b0 7b aa 93 44 d5 51 e6 7b 21 78 bf 05 ec 6f 52
c3 6a 2f a5 be 23 2d d4 78
~~~~~~~~
~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
76 8e 13 75 27 2e 1e 68 b4 2c a3 24 84 80 d5 bb a8 8b cb 55 f6 60 ce
7f 94 1e 67 09 10 31 17 a1
~~~~~~~~

R selects its connection identifier C_R to be the empty byte string "":

~~~~~~~~
C_R (raw value) (Connection identifier chosen by R) (0 bytes)

~~~~~~~~
~~~~~~~~
C_R (CBOR Data Item) (Connection identifier chosen by R) (1 bytes)
40
~~~~~~~~

The transcript hash TH_2 is calculated using the EDHOC hash algorithm:

TH_2 = H(H(message_1), G_Y, C_R)

~~~~~~~~
H(message_1) (Raw Value) (32 bytes)
9b dd b0 cd 55 48 7f 82 a8 6f b7 2a 8b b3 58 52 68 91 a0 a6 c9 08 61
24 12 f5 af 29 9d af 01 96
~~~~~~~~
~~~~~~~~
H(message_1) (CBOR Data Item) (34 bytes)
58 20 9b dd b0 cd 55 48 7f 82 a8 6f b7 2a 8b b3 58 52 68 91 a0 a6 c9
08 61 24 12 f5 af 29 9d af 01 96
~~~~~~~~

The input to calculate TH_2 is the CBOR sequence:

H(message_1), G_Y, C_R

~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (69 bytes)
58 20 9b dd b0 cd 55 48 7f 82 a8 6f b7 2a 8b b3 58 52 68 91 a0 a6 c9
08 61 24 12 f5 af 29 9d af 01 96 58 20 25 54 91 b0 5a 39 89 ff 2d 3f
fe a6 20 98 aa b5 7c 16 0f 29 4e d9 48 01 8b 41 90 f7 d1 61 82 4e 40
~~~~~~~~
~~~~~~~~
TH_2 (Raw Value) (32 bytes)
71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59 68 71 1b
9a 91 1c 71 fc 09 6a ee 0e
~~~~~~~~
~~~~~~~~
TH_2 (CBOR Data Item) (34 bytes)
58 20 71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59 68
71 1b 9a 91 1c 71 fc 09 6a ee 0e
~~~~~~~~

R constructs the remaining input needed to calculate MAC_2:

MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2",
            << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2)

CRED_R is identified by a 'kid' with integer value 5:

    ID_CRED_R =
    {
     4 : 5
    }

~~~~~~~~
ID_CRED_R (CBOR Data Item) (3 bytes)
a1 04 05
~~~~~~~~

CRED_R is an RPK encoded as a CCS:

    {                                              /CCS/
      2 : "example.edu",                           /sub/
      8 : {                                        /cnf/
        1 : {                                      /COSE_Key/
          1 : 1,                                   /kty/
          2 : 5,                                   /kid/
         -1 : 4,                                   /crv/
         -2 : h'E66F355990223C3F6CAFF862E407EDD1   /x/
                174D0701A09ECD6A15CEE2C6CE21AA50'
        }
      }
    }

~~~~~~~~
CRED_R (CBOR Data Item) (59 bytes)
a2 02 6b 65 78 61 6d 70 6c 65 2e 65 64 75 08 a1 01 a4 01 01 02 05 20
04 21 58 20 e6 6f 35 59 90 22 3c 3f 6c af f8 62 e4 07 ed d1 17 4d 07
01 a0 9e cd 6a 15 ce e2 c6 ce 21 aa 50
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_2 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_2 is computed through Expand() using the
EDHOC hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

MAC_2 = HKDF-Expand(PRK_3e2m, info, mac_length_2)

Since METHOD = 3, mac_length_2 is given by the EDHOC MAC length.

info for MAC_2 is:

    info =
    (
     h'71A6C7C5BA9AD47FE72DA4DC359BF6B276D3515968711B9A911C71FC096AEE0E',
     "MAC_2",
     h'A10405A2026B6578616D706C652E65647508A101A4010102052004215820E6
       6F355990223C3F6CAFF862E407EDD1174D0701A09ECD6A15CEE2C6CE21AA50',
     8
    )

where the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (105 bytes)
58 20 71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59 68
71 1b 9a 91 1c 71 fc 09 6a ee 0e 65 4d 41 43 5f 32 58 3e a1 04 05 a2
02 6b 65 78 61 6d 70 6c 65 2e 65 64 75 08 a1 01 a4 01 01 02 05 20 04
21 58 20 e6 6f 35 59 90 22 3c 3f 6c af f8 62 e4 07 ed d1 17 4d 07 01
a0 9e cd 6a 15 ce e2 c6 ce 21 aa 50 08
~~~~~~~~
~~~~~~~~
MAC_2 (Raw Value) (8 bytes)
8e 27 cb d4 94 f7 52 83
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (9 bytes)
48 8e 27 cb d4 94 f7 52 83
~~~~~~~~

Since METHOD = 3, Signature_or_MAC_2 is MAC_2:

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (8 bytes)
8e 27 cb d4 94 f7 52 83
~~~~~~~~

~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (9 bytes)
48 8e 27 cb d4 94 f7 52 83
~~~~~~~~

R constructs the plaintext:

    PLAINTEXT_2 =
    (
     ID_CRED_R / bstr / int,
     Signature_or_MAC_2,
     ? EAD_2
    )

Since ID_CRED_R contains a single 'kid' parameter, only the int 5 is included in the plaintext.

~~~~~~~~
PLAINTEXT_2 (CBOR Sequence) (10 bytes)
05 48 8e 27 cb d4 94 f7 52 83
~~~~~~~~

The input needed to calculate KEYSTREAM_2 is defined in Section 4.2 of
{{I-D.ietf-lake-edhoc}}, using Expand() with the EDHOC hash algorithm:

    KEYSTREAM_2 = EDHOC-KDF(PRK_2e, TH_2, "KEYSTREAM_2", h'', length) =
                = HKDF-Expand(PRK_2e, info, length),


where length is the length of PLAINTEXT_2, and info for KEYSTREAM_2 is:

    info =
    (
     h'71A6C7C5BA9AD47FE72DA4DC359BF6B276D3515968711B9A911C71FC096AEE0E',
     "KEYSTREAM_2",
     h'',
     10
    )

where last value is the length of PLAINTEXT_2.

~~~~~~~~
info for KEYSTREAM_2 (CBOR Sequence) (48 bytes)
58 20 71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59 68
71 1b 9a 91 1c 71 fc 09 6a ee 0e 6b 4b 45 59 53 54 52 45 41 4d 5f 32
40 0a
~~~~~~~~
~~~~~~~~
KEYSTREAM_2 (Raw Value) (10 bytes)
0a b8 c2 0e 84 9e 52 f5 9d fb
~~~~~~~~

R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (10 bytes)
0f f0 4c 29 4f 4a c6 02 cf 78
~~~~~~~~

R constructs message_2:

    message_2 =
    (
     G_Y_CIPHERTEXT_2,
     C_R
    )

where G_Y_CIPHERTEXT_2 is the bstr encoding of the concatenation of
the raw values of G_Y and CIPHERTEXT_2.

~~~~~~~~
message_2 (CBOR Sequence) (45 bytes)
58 2a 25 54 91 b0 5a 39 89 ff 2d 3f fe a6 20 98 aa b5 7c 16 0f 29 4e
d9 48 01 8b 41 90 f7 d1 61 82 4e 0f f0 4c 29 4f 4a c6 02 cf 78 40
~~~~~~~~


## message_3

Since METHOD = 3, I authenticates using static DH.

I's static key pair for use with the EDHOC key exchange algorithm is based on
the same curve as for the ephemeral keys, X25519:

~~~~~~~~
I (Raw Value) (Initiator's private authentication key) (32 bytes)
cf c4 b6 ed 22 e7 00 a3 0d 5c 5b cd 61 f1 f0 20 49 de 23 54 62 33 48
93 d6 ff 9f 0c fe a3 fe 04
~~~~~~~~
~~~~~~~~
G_I (Raw Value) (Initiator's public authentication key) (32 bytes)
4a 49 d8 8c d5 d8 41 fa b7 ef 98 3e 91 1d 25 78 86 1f 95 88 4f 9f 5d
c4 2a 2e ed 33 de 79 ed 77
~~~~~~~~

PRK_4x3m is derived as specified in Section 4.1.3 of {{I-D.ietf-lake-edhoc}}.
Since I authenticates with static DH (METHOD = 3), PRK_4x3m is derived
from G_IY using Extract() with the EDHOC hash algorithm:

    PRK_4x3m = Extract(PRK_3e2m, G_IY) =
             = HMAC-SHA-256(PRK_3e2m, G_IY)

where G_IY is the ECDH shared secret calculated from G_I and Y, or G_Y and I.

~~~~~~~~
G_IY (Raw Value) (ECDH shared secret) (32 bytes)
0a f4 2a d5 12 dc 3e 97 2b 3a c4 d4 7b a3 3f fc 21 f1 ae 6f 07 f2 f8
94 85 4a 5a 47 44 33 85 48
~~~~~~~~
~~~~~~~~
PRK_4x3m (Raw Value) (32 bytes)
b8 cc df 14 20 b5 b0 c8 2a 58 7e 7d 26 dd 7b 70 48 57 4c 3a 48 df 9f
6a 45 f7 21 c0 cf a4 b2 7c
~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:

TH_3 = H(TH_2, CIPHERTEXT_2)

~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (45 bytes)
58 20 71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59 68
71 1b 9a 91 1c 71 fc 09 6a ee 0e 4a 0f f0 4c 29 4f 4a c6 02 cf 78
~~~~~~~~

~~~~~~~~
TH_3 (Raw Value) (32 bytes)
a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9 5a c2
62 9b 2b be f7 fb 24 a3 70
~~~~~~~~
~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9
5a c2 62 9b 2b be f7 fb 24 a3 70
~~~~~~~~

I constructs the remaining input needed to calculate MAC_3:

    MAC_3 = EDHOC-KDF(PRK_4x3m, TH_3, "MAC_3",
            << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3)

CRED_I is identified by a 'kid' with integer value -10:

    ID_CRED_I =
    {
     4 : -10
    }


ID_CRED_I (CBOR Data Item) (3 bytes)
a1 04 29

CRED_I is an RPK encoded as a CCS:

    {                                              /CCS/
      2 : "42-50-31-FF-EF-37-32-39",               /sub/
      8 : {                                        /cnf/
        1 : {                                      /COSE_Key/
          1 : 1,                                   /kty/
          2 : -10,                                 /kid/
         -1 : 4,                                   /crv/
         -2 : h'4A49D88CD5D841FAB7EF983E911D2578   /x/
                861F95884F9F5DC42A2EED33DE79ED77'
        }
      }
    }


~~~~~~~~
CRED_I (CBOR Data Item) (71 bytes)
a2 02 77 34 32 2d 35 30 2d 33 31 2d 46 46 2d 45 46 2d 33 37 2d 33 32
2d 33 39 08 a1 01 a4 01 01 02 29 20 04 21 58 20 4a 49 d8 8c d5 d8 41
fa b7 ef 98 3e 91 1d 25 78 86 1f 95 88 4f 9f 5d c4 2a 2e ed 33 de 79
ed 77
~~~~~~~~

No external authorization data:

EAD_3 (CBOR Sequence) (0 bytes)

MAC_3 is computed through Expand() using the EDHOC hash algorithm, see
Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    MAC_3 = HKDF-Expand(PRK_4x3m, info, mac_length_3)

Since METHOD = 3, mac_length_3 is given by the EDHOC MAC length.

info for MAC_3 is:

    info =
    (
     h'A49007CE54762E467C4E4A44692F2070D3E9EB00F95AC2629B2BBEF7FB24A370',
     "MAC_3",
     h'A10429A2027734322D35302D33312D46462D45462D33372D33322D333908A101
       A40101022920042158204A49D88CD5D841FAB7EF983E911D2578861F95884F9F
       5DC42A2EED33DE79ED77',
     8
    )

where the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (117 bytes)
58 20 a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9
5a c2 62 9b 2b be f7 fb 24 a3 70 65 4d 41 43 5f 33 58 4a a1 04 29 a2
02 77 34 32 2d 35 30 2d 33 31 2d 46 46 2d 45 46 2d 33 37 2d 33 32 2d
33 39 08 a1 01 a4 01 01 02 29 20 04 21 58 20 4a 49 d8 8c d5 d8 41 fa
b7 ef 98 3e 91 1d 25 78 86 1f 95 88 4f 9f 5d c4 2a 2e ed 33 de 79 ed
77 08
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (8 bytes)
db 0b 8f 75 27 09 53 da
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (9 bytes)
48 db 0b 8f 75 27 09 53 da
~~~~~~~~

Since METHOD = 3, Signature_or_MAC_3 is MAC_3:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (8 bytes)
db 0b 8f 75 27 09 53 da
~~~~~~~~

~~~~~~~~
Signature_or_MAC_3 (CBOR Data Item) (9 bytes)
48 db 0b 8f 75 27 09 53 da
~~~~~~~~

I constructs the plaintext P_3:

    P_3 =
    (
     ID_CRED_I / bstr / int,
     Signature_or_MAC_3,
     ? EAD_3
    )

Since ID_CRED_I contains a single 'kid' parameter, only the
int -10 is included in the plaintext.


~~~~~~~~
P_3 (CBOR Sequence) (10 bytes)
29 48 db 0b 8f 75 27 09 53 da
~~~~~~~~

I constructs the associated data for message_3:

    A_3 =
    (
     "Encrypt0",
     h'',
     TH_3
    )

~~~~~~~~
A_3 (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 a4 90 07 ce 54 76 2e 46 7c 4e
4a 44 69 2f 20 70 d3 e9 eb 00 f9 5a c2 62 9b 2b be f7 fb 24 a3 70
~~~~~~~~

I constructs the input needed to derive the key K_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3 = EDHOC-KDF(PRK_3e2m, TH_3, "K_3", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

where length is the key length of EDHOC AEAD algorithm, and info for K_3 is:

    info =
    (
     h'A49007CE54762E467C4E4A44692F2070D3E9EB00F95AC2629B2BBEF7FB24A370',
     "K_3",
     h'',
     16
    )

  where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_3 (CBOR Sequence) (40 bytes)
58 20 a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9
5a c2 62 9b 2b be f7 fb 24 a3 70 63 4b 5f 33 40 10
~~~~~~~~
~~~~~~~~
K_3 (Raw Value) (16 bytes)
2a 30 e4 f6 bc 55 8d 0e 7a 8c 63 ee 7b b5 45 7f
~~~~~~~~

I constructs the input needed to derive the nonce IV_3, see Section 4.2 of
{{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3 = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

where length is the nonce length of EDHOC AEAD algorithm, and info for IV_3 is:

    info =
    (
     h'A49007CE54762E467C4E4A44692F2070D3E9EB00F95AC2629B2BBEF7FB24A370',
     "IV_3",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3 (CBOR Sequence) (41 bytes)
58 20 a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9
5a c2 62 9b 2b be f7 fb 24 a3 70 64 49 56 5f 33 40 0d
~~~~~~~~
~~~~~~~~
IV_3 (Raw Value) (13 bytes)
b3 8f b6 31 e3 44 a8 10 52 56 32 ed f8
~~~~~~~~

I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_3, additional data
A_3, key K_3 and nonce IV_3.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (18 bytes)
be 01 46 c1 36 ac 2e ff d4 53 a7 5e fa 90 89 6f 65 3b
~~~~~~~~

message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (19 bytes)
52 be 01 46 c1 36 ac 2e ff d4 53 a7 5e fa 90 89 6f 65 3b
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (53 bytes)
58 20 a4 90 07 ce 54 76 2e 46 7c 4e 4a 44 69 2f 20 70 d3 e9 eb 00 f9
5a c2 62 9b 2b be f7 fb 24 a3 70 52 be 01 46 c1 36 ac 2e ff d4 53 a7
5e fa 90 89 6f 65 3b
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07 f8 d0
00 ad ce 88 b6 30 d8 84 eb
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07
f8 d0 00 ad ce 88 b6 30 d8 84 eb
~~~~~~~~


## message_4

No external authorization data:

EAD_4 (CBOR Sequence) (0 bytes)

R constructs the plaintext P_4:

    P_4 =
    (
     ? EAD_4
    )

P_4 (CBOR Sequence) (0 bytes)

R constructs the associated data for message_4:

    A_4 =
    (
     "Encrypt0",
     h'',
     TH_4
    )

~~~~~~~~
A_4 (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 4b 9a dd 2a 9e eb 88 49 71 6c
79 68 78 4f 55 40 dd 64 a3 bb 07 f8 d0 00 ad ce 88 b6 30 d8 84 eb
~~~~~~~~

R constructs the input needed to derive the EDHOC message_4 key, see Section
4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_4 = EDHOC-Exporter("EDHOC_K_4", h'', length)
          = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_K_4", h'', length)
          = HKDF-Expand(PRK_4x3m, info, length)

where length is the key length of the EDHOC AEAD algorithm,
and info for EDHOC_K_4 is:

    info =
    (
     h'4B9ADD2A9EEB8849716C7968784F5540DD64A3BB07F8D000ADCE88B630D884EB',
     "EDHOC_K_4",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_4 (CBOR Sequence) (46 bytes)
58 20 4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07
f8 d0 00 ad ce 88 b6 30 d8 84 eb 69 45 44 48 4f 43 5f 4b 5f 34 40 10
~~~~~~~~
~~~~~~~~
K_4 (Raw Value) (16 bytes)
55 b5 7d 59 a8 26 f4 56 38 86 9b 75 07 0b 11 17
~~~~~~~~

R constructs the input needed to derive the EDHOC message_4 nonce,
see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

           IV_4 =
           = EDHOC-Exporter( "EDHOC_IV_4", h'', length )
           = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_IV_4", h'', length)
           = HKDF-Expand(PRK_4x3m, info, length)

where length is the nonce length of EDHOC AEAD algorithm,
and info for EDHOC_IV_4 is:

    info =
    (
     h'4B9ADD2A9EEB8849716C7968784F5540DD64A3BB07F8D000ADCE88B630D884EB',
     "EDHOC_IV_4",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4 (CBOR Sequence) (47 bytes)
58 20 4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07
f8 d0 00 ad ce 88 b6 30 d8 84 eb 6a 45 44 48 4f 43 5f 49 56 5f 34 40
0d
~~~~~~~~
~~~~~~~~
IV_4 (Raw Value) (13 bytes)
20 7a 4e fc 25 a6 58 96 45 11 f1 63 76
~~~~~~~~

  R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_4, additional data
  A_4, key K_4 and nonce IV_4.

~~~~~~~~
CIPHERTEXT_4 (8 bytes)
e9 e6 c8 b6 37 6d b0 b1
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 e9 e6 c8 b6 37 6d b0 b1
~~~~~~~~


## OSCORE Parameters

The derivation of OSCORE parameters is specified in Appendix A.2 of
{{I-D.ietf-lake-edhoc}}.

The AEAD and Hash algorithms to use in OSCORE are given by the selected cipher suite:

~~~~~~~~
Application AEAD Algorithm (int)
10
~~~~~~~~

~~~~~~~~
Application Hash Algorithm (int)
-16
~~~~~~~~

The mapping from EDHOC connection identifiers to OSCORE Sender/Recipient IDs
is defined in Section A.1of {{I-D.ietf-lake-edhoc}}.

C_R is mapped to the Recipient ID of the server, i.e., the Sender ID of the client. Since C_R is byte valued it the OSCORE Sender/Recipient ID equals the byte string (in this case the empty byte string).

~~~~~~~~
Client's OSCORE Sender ID (Raw Value) (0 bytes)
~~~~~~~~

C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server.
Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
0c
~~~~~~~~

The OSCORE Master Secret is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Secret =
    = EDHOC-Exporter("OSCORE_Master_Secret", h'', key_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Master_Secret", h'', key_length)
    = HKDF-Expand(PRK_4x3m, info, key_length)

where key_length is by default the key length of the Application AEAD algorithm, and info for the OSCORE Master Secret is:

    info =
    (
     h'4B9ADD2A9EEB8849716C7968784F5540DD64A3BB07F8D000ADCE88B630D884EB',
     "OSCORE_Master_Secret",
     h'',
     16
    )

where the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (57 bytes)
58 20 4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07
f8 d0 00 ad ce 88 b6 30 d8 84 eb 74 4f 53 43 4f 52 45 5f 4d 61 73 74
65 72 5f 53 65 63 72 65 74 40 10

~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
c0 53 01 37 6c e9 5f 67 c4 14 d8 bb 5f 0f db 5e
~~~~~~~~

The OSCORE Master Salt is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE_Master_Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Master_Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

where salt_length is the length of the OSCORE Master Salt, and info for the OSCORE Master Salt is:

    info =
    (
     h'4B9ADD2A9EEB8849716C7968784F5540DD64A3BB07F8D000ADCE88B630D884EB',
     "OSCORE_Master_Salt",
     h'',
     8
    )

where the last value is the length of the OSCORE Master Salt.


~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (55 bytes)
58 20 4b 9a dd 2a 9e eb 88 49 71 6c 79 68 78 4f 55 40 dd 64 a3 bb 07
f8 d0 00 ad ce 88 b6 30 d8 84 eb 72 4f 53 43 4f 52 45 5f 4d 61 73 74
65 72 5f 53 61 6c 74 40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
74 01 b4 6f a8 2f 66 31
~~~~~~~~


## Key Update

Key update is defined in Section 4.4 of {{I-D.ietf-lake-edhoc}}:

    EDHOC-KeyUpdate(nonce):
    PRK_4x3m = Extract(nonce, PRK_4x3m)

~~~~~~~~
KeyUpdate Nonce (Raw Value) (16 bytes)
d4 91 a2 04 ca a6 b8 02 54 c4 71 e0 de ee d1 60
~~~~~~~~

~~~~~~~~
PRK_4x3m after KeyUpdate (Raw Value) (32 bytes)
82 09 6e 3a e6 3d 93 c7 b6 f8 8b 7c 1b 5e 63 f4 9f 74 c8 0e f3 14 42
51 9f fb 20 e2 f8 87 3e b1
~~~~~~~~

The OSCORE Master Secret is derived with the updated PRK_4x3m:

OSCORE Master Secret = HKDF-Expand(PRK_4x3m, info, key_length)

where info and key_length are unchanged.

~~~~~~~~
OSCORE Master Secret after KeyUpdate (Raw Value) (16 bytes)
a5 15 23 1d 9e c5 88 74 82 22 6b f9 e0 da 05 ce
~~~~~~~~

The OSCORE Master Salt is derived with the updated PRK_4x3m:

OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
50 57 e5 92 ed 8b 11 28
~~~~~~~~



# Authentication with signatures, X.509 certificates identified by 'x5t'

In this example the Initiator (I) and Responder (R) are authenticated with digital signatures (METHOD = 0). I supports cipher suites 6 and 2 (in order of preference) and R only supports cipher suite 2. After an initial negotiation smessage exchange cipher suite 2 is used, which determines the algorithms:

* EDHOC AEAD algorithm = AES-CCM-16-64-128
* EDHOC hash algorithm = SHA-256
* EDHOC MAC length in bytes (Static DH) = 8
* EDHOC key exchange algorithm (ECDH curve) = P-256
* EDHOC signature algorithm = ES256
* Application AEAD algorithm = AES-CCM-16-64-128
* Application hash algorithm = SHA-256

The public keys are represented with X.509 certificates identified by the COSE header parameter 'x5t'.


## message_1 (first time) {#m1_1}

Both endpoints are authenticated with signatures, i.e. METHOD = 0:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
00
~~~~~~~~

I selects its preferred cipher suite 6. A single cipher suite is encoded as an int:

~~~~~~~~
SUITES_I (CBOR Data Item) (1 bytes)
06
~~~~~~~~

I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
X (Raw Value) (Initiator's ephemeral private key) (32 bytes)
5c 41 72 ac a8 b8 2b 5a 62 e6 6f 72 22 16 f5 a1 0f 72 aa 69 f4 2c 1d
1c d3 cc d7 bf d2 9c a4 e9
~~~~~~~~
~~~~~~~~
G_X (Raw Value) (Initiator's ephemeral public key) (33 bytes)
02 74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b 3d 8f 65 f3
26 20 b7 49 be e8 d2 78 ef a9
~~~~~~~~
~~~~~~~~
G_X (CBOR Data Item) (Initiator's ephemeral public key) (35 bytes)
58 21 02 74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b 3d 8f
65 f3 26 20 b7 49 be e8 d2 78 ef a9
~~~~~~~~

I selects its connection identifier C_I to be the int 14:

~~~~~~~~
C_I (Raw Value) (Connection identifier chosen by I) (int)
14
~~~~~~~~
~~~~~~~~
C_I (CBOR Data Item) (Connection identifier chosen by I) (1 bytes)
0e
~~~~~~~~

No external authorization data:

EAD_1 (CBOR Sequence) (0 bytes)

I constructs message_1:

    message_1 =
    (
     0,
     6,
     h'02741A13D7BA048FBB615E94386AA3B61BEA5B3D8F65F32620B749BEE8D278EFA9',
     14
    )

~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
00 06 58 21 02 74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b
3d 8f 65 f3 26 20 b7 49 be e8 d2 78 ef a9 0e
~~~~~~~~


## error

R does not support cipher suite 6 and sends an error with ERR_CODE 2 containing SUITES_R as ERR_INFO. R proposes cipher suite 2, a single cipher suite thus encoded as an int.

~~~~~~~~
SUITES_R
02
~~~~~~~~

~~~~~~~~
error (CBOR Sequence) (2 bytes)
02 02
~~~~~~~~


## message_1 (second time)

Same steps are performed as message_1 first time, {{m1_1}}, but with updated SUITES_I.

Both endpoints are authenticated with signatures, i.e. METHOD = 0:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
00
~~~~~~~~

I selects cipher suite 2 and indicates the more preferred cipher suite(s), in this case 6, all encoded as the array [6, 2]:

~~~~~~~~
SUITES_I (CBOR Data Item) (3 bytes)
82 06 02
~~~~~~~~


I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
X (Raw Value) (Initiator's ephemeral private key) (32 bytes)
c4 84 04 c9 12 d6 8a ad 55 7f 1f 02 f7 0c 61 c1 9b 1e a1 d6 2f 1b d6
46 16 04 2d f5 c4 fe 61 95
~~~~~~~~
~~~~~~~~
G_X (Raw Value) (Initiator's ephemeral public key) (33 bytes)
02 50 a7 6b 38 ea 84 0f a1 b1 a5 11 52 59 1d 4c d5 2c 75 89 21 52 c8
70 27 72 25 b1 ed 99 8e d9 53
~~~~~~~~
~~~~~~~~
G_X (CBOR Data Item) (Initiator's ephemeral public key) (35 bytes)
58 21 02 50 a7 6b 38 ea 84 0f a1 b1 a5 11 52 59 1d 4c d5 2c 75 89 21
52 c8 70 27 72 25 b1 ed 99 8e d9 53
~~~~~~~~

I selects its connection identifier C_I to be the int -24:

~~~~~~~~
C_I (Raw Value) (Connection identifier chosen by I) (int)
-24
~~~~~~~~
~~~~~~~~
C_I (CBOR Data Item) (Connection identifier chosen by I) (1 bytes)
37
~~~~~~~~

No external authorization data:

EAD_1 (CBOR Sequence) (0 bytes)

I constructs message_1:

    message_1 =
    (
     0,
     [6,2],
     h'0250A76B38EA840FA1B1A51152591D4CD52C75892152C870277225B1ED998ED953',
     -24
    )

~~~~~~~~
message_1 (CBOR Sequence) (40 bytes)
00 82 06 02 58 21 02 50 a7 6b 38 ea 84 0f a1 b1 a5 11 52 59 1d 4c d5
2c 75 89 21 52 c8 70 27 72 25 b1 ed 99 8e d9 53 37
~~~~~~~~

## message_2

R supports the selected cipher suite 2 and not the by I more preferred cipher suite(s) 6, so SUITES_I is acceptable.

R creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Y (Raw Value) (Responder's ephemeral private key) (32 bytes)
3c 5c e3 2c 6c ff c1 4d 14 5c 06 18 6f 8d d1 08 f0 85 d8 62 7a 0d 16
0b ee 84 8c fc 42 fd 3e 9f
~~~~~~~~
~~~~~~~~
G_Y (Raw Value) (Responder's ephemeral public key) (33 bytes)
02 13 fe 27 ad cd 01 d9 88 d0 ae 00 ec d3 fe 96 f3 ce 1e e4 64 90 87
39 0b 7d 24 d4 44 ff ad 67 2d
~~~~~~~~
~~~~~~~~
G_Y (CBOR Data Item) (Responder's ephemeral public key) (35 bytes)
58 21 02 13 fe 27 ad cd 01 d9 88 d0 ae 00 ec d3 fe 96 f3 ce 1e e4 64
90 87 39 0b 7d 24 d4 44 ff ad 67 2d
~~~~~~~~

PRK_2e is specified in Section 4.1.1 of {{I-D.ietf-lake-edhoc}}.

First, the ECDH shared secret G_XY is computed from G_X and Y, or G_Y and X:

~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
10 e9 07 f1 1d 96 a1 a5 03 77 a5 d5 72 cc 70 65 05 27 8a 4a d4 22 4f
27 f1 45 76 17 ca ec cc 6f
~~~~~~~~

Then, PRK_2e is calculated using Extract() determined by the EDHOC hash algorithm:

    PRK_2e = Extract(salt, G_XY) =
           = HMAC-SHA-256(salt, G_XY)

where salt is the zero-length byte string:

~~~~~~~~
salt (Raw Value) (0 bytes)
~~~~~~~~

~~~~~~~~
PRK_2e (Raw Value) (32 bytes)
07 a0 8f 91 aa 6f 62 84 58 94 93 4c 04 4f f0 4b 43 96 ab 3c fd 49 31
d9 f0 15 5b 34 7d c4 11 ee
~~~~~~~~

Since METHOD = 0, R authenticates using signatures with the EDHOC signature algorithm ES256.
R's signature key pair using ECDSA with P-256:

~~~~~~~~
SK_R (Raw Value) (Responders's private authentication key) (32 bytes)
72 cc 47 61 db d4 c7 8f 75 89 31 aa 58 9d 34 8d 1e f8 74 a7 e3 03 ed
e2 f1 40 dc f3 e6 aa 4a ac
~~~~~~~~
~~~~~~~~
PK_R (Raw Value) (Responders's public authentication key) (65 bytes)
04 27 ec f4 b4 66 d3 cd 61 14 4c 94 40 21 83 8d 57 bf 67 01 97 33 78
a1 5b 3f 5d 27 57 5d 34 c4 a9 7b 79 e0 f2 4b 44 6b ca 67 e1 3d 75 d0
95 73 12 4b 49 b8 38 b1 09 73 f0 fb 67 e1 26 05 1c 95 95
~~~~~~~~

PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with signatures PRK_3e2m = PRK_2e.

~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
07 a0 8f 91 aa 6f 62 84 58 94 93 4c 04 4f f0 4b 43 96 ab 3c fd 49 31
d9 f0 15 5b 34 7d c4 11 ee
~~~~~~~~

R selects its connection identifier C_R to be the int -19

~~~~~~~~
C_R (Raw Value) (Connection identifier chosen by R) (int)
-8
~~~~~~~~
~~~~~~~~
C_R (CBOR Data Item) (Connection identifier chosen by R) (1 bytes)
27
~~~~~~~~

The transcript hash TH_2 is calculated using the EDHOC hash algorithm:

TH_2 = H(H(message_1), G_Y, C_R)

~~~~~~~~
H(message_1) (Raw Value) (32 bytes)
21 55 c4 97 9b 19 7e f8 c0 24 cf c0 83 56 dc 39 0f 0d 3b 1b 28 b3 66
d7 3d bb c7 01 ec ca 7c ff
~~~~~~~~

~~~~~~~~
H(message_1) (CBOR Data Item) (34 bytes)
58 20 21 55 c4 97 9b 19 7e f8 c0 24 cf c0 83 56 dc 39 0f 0d 3b 1b 28
b3 66 d7 3d bb c7 01 ec ca 7c ff
~~~~~~~~

The input to calculate TH_2 is the CBOR sequence:

H(message_1), G_Y, C_R

~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (70 bytes)
58 20 21 55 c4 97 9b 19 7e f8 c0 24 cf c0 83 56 dc 39 0f 0d 3b 1b 28
b3 66 d7 3d bb c7 01 ec ca 7c ff 58 21 02 13 fe 27 ad cd 01 d9 88 d0
ae 00 ec d3 fe 96 f3 ce 1e e4 64 90 87 39 0b 7d 24 d4 44 ff ad 67 2d
27
~~~~~~~~

~~~~~~~~
TH_2 (Raw Value) (32 bytes)
14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11 05 4d e8 54 c4 16 7f 6a 6e
40 e8 af 32 43 22 a4 d0 c8
~~~~~~~~

~~~~~~~~
TH_2 (CBOR Data Item) (34 bytes)
58 20 14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11 05 4d e8 54 c4 16 7f
6a 6e 40 e8 af 32 43 22 a4 d0 c8
~~~~~~~~

R constructs the remaining input needed to calculate MAC_2:

MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2",
            << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2)

CRED_R is identified by a 64-bit hash:

    ID_CRED_R =
    {
      34 : [-15, h'3480F5FA01A8ABF4']
    }

where the COSE header value 34 ('x5t') indicates a hash of an X.509 certficate,
and the COSE algorithm -15 indicates the hash algorithm SHA-256 truncated to 64 bits.

ID_CRED_R (CBOR Data Item) (14 bytes)
a1 18 22 82 2e 48 34 80 f5 fa 01 a8 ab f4

CRED_R is a CBOR byte string of the DER encoding of the X.509 certificate in {{resp-cer}}:

~~~~~~~~
CRED_R (Raw Value) (290 bytes)
3082011E3081C5A003020102020461E9981E300A06082A8648CE3D04030230153113
301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313330
325A170D3239313233313233303030305A301A3118301606035504030C0F4544484F
4320526573706F6E6465723059301306072A8648CE3D020106082A8648CE3D030107
03420004BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD
44F04519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072
300A06082A8648CE3D0403020348003045022030194EF5FC65C8B795CDCD0BB431BF
83EE6741C1370C22C8EB8EE9EDD2A70519022100B5830E9C89A62AC73CE1EBCE0061
707DB8A88E23709B4ACC58A1313B133D0558
~~~~~~~~

~~~~~~~~
CRED_R (CBOR Data Item) (293 bytes)
59 01 22 30 82 01 1e 30 81 c5 a0 03 02 01 02 02 04 61 e9 98 1e 30 0a
06 08 2a 86 48 ce 3d 04 03 02 30 15 31 13 30 11 06 03 55 04 03 0c 0a
45 44 48 4f 43 20 52 6f 6f 74 30 1e 17 0d 32 32 30 31 32 30 31 37 31
33 30 32 5a 17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 1a 31 18
30 16 06 03 55 04 03 0c 0f 45 44 48 4f 43 20 52 65 73 70 6f 6e 64 65
72 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01
07 03 42 00 04 bb c3 49 60 52 6e a4 d3 2e 94 0c ad 2a 23 41 48 dd c2
17 91 a1 2a fb cb ac 93 62 20 46 dd 44 f0 45 19 e2 57 23 6b 2a 0c e2
02 3f 09 31 f1 f3 86 ca 7a fd a6 4f cd e0 10 8c 22 4c 51 ea bf 60 72
30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 48 00 30 45 02 20 30 19 4e f5
fc 65 c8 b7 95 cd cd 0b b4 31 bf 83 ee 67 41 c1 37 0c 22 c8 eb 8e e9
ed d2 a7 05 19 02 21 00 b5 83 0e 9c 89 a6 2a c7 3c e1 eb ce 00 61 70
7d b8 a8 8e 23 70 9b 4a cc 58 a1 31 3b 13 3d 05 58
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_2 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_2 is computed through Expand() using the EDHOC hash algorithm, Section 4.2 of {{I-D.ietf-lake-edhoc}}:

MAC_2 = HKDF-Expand(PRK_3e2m, info, mac_length_2)

Since METHOD = 0, mac_length_2 is given by the EDHOC hash algorithm.

info for MAC_2 is:

    info =
    (
     h'1480DAEFC37F13E27CEE5E816D11054DE854C4167F6A6E40E8AF324322A4D0C8',
     "MAC_2",
     h'A11822822E483480F5FA01A8ABF45901223082011E3081C5A003020102020461E9
       981E300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320
       526F6F74301E170D3232303132303137313330325A170D32393132333132333030
       30305A301A3118301606035504030C0F4544484F4320526573706F6E6465723059
       301306072A8648CE3D020106082A8648CE3D03010703420004BBC34960526EA4D3
       2E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F04519E257236B2A0CE2
       023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072300A06082A8648CE3D04
       03020348003045022030194EF5FC65C8B795CDCD0BB431BF83EE6741C1370C22C8
       EB8EE9EDD2A70519022100B5830E9C89A62AC73CE1EBCE0061707DB8A88E23709B
       4ACC58A1313B133D0558',
     32
    )

where the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (352 bytes)
58 20 14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11 05 4d e8 54 c4 16 7f
6a 6e 40 e8 af 32 43 22 a4 d0 c8 65 4d 41 43 5f 32 59 01 33 a1 18 22
82 2e 48 34 80 f5 fa 01 a8 ab f4 59 01 22 30 82 01 1e 30 81 c5 a0 03
02 01 02 02 04 61 e9 98 1e 30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 15
31 13 30 11 06 03 55 04 03 0c 0a 45 44 48 4f 43 20 52 6f 6f 74 30 1e
17 0d 32 32 30 31 32 30 31 37 31 33 30 32 5a 17 0d 32 39 31 32 33 31
32 33 30 30 30 30 5a 30 1a 31 18 30 16 06 03 55 04 03 0c 0f 45 44 48
4f 43 20 52 65 73 70 6f 6e 64 65 72 30 59 30 13 06 07 2a 86 48 ce 3d
02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 bb c3 49 60 52 6e a4
d3 2e 94 0c ad 2a 23 41 48 dd c2 17 91 a1 2a fb cb ac 93 62 20 46 dd
44 f0 45 19 e2 57 23 6b 2a 0c e2 02 3f 09 31 f1 f3 86 ca 7a fd a6 4f
cd e0 10 8c 22 4c 51 ea bf 60 72 30 0a 06 08 2a 86 48 ce 3d 04 03 02
03 48 00 30 45 02 20 30 19 4e f5 fc 65 c8 b7 95 cd cd 0b b4 31 bf 83
ee 67 41 c1 37 0c 22 c8 eb 8e e9 ed d2 a7 05 19 02 21 00 b5 83 0e 9c
89 a6 2a c7 3c e1 eb ce 00 61 70 7d b8 a8 8e 23 70 9b 4a cc 58 a1 31
3b 13 3d 05 58 18 20
~~~~~~~~

~~~~~~~~
MAC_2 (Raw Value) (32 bytes)
5a e0 84 55 b1 43 bb 2f 2c 4a 89 07 03 af e4 df ea 65 e5 ad ff 44 7e
6c f0 93 fe 93 43 65 11 fa
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (34 bytes)
58 20 5a e0 84 55 b1 43 bb 2f 2c 4a 89 07 03 af e4 df ea 65 e5 ad ff
44 7e 6c f0 93 fe 93 43 65 11 fa
~~~~~~~~



Since METHOD = 0, Signature_or_MAC_2 is the 'signature' of the COSE_Sign1 object.

R constructs the message to be signed:

    [ "Signature1", << ID_CRED_R >>,
     << TH_2, CRED_R, ? EAD_2 >>, MAC_2 ] =

    [
     "Signature1",
     h'A11822822E4860780E9451BDC43C',
     h'58200782DBB687C30288A30B706B074BED789574573F24443E91833D68CDDD7F
       9B39586F000102030405060708090A0B0C0D0E0F101112131415161718191A1B
       1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B
       3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B
       5C5D5E5F606162636465666768696A6B6C6D6E',
     h'27C8F1E4A7AFF2A0F0BC0F918393EEF18B690C4D4C3D81BDFE22954240BCC4CC'
    ]

~~~~~~~~
Message to be signed 2 (CBOR Data Item) (391 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 34 80 f5 fa
01 a8 ab f4 59 01 47 58 20 14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11
05 4d e8 54 c4 16 7f 6a 6e 40 e8 af 32 43 22 a4 d0 c8 59 01 22 30 82
01 1e 30 81 c5 a0 03 02 01 02 02 04 61 e9 98 1e 30 0a 06 08 2a 86 48
ce 3d 04 03 02 30 15 31 13 30 11 06 03 55 04 03 0c 0a 45 44 48 4f 43
20 52 6f 6f 74 30 1e 17 0d 32 32 30 31 32 30 31 37 31 33 30 32 5a 17
0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 1a 31 18 30 16 06 03 55
04 03 0c 0f 45 44 48 4f 43 20 52 65 73 70 6f 6e 64 65 72 30 59 30 13
06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04
bb c3 49 60 52 6e a4 d3 2e 94 0c ad 2a 23 41 48 dd c2 17 91 a1 2a fb
cb ac 93 62 20 46 dd 44 f0 45 19 e2 57 23 6b 2a 0c e2 02 3f 09 31 f1
f3 86 ca 7a fd a6 4f cd e0 10 8c 22 4c 51 ea bf 60 72 30 0a 06 08 2a
86 48 ce 3d 04 03 02 03 48 00 30 45 02 20 30 19 4e f5 fc 65 c8 b7 95
cd cd 0b b4 31 bf 83 ee 67 41 c1 37 0c 22 c8 eb 8e e9 ed d2 a7 05 19
02 21 00 b5 83 0e 9c 89 a6 2a c7 3c e1 eb ce 00 61 70 7d b8 a8 8e 23
70 9b 4a cc 58 a1 31 3b 13 3d 05 58 58 20 5a e0 84 55 b1 43 bb 2f 2c
4a 89 07 03 af e4 df ea 65 e5 ad ff 44 7e 6c f0 93 fe 93 43 65 11 fa
~~~~~~~~

R signs using the private authentication key SK_R

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (64 bytes)
6b a1 fd c1 b8 8d 69 6b a5 23 1f b7 bc 2c 8a 2d 22 0d cf 91 b5 7b 98
14 60 ae b0 9f ae ff e4 bf 7d 8a 96 95 b6 37 60 dc 30 83 29 89 e1 2e
b1 e4 3f 8b 00 93 9a 13 9a 46 78 fd ad 47 da 7d 5d 6e
~~~~~~~~
~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (66 bytes)
58 40 6b a1 fd c1 b8 8d 69 6b a5 23 1f b7 bc 2c 8a 2d 22 0d cf 91 b5
7b 98 14 60 ae b0 9f ae ff e4 bf 7d 8a 96 95 b6 37 60 dc 30 83 29 89
e1 2e b1 e4 3f 8b 00 93 9a 13 9a 46 78 fd ad 47 da 7d 5d 6e
~~~~~~~~


R constructs the plaintext:

    PLAINTEXT_2 =
    (
     ID_CRED_R / bstr / int,
     Signature_or_MAC_2,
     ? EAD_2
    )

~~~~~~~~
PLAINTEXT_2 (CBOR Sequence) (80 bytes)
a1 18 22 82 2e 48 34 80 f5 fa 01 a8 ab f4 58 40 6b a1 fd c1 b8 8d 69
6b a5 23 1f b7 bc 2c 8a 2d 22 0d cf 91 b5 7b 98 14 60 ae b0 9f ae ff
e4 bf 7d 8a 96 95 b6 37 60 dc 30 83 29 89 e1 2e b1 e4 3f 8b 00 93 9a
13 9a 46 78 fd ad 47 da 7d 5d 6e
~~~~~~~~

The input needed to calculate KEYSTREAM_2 is defined in Section 4.2 of
{{I-D.ietf-lake-edhoc}}, using Expand() with the EDHOC hash algorithm:

    KEYSTREAM_2 = EDHOC-KDF(PRK_2e, TH_2, "KEYSTREAM_2", h'', length) =
                = HKDF-Expand(PRK_2e, info, length)

where length is the length of PLAINTEXT_2, and info for KEYSTREAM_2 is:

    info =
    (
     h'1480DAEFC37F13E27CEE5E816D11054DE854C4167F6A6E40E8AF324322A4D0C8',
     "KEYSTREAM_2",
     h'',
     80
    )

where the last value is the length of PLAINTEXT_2.

~~~~~~~~
info for KEYSTREAM_2 (CBOR Sequence) (49 bytes)
58 20 14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11 05 4d e8 54 c4 16 7f
6a 6e 40 e8 af 32 43 22 a4 d0 c8 6b 4b 45 59 53 54 52 45 41 4d 5f 32
40 18 50
~~~~~~~~

~~~~~~~~
KEYSTREAM_2 (Raw Value) (80 bytes)
ab e0 f8 46 1a 5f b9 55 79 c4 68 f3 dc 10 47 2a c6 67 39 89 f7 76 b5
b7 91 3d a8 8b c3 10 df 0f 81 91 7a ec 0b fb 77 11 ae 26 c6 47 bd 3c
23 aa 95 71 54 9e ce 28 c2 b4 f4 cb 07 35 65 91 de 65 90 87 2e 44 09
4d 0b a8 af ae 9c 08 30 c7 4d 59
~~~~~~~~

R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (80 bytes)
0a f8 da c4 34 17 8d d5 8c 3e 69 5b 77 e4 1f 6a ad c6 c4 48 4f fb dc
dc 34 1e b7 3c 7f 3c 55 22 a3 9c b5 7d be 80 ef 05 ce 88 76 d8 13 c3
c7 15 e8 fb c2 0b 78 1f a2 68 c4 48 2e bc 84 bf 6f 81 af 0c 2e d7 93
5e 91 ee d7 53 31 4f ea ba 10 37
~~~~~~~~

R constructs message_2:

    message_2 =
    (
     G_Y_CIPHERTEXT_2,
     C_R
    )

  where G_Y_CIPHERTEXT_2 is the bstr encoding of the concatenation of
  the raw values of G_Y and CIPHERTEXT_2.

~~~~~~~~
message_2 (CBOR Sequence) (116 bytes)
58 71 02 13 fe 27 ad cd 01 d9 88 d0 ae 00 ec d3 fe 96 f3 ce 1e e4 64
90 87 39 0b 7d 24 d4 44 ff ad 67 2d 0a f8 da c4 34 17 8d d5 8c 3e 69
5b 77 e4 1f 6a ad c6 c4 48 4f fb dc dc 34 1e b7 3c 7f 3c 55 22 a3 9c
b5 7d be 80 ef 05 ce 88 76 d8 13 c3 c7 15 e8 fb c2 0b 78 1f a2 68 c4
48 2e bc 84 bf 6f 81 af 0c 2e d7 93 5e 91 ee d7 53 31 4f ea ba 10 37
27
~~~~~~~~


## message_3

Since METHOD = 0, I authenticates using signatures with the EDHOC signature algorithm ES256.
I's signature key pair using ECDSA with P-256.

~~~~~~~~
SK_I (Raw Value) (Initiator's private authentication key) (32 bytes)
8e a3 ac 17 0f b9 00 ae 50 5b 18 74 7f b5 04 db da 74 8c 6d 0c 17 60
1d 7b a3 14 30 d7 45 17 8a
~~~~~~~~

~~~~~~~~
PK_I (Raw Value) (Responders's public authentication key) (65 bytes)
04 8a 93 ca 7e 1b c8 46 47 d7 e7 eb 4c 61 07 c4 dc 4e 53 df 81 df d1
98 1c 7f 82 4a 7c 1b 61 a6 fc 91 36 28 13 c2 5d b6 af 93 be 22 c3 50
ce b2 51 89 5b 9f 3a 8d 85 a3 58 23 a2 22 2b 9d e2 c8 c8
~~~~~~~~

PRK_4x3m is specified in Section 4.1.3 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with signatures PRK_4x3m = PRK_3e2m.

~~~~~~~~
PRK_4x3m (Raw Value) (32 bytes)
07 a0 8f 91 aa 6f 62 84 58 94 93 4c 04 4f f0 4b 43 96 ab 3c fd 49 31
d9 f0 15 5b 34 7d c4 11 ee
~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:

TH_3 = H(TH_2, CIPHERTEXT_2)

~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (116 bytes)
58 20 14 80 da ef c3 7f 13 e2 7c ee 5e 81 6d 11 05 4d e8 54 c4 16 7f
6a 6e 40 e8 af 32 43 22 a4 d0 c8 58 50 0a f8 da c4 34 17 8d d5 8c 3e
69 5b 77 e4 1f 6a ad c6 c4 48 4f fb dc dc 34 1e b7 3c 7f 3c 55 22 a3
9c b5 7d be 80 ef 05 ce 88 76 d8 13 c3 c7 15 e8 fb c2 0b 78 1f a2 68
c4 48 2e bc 84 bf 6f 81 af 0c 2e d7 93 5e 91 ee d7 53 31 4f ea ba 10
37
~~~~~~~~

~~~~~~~~
TH_3 (Raw Value) (32 bytes)
9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2 dd b7
42 fb 00 77 21 fe 02 08 7f
~~~~~~~~

~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2
dd b7 42 fb 00 77 21 fe 02 08 7f
~~~~~~~~

I constructs the remaining input needed to calculate MAC_3:

    MAC_3 = EDHOC-KDF(PRK_4x3m, TH_3, "MAC_3",
            << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3)

CRED_I is identified by a 64-bit hash:

    ID_CRED_I =
    {
      34 : [-15, h'81D45BE06329D63A']
    }

where the COSE header value 34 ('x5t') indicates a hash of an X.509 certficate,
and the COSE algorithm -15 indicates the hash algorithm SHA-256 truncated to 64 bits.

~~~~~~~~
ID_CRED_I (CBOR Data Item) (14 bytes)
a1 18 22 82 2e 48 64 54 72 0f f0 db 4b 1a
~~~~~~~~

CRED_I is a CBOR byte string of the DER encoding of the X.509 certificate in {{init-cer}}:

~~~~~~~~
CRED_I (Raw Value) (290 bytes)
3082011E3081C5A003020102020461E997F4300A06082A8648CE3D04030230153113
301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313232
305A170D3239313233313233303030305A301A3118301606035504030C0F4544484F
4320496E69746961746F723059301306072A8648CE3D020106082A8648CE3D030107
034200048A93CA7E1BC84647D7E7EB4C6107C4DC4E53DF81DFD1981C7F824A7C1B61
A6FC91362813C25DB6AF93BE22C350CEB251895B9F3A8D85A35823A2222B9DE2C8C8
300A06082A8648CE3D0403020348003045022032FCFCA3E80488515EC11EF570C6B8
33B430DCBDD327D965F22D4AD2D34E07090221008BBFECD263F699E5E23CBEC58478
6FF5EA18E23236E511D956935FFF281720AE
~~~~~~~~

~~~~~~~~
CRED_I (CBOR Data Item) (293 bytes)
59 01 22 30 82 01 1e 30 81 c5 a0 03 02 01 02 02 04 61 e9 97 f4 30 0a
06 08 2a 86 48 ce 3d 04 03 02 30 15 31 13 30 11 06 03 55 04 03 0c 0a
45 44 48 4f 43 20 52 6f 6f 74 30 1e 17 0d 32 32 30 31 32 30 31 37 31
32 32 30 5a 17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 1a 31 18
30 16 06 03 55 04 03 0c 0f 45 44 48 4f 43 20 49 6e 69 74 69 61 74 6f
72 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01
07 03 42 00 04 8a 93 ca 7e 1b c8 46 47 d7 e7 eb 4c 61 07 c4 dc 4e 53
df 81 df d1 98 1c 7f 82 4a 7c 1b 61 a6 fc 91 36 28 13 c2 5d b6 af 93
be 22 c3 50 ce b2 51 89 5b 9f 3a 8d 85 a3 58 23 a2 22 2b 9d e2 c8 c8
30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 48 00 30 45 02 20 32 fc fc a3
e8 04 88 51 5e c1 1e f5 70 c6 b8 33 b4 30 dc bd d3 27 d9 65 f2 2d 4a
d2 d3 4e 07 09 02 21 00 8b bf ec d2 63 f6 99 e5 e2 3c be c5 84 78 6f
f5 ea 18 e2 32 36 e5 11 d9 56 93 5f ff 28 17 20 ae
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_3 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_3 is computed through Expand() using the
EDHOC hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    MAC_3 = HKDF-Expand(PRK_4x3m, info, mac_length_3)

Since METHOD = 0, mac_length_3 is given by the EDHOC hash algorithm.

info for MAC_3 is:

    info =
    (
     h'9E8C2201AB4F40012304B05D5C5E1C1E5EEDEED4F2DDB742FB007721FE02087F',
     "MAC_3",
     h'A11822822E486454720FF0DB4B1A5901223082011E3081C5A003020102020461E9
       97F4300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320
       526F6F74301E170D3232303132303137313232305A170D32393132333132333030
       30305A301A3118301606035504030C0F4544484F4320496E69746961746F723059
       301306072A8648CE3D020106082A8648CE3D030107034200048A93CA7E1BC84647
       D7E7EB4C6107C4DC4E53DF81DFD1981C7F824A7C1B61A6FC91362813C25DB6AF93
       BE22C350CEB251895B9F3A8D85A35823A2222B9DE2C8C8300A06082A8648CE3D04
       03020348003045022032FCFCA3E80488515EC11EF570C6B833B430DCBDD327D965
       F22D4AD2D34E07090221008BBFECD263F699E5E23CBEC584786FF5EA18E23236E5
       11D956935FFF281720AE',
     32
    )

where the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (352 bytes)
58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2
dd b7 42 fb 00 77 21 fe 02 08 7f 65 4d 41 43 5f 33 59 01 33 a1 18 22
82 2e 48 64 54 72 0f f0 db 4b 1a 59 01 22 30 82 01 1e 30 81 c5 a0 03
02 01 02 02 04 61 e9 97 f4 30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 15
31 13 30 11 06 03 55 04 03 0c 0a 45 44 48 4f 43 20 52 6f 6f 74 30 1e
17 0d 32 32 30 31 32 30 31 37 31 32 32 30 5a 17 0d 32 39 31 32 33 31
32 33 30 30 30 30 5a 30 1a 31 18 30 16 06 03 55 04 03 0c 0f 45 44 48
4f 43 20 49 6e 69 74 69 61 74 6f 72 30 59 30 13 06 07 2a 86 48 ce 3d
02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 8a 93 ca 7e 1b c8 46
47 d7 e7 eb 4c 61 07 c4 dc 4e 53 df 81 df d1 98 1c 7f 82 4a 7c 1b 61
a6 fc 91 36 28 13 c2 5d b6 af 93 be 22 c3 50 ce b2 51 89 5b 9f 3a 8d
85 a3 58 23 a2 22 2b 9d e2 c8 c8 30 0a 06 08 2a 86 48 ce 3d 04 03 02
03 48 00 30 45 02 20 32 fc fc a3 e8 04 88 51 5e c1 1e f5 70 c6 b8 33
b4 30 dc bd d3 27 d9 65 f2 2d 4a d2 d3 4e 07 09 02 21 00 8b bf ec d2
63 f6 99 e5 e2 3c be c5 84 78 6f f5 ea 18 e2 32 36 e5 11 d9 56 93 5f
ff 28 17 20 ae 18 20
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (32 bytes)
4c 64 f4 f1 81 a5 f0 c5 01 5c ed ce 3d 81 c6 ec b4 2b 46 d0 cf fe 6b
8b 96 93 2c f3 e8 fb 5a 84
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (34 bytes)
58 20 4c 64 f4 f1 81 a5 f0 c5 01 5c ed ce 3d 81 c6 ec b4 2b 46 d0 cf
fe 6b 8b 96 93 2c f3 e8 fb 5a 84
~~~~~~~~

Since METHOD = 0, Signature_or_MAC_3 is the 'signature' of the
COSE_Sign1 object.

I constructs the message to be signed:

    [ "Signature1", << ID_CRED_I >>,
     << TH_3, CRED_I, ? EAD_3 >>, MAC_3 ] =

    [
     "Signature1",
     h'A11822822E486454720FF0DB4B1A',
     h'58209E8C2201AB4F40012304B05D5C5E1C1E5EEDEED4F2DDB742FB007721FE020
       87F5901223082011E3081C5A003020102020461E997F4300A06082A8648CE3D04
       030230153113301106035504030C0A4544484F4320526F6F74301E170D3232303
       132303137313232305A170D3239313233313233303030305A301A311830160603
       5504030C0F4544484F4320496E69746961746F723059301306072A8648CE3D020
       106082A8648CE3D030107034200048A93CA7E1BC84647D7E7EB4C6107C4DC4E53
       DF81DFD1981C7F824A7C1B61A6FC91362813C25DB6AF93BE22C350CEB251895B9
       F3A8D85A35823A2222B9DE2C8C8300A06082A8648CE3D04030203480030450220
       32FCFCA3E80488515EC11EF570C6B833B430DCBDD327D965F22D4AD2D34E07090
       221008BBFECD263F699E5E23CBEC584786FF5EA18E23236E511D956935FFF2817
       20AE',
     h'4C64F4F181A5F0C5015CEDCE3D81C6ECB42B46D0CFFE6B8B96932CF3E8FB5A84'
    ]

~~~~~~~~
Message to be signed 3 (CBOR Data Item) (236 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 64 54 72 0f
f0 db 4b 1a 59 01 47 58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e
1c 1e 5e ed ee d4 f2 dd b7 42 fb 00 77 21 fe 02 08 7f 59 01 22 30 82
01 1e 30 81 c5 a0 03 02 01 02 02 04 61 e9 97 f4 30 0a 06 08 2a 86 48
ce 3d 04 03 02 30 15 31 13 30 11 06 03 55 04 03 0c 0a 45 44 48 4f 43
20 52 6f 6f 74 30 1e 17 0d 32 32 30 31 32 30 31 37 31 32 32 30 5a 17
0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 1a 31 18 30 16 06 03 55
04 03 0c 0f 45 44 48 4f 43 20 49 6e 69 74 69 61 74 6f 72 30 59 30 13
06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04
8a 93 ca 7e 1b c8 46 47 d7 e7 eb 4c 61 07 c4 dc 4e 53 df 81 df d1 98
1c 7f 82 4a 7c 1b 61 a6 fc 91 36 28 13 c2 5d b6 af 93 be 22 c3 50 ce
b2 51 89 5b 9f 3a 8d 85 a3 58 23 a2 22 2b 9d e2 c8 c8 30 0a 06 08 2a
86 48 ce 3d 04 03 02 03 48 00 30 45 02 20 32 fc fc a3 e8 04 88 51 5e
c1 1e f5 70 c6 b8 33 b4 30 dc bd d3 27 d9 65 f2 2d 4a d2 d3 4e 07 09
02 21 00 8b bf ec d2 63 f6 99 e5 e2 3c be c5 84 78 6f f5 ea 18 e2 32
36 e5 11 d9 56 93 5f ff 28 17 20 ae 58 20 4c 64 f4 f1 81 a5 f0 c5 01
5c ed ce 3d 81 c6 ec b4 2b 46 d0 cf fe 6b 8b 96 93 2c f3 e8 fb 5a 84
~~~~~~~~

R signs using the private authentication key SK_R:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (64 bytes)
19 1a 6f d0 67 d9 4c d0 cf 6b ac b4 21 82 ac b5 dc de 75 e3 83 82 2f
81 02 33 c1 a4 85 db 6e e4 b1 69 7b 9a 32 1b 06 1f 9d f5 3e 2b 00 0f
00 ff 24 5d 43 26 e2 0c 47 3a d8 53 b5 d3 71 70 78 e7
~~~~~~~~

~~~~~~~~
Signature_or_MAC_3 (CBOR Data Item) (66 bytes)
58 40 19 1a 6f d0 67 d9 4c d0 cf 6b ac b4 21 82 ac b5 dc de 75 e3 83
82 2f 81 02 33 c1 a4 85 db 6e e4 b1 69 7b 9a 32 1b 06 1f 9d f5 3e 2b
00 0f 00 ff 24 5d 43 26 e2 0c 47 3a d8 53 b5 d3 71 70 78 e7
~~~~~~~~

R constructs the plaintext:

    P_3 =
    (
     ID_CRED_I / bstr / int,
     Signature_or_MAC_3,
     ? EAD_3
    )

~~~~~~~~
P_3 (CBOR Sequence) (80 bytes)
a1 18 22 82 2e 48 64 54 72 0f f0 db 4b 1a 58 40 19 1a 6f d0 67 d9 4c
d0 cf 6b ac b4 21 82 ac b5 dc de 75 e3 83 82 2f 81 02 33 c1 a4 85 db
6e e4 b1 69 7b 9a 32 1b 06 1f 9d f5 3e 2b 00 0f 00 ff 24 5d 43 26 e2
0c 47 3a d8 53 b5 d3 71 70 78 e7
~~~~~~~~

I constructs the associated data for message_3:

    A_3 =
    (
     "Encrypt0",
     h'',
     TH_3
    )

~~~~~~~~
A_3 (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 9e 8c 22 01 ab 4f 40 01 23 04
b0 5d 5c 5e 1c 1e 5e ed ee d4 f2 dd b7 42 fb 00 77 21 fe 02 08 7f
~~~~~~~~

I constructs the input needed to derive the key K_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3 = EDHOC-KDF(PRK_3e2m, TH_3, "K_3", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

where length is the key length of EDHOC AEAD algorithm, and info for K_3 is:

    info =
    (
     h'23CE4296FC64AB048A593B6711E4822011BB58D85D3798B081A9BD12A3317A82',
     "K_3",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.


~~~~~~~~
info for K_3 (CBOR Sequence) (40 bytes)
58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2
dd b7 42 fb 00 77 21 fe 02 08 7f 63 4b 5f 33 40 10
~~~~~~~~

~~~~~~~~
K_3 (Raw Value) (16 bytes)
5e 65 d6 b0 7b eb 01 bd 9f c6 4a 8d 90 0f 6e 30
~~~~~~~~

I constructs the input needed to derive the nonce IV_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3 = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

where length is the nonce length of EDHOC AEAD algorithm, and info for IV_3 is:

    info =
    (
     h'23CE4296FC64AB048A593B6711E4822011BB58D85D3798B081A9BD12A3317A82',
     "IV_3",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3 (CBOR Sequence) (41 bytes)
58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2
dd b7 42 fb 00 77 21 fe 02 08 7f 64 49 56 5f 33 40 0d
~~~~~~~~

~~~~~~~~
IV_3 (Raw Value) (13 bytes)
d4 9d e0 89 d4 b3 aa e3 36 e3 29 d3 4c
~~~~~~~~

I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_3, additional data
A_3, key K_3 and nonce IV_3.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (88 bytes)
98 d7 3d 60 4c 06 ca d2 34 de 9c 75 14 10 91 3c 60 65 b7 ea bf 76 08
eb 42 d6 69 1f fa a1 ab c1 20 d7 b9 ae 1b bc 15 a1 8e ff cb be 97 c1
44 75 0f 09 52 70 b2 bb 7b 08 27 be 0f d7 9f aa 79 e3 5a ac 6e 07 a5
07 81 fd 0f 18 9a c7 a1 79 a4 84 0f a5 85 13 6d 17 97 a4
~~~~~~~~

message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (90 bytes)
58 58 98 d7 3d 60 4c 06 ca d2 34 de 9c 75 14 10 91 3c 60 65 b7 ea bf
76 08 eb 42 d6 69 1f fa a1 ab c1 20 d7 b9 ae 1b bc 15 a1 8e ff cb be
97 c1 44 75 0f 09 52 70 b2 bb 7b 08 27 be 0f d7 9f aa 79 e3 5a ac 6e
07 a5 07 81 fd 0f 18 9a c7 a1 79 a4 84 0f a5 85 13 6d 17 97 a4
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (124 bytes)
58 20 9e 8c 22 01 ab 4f 40 01 23 04 b0 5d 5c 5e 1c 1e 5e ed ee d4 f2
dd b7 42 fb 00 77 21 fe 02 08 7f 58 58 98 d7 3d 60 4c 06 ca d2 34 de
9c 75 14 10 91 3c 60 65 b7 ea bf 76 08 eb 42 d6 69 1f fa a1 ab c1 20
d7 b9 ae 1b bc 15 a1 8e ff cb be 97 c1 44 75 0f 09 52 70 b2 bb 7b 08
27 be 0f d7 9f aa 79 e3 5a ac 6e 07 a5 07 81 fd 0f 18 9a c7 a1 79 a4
84 0f a5 85 13 6d 17 97 a4
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca d2 25
0b f2 25 9a 5d 69 f6 c0 75
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca
d2 25 0b f2 25 9a 5d 69 f6 c0 75
~~~~~~~~


## message_4

No external authorization data:

~~~~~~~~
EAD_4 (CBOR Sequence) (0 bytes)
~~~~~~~~

R constructs the plaintext P_4:

    P_4 =
    (
     ? EAD_4
    )

~~~~~~~~
P_4 (CBOR Sequence) (0 bytes)
~~~~~~~~

R constructs the associated data for message_4:

    A_4 =
    (
     "Encrypt0",
     h'',
     TH_4
    )

~~~~~~~~
A_4 (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 9e d6 46 8f 27 b7 0f 2f 89 f3
0a a2 e9 bd 6b 4f f1 6d fe 54 ca d2 25 0b f2 25 9a 5d 69 f6 c0 75
~~~~~~~~

R constructs the input needed to derive the EDHOC message_4 key, see
Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_4 = EDHOC-Exporter("EDHOC_K_4", h'', length)
          = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_K_4", h'', length)
          = HKDF-Expand(PRK_4x3m, info, length)

  where length is the key length of the EDHOC AEAD algorithm,
  and info for EDHOC_K_4 is:

    info =
    (
     h'9ED6468F27B70F2F89F30AA2E9BD6B4FF16DFE54CAD2250BF2259A5D69F6C075',
     "EDHOC_K_4",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_4 (CBOR Sequence) (46 bytes)
58 20 9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca
d2 25 0b f2 25 9a 5d 69 f6 c0 75 69 45 44 48 4f 43 5f 4b 5f 34 40 10
~~~~~~~~

~~~~~~~~
K_4 (Raw Value) (16 bytes)
d0 a1 81 cd 96 3a 07 79 80 b2 6e bb bd 3b f7 62
~~~~~~~~

 R constructs the input needed to derive the EDHOC message_4 nonce, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

           IV_4 =
           = EDHOC-Exporter( "EDHOC_IV_4", h'', length )
           = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_IV_4", h'', length)
           = HKDF-Expand(PRK_4x3m, info, length)

  where length is the nonce length of EDHOC AEAD algorithm,
  and info for EDHOC_IV_4 is:

    info =
    (
     h'9ED6468F27B70F2F89F30AA2E9BD6B4FF16DFE54CAD2250BF2259A5D69F6C075',
     "EDHOC_IV_4",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4 (CBOR Sequence) (47 bytes)
58 20 9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca
d2 25 0b f2 25 9a 5d 69 f6 c0 75 6a 45 44 48 4f 43 5f 49 56 5f 34 40
0d
~~~~~~~~

~~~~~~~~
IV_4 (Raw Value) (13 bytes)
13 ce 5d 07 87 f0 27 68 25 bd 23 f8 36
~~~~~~~~

R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_4, additional data
A_4, key K_4 and nonce IV_4.


~~~~~~~~
CIPHERTEXT_4 (8 bytes)
97 28 04 fb e1 f3 00 2d
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 97 28 04 fb e1 f3 00 2d
~~~~~~~~


## OSCORE Parameters

The derivation of OSCORE parameters is specified in Appendix A.2 of {{I-D.ietf-lake-edhoc}}.

The AEAD and Hash algorithms to use in OSCORE are given by the selected cipher suite:

~~~~~~~~
Application AEAD Algorithm (int)
10
~~~~~~~~

~~~~~~~~
Application Hash Algorithm (int)
-16
~~~~~~~~

The mapping from EDHOC connection identifiers to OSCORE Sender/Recipient IDs is defined in Appendix A.1 of {{I-D.ietf-lake-edhoc}}.

C_R is mapped to the Recipient ID of the server, i.e., the Sender ID of the client. Since C_R is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Client's OSCORE Sender ID (Raw Value) (1 bytes)
27
~~~~~~~~

C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server. Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
37
~~~~~~~~

The OSCORE Master Secret is computed through Expand() using the
Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Secret =
    = EDHOC-Exporter("OSCORE_Secret", h'', key_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Secret", h'', key_length)
    = HKDF-Expand(PRK_4x3m, info, key_length)

where key_length is by default the key length of the Application AEAD
algorithm, and info for the OSCORE Master Secret is:

    info =
    (
     h'9ED6468F27B70F2F89F30AA2E9BD6B4FF16DFE54CAD2250BF2259A5D69F6C075',
     "OSCORE_Secret",
     h'',
     16
    )

where the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (50 bytes)
58 20 9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca
d2 25 0b f2 25 9a 5d 69 f6 c0 75 6d 4f 53 43 4f 52 45 5f 53 65 63 72
65 74 40 10
~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
fa e3 e2 8d d1 bc d5 e7 94 66 ec 9d 9d 79 90 dc
~~~~~~~~

The OSCORE Master Salt is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE_Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

where salt_length is the length of the OSCORE Master Salt, and info for the OSCORE Master Salt is:

    info =
    (
     h'9ED6468F27B70F2F89F30AA2E9BD6B4FF16DFE54CAD2250BF2259A5D69F6C075',
     "OSCORE_Salt",
     h'',
     8
    )

where the last value is the length of the OSCORE Master Salt.

~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (48 bytes)
58 20 9e d6 46 8f 27 b7 0f 2f 89 f3 0a a2 e9 bd 6b 4f f1 6d fe 54 ca
d2 25 0b f2 25 9a 5d 69 f6 c0 75 6b 4f 53 43 4f 52 45 5f 53 61 6c 74
40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
1f 3d 2f 2b e8 d8 bb ab
~~~~~~~~


## Key Update

Key update is defined in Section 4.4 of {{I-D.ietf-lake-edhoc}}.

    EDHOC-KeyUpdate(nonce):
    PRK_4x3m = Extract(nonce, PRK_4x3m)

~~~~~~~~
KeyUpdate Nonce (Raw Value) (16 bytes)
05 bd 1f fd 85 c5 46 da 86 3c 97 0a 34 b7 43 a3
~~~~~~~~

~~~~~~~~
PRK_4x3m after KeyUpdate (Raw Value) (32 bytes)
9b c6 ee 56 ae 8b 3a b9 55 ff 4e 63 17 31 d9 47 e8 50 7a 79 1c f2 ee
71 bd 12 3e 4c 58 5e f9 75
~~~~~~~~

The OSCORE Master Secret is derived with the updated PRK_4x3m:

    OSCORE Master Secret = HKDF-Expand(PRK_4x3m, info, key_length)

where info and key_length are unchanged.

~~~~~~~~
OSCORE Master Secret after KeyUpdate (Raw Value) (16 bytes)
a4 74 30 91 e4 a3 84 3a 3a 06 6c 6b f8 f2 0a 30
~~~~~~~~

The OSCORE Master Salt is derived with the updated PRK_4x3m:

    OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
db 5f 77 14 b9 b7 ae 2a
~~~~~~~~

## Certificates



### Responder Certificate {#resp-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1642698782 (0x61e9981e)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=EDHOC Root
        Validity
            Not Before: Jan 20 17:13:02 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN=EDHOC Responder
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:bb:c3:49:60:52:6e:a4:d3:2e:94:0c:ad:2a:23:
                    41:48:dd:c2:17:91:a1:2a:fb:cb:ac:93:62:20:46:
                    dd:44:f0:45:19:e2:57:23:6b:2a:0c:e2:02:3f:09:
                    31:f1:f3:86:ca:7a:fd:a6:4f:cd:e0:10:8c:22:4c:
                    51:ea:bf:60:72
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:30:19:4e:f5:fc:65:c8:b7:95:cd:cd:0b:b4:31:
         bf:83:ee:67:41:c1:37:0c:22:c8:eb:8e:e9:ed:d2:a7:05:19:
         02:21:00:b5:83:0e:9c:89:a6:2a:c7:3c:e1:eb:ce:00:61:70:
         7d:b8:a8:8e:23:70:9b:4a:cc:58:a1:31:3b:13:3d:05:58
~~~~~~~~

### Initiator Certificate {#init-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1642698740 (0x61e997f4)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=EDHOC Root
        Validity
            Not Before: Jan 20 17:12:20 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN=EDHOC Initiator
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8a:93:ca:7e:1b:c8:46:47:d7:e7:eb:4c:61:07:
                    c4:dc:4e:53:df:81:df:d1:98:1c:7f:82:4a:7c:1b:
                    61:a6:fc:91:36:28:13:c2:5d:b6:af:93:be:22:c3:
                    50:ce:b2:51:89:5b:9f:3a:8d:85:a3:58:23:a2:22:
                    2b:9d:e2:c8:c8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:32:fc:fc:a3:e8:04:88:51:5e:c1:1e:f5:70:c6:
         b8:33:b4:30:dc:bd:d3:27:d9:65:f2:2d:4a:d2:d3:4e:07:09:
         02:21:00:8b:bf:ec:d2:63:f6:99:e5:e2:3c:be:c5:84:78:6f:
         f5:ea:18:e2:32:36:e5:11:d9:56:93:5f:ff:28:17:20:ae
~~~~~~~~


### Common Root Certificate {#root-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1642698693 (0x61e997c5)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=EDHOC Root
        Validity
            Not Before: Jan 20 17:11:33 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN=EDHOC Root
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:27:ec:f4:b4:66:d3:cd:61:14:4c:94:40:21:83:
                    8d:57:bf:67:01:97:33:78:a1:5b:3f:5d:27:57:5d:
                    34:c4:a9:7b:79:e0:f2:4b:44:6b:ca:67:e1:3d:75:
                    d0:95:73:12:4b:49:b8:38:b1:09:73:f0:fb:67:e1:
                    26:05:1c:95:95
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:13:73:43:26:f2:ca:35:d1:ae:db:6d:5e:1c:8e:
         b7:b9:65:da:67:ea:d3:31:4e:50:29:09:b9:d7:57:cb:a1:68:
         02:20:49:ba:0b:a4:f0:6e:fe:8c:0d:9c:3d:31:15:eb:9c:96:
         ca:46:d1:28:49:9b:68:95:7d:0a:85:af:13:6b:f3:06
~~~~~~~~



# Security Considerations {#security}

This document contains examples of EDHOC {{I-D.ietf-lake-edhoc}} whose security considerations apply. The keys printed in these examples cannot be considered secret and must not be used.

# IANA Considerations {#iana}

There are no IANA considerations.

--- back


# Acknowledgments
{: numbered="no"}

--- fluff
