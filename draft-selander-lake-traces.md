---
title: Traces of EDHOC
docname: draft-selander-lake-traces-latest
abbrev:

ipr: trust200902
cat: std

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
- name: Göran Selander
  surname: Selander
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: goran.selander@ericsson.com
- name: John Preuß Mattsson
  initials: J
  surname: Preuß Mattsson
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.mattsson@ericsson.com

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


# Setup

EDHOC is run between an Initiator (I) and a Responder (R). The private/public key pairs and credentials of I and R required to produce the protocol messages are shown in the traces when needed for the calculations.

Both I and R are assumed to support cipher suite 0, which determines the algorithms:

* EDHOC AEAD algorithm = AES-CCM-16-64-128
* EDHOC hash algorithm = SHA-256
* EDHOC MAC length in bytes (Static DH) = 8
* EDHOC key exchange algorithm (ECDH curve) = X25519 
* EDHOC signature algorithm = EdDSA
* Application AEAD algorithm = AES-CCM-16-64-128
* Application hash algorithm = SHA-256

External authorization data (EAD) is not used in these examples.

EDHOC messages and intermediate results are encoded in CBOR {{RFC8949}} and can therefore be displayed in CBOR diagnostic notation using, e.g., the CBOR playground {{CborMe}}, which makes them easy to parse for humans.

NOTE 1. The same name is used for hexadecimal byte strings and their CBOR encodings. The traces contain both the raw byte strings and the corresponding CBOR encoded data items.

NOTE 2. If not clear from the context, remember that CBOR sequences and CBOR arrays assume CBOR encoded data items as elements.

A more extensive test vector suite and related code that was used to generate them can be found at: https://github.com/lake-wg/edhoc/tree/master/test-vectors-10.

# Authentication with static DH, RPK identified by 'kid'

In this example I and R are authenticated with ephemeral-static Diffie-Hellman (METHOD = 3). The public keys are represented as raw public keys (RPK), encoded in an unprotected CWT claims set (UCCS) and identified by the COSE header parameter 'kid'. 


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

  Then, PRK_2e is calculated using Extract() determined by the EDHOC hash
  algorithm:

    PRK_2e = Extract(salt, G_XY) =
           = HMAC-SHA-256(salt, G_XY)

  where salt is the empty byte string:

~~~~~~~~
salt (Raw Value) (0 bytes)
~~~~~~~~
~~~~~~~~
PRK_2e (Raw Value) (32 bytes)
d1 d0 11 a5 9a 6d 10 57 5e b2 20 c7 65 2e 6f 98 c4 17 a5 65 e4 e4 5c
f5 b5 01 06 95 04 3b 0e b7
~~~~~~~~

  Since METHOD = 3, R authenticates using static DH.
  R's static key pair for use with the EDHOC key exchange algorithm is:

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

  R selects its connection identifier C_R to be the empty bstr h'':

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

  CRED_R is an RPK encoded as a UCCS:

    {                                              /UCCS/
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
     10,
     h'71A6C7C5BA9AD47FE72DA4DC359BF6B276D3515968711B9A911C71FC096AEE0E',
     "MAC_2",
     h'A10405A2026B6578616D706C652E65647508A101A4010102052004215820E6
       6F355990223C3F6CAFF862E407EDD1174D0701A09ECD6A15CEE2C6CE21AA50',
     8
    )

where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, and the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (106 bytes)
68 71 1b 9a 91 1c 71 fc 09 6a ee 0e 65 4d 41 43 5f 32 58 3e a1 04 05
a2 02 6b 65 78 61 6d 70 6c 65 2e 65 64 75 08 a1 01 a4 01 01 02 05 20
04 21 58 20 e6 6f 35 59 90 22 3c 3f 6c af f8 62 e4 07 ed d1 17 4d 07
01 a0 9e cd 6a 15 ce e2 c6 ce 21 aa 50 08
~~~~~~~~
~~~~~~~~
MAC_2 (Raw Value) (8 bytes)
25 d3 a6 26 83 c9 54 e4
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (9 bytes)
48 25 d3 a6 26 83 c9 54 e4
~~~~~~~~

Since METHOD = 3, Signature_or_MAC_2 is MAC_2:

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (8 bytes)
25 d3 a6 26 83 c9 54 e4
~~~~~~~~

~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (9 bytes)
48 25 d3 a6 26 83 c9 54 e4
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
05 48 25 d3 a6 26 83 c9 54 e4
~~~~~~~~

The input needed to calculate KEYSTREAM_2 is defined in Section 4.2 of {{I-D.ietf-lake-edhoc}}, using Expand() with the EDHOC hash algorithm:

    KEYSTREAM_2 = EDHOC-KDF(PRK_2e, TH_2, "KEYSTREAM_2", h'', length) =
                = HKDF-Expand(PRK_2e, info, length),

where length is the length of PLAINTEXT_2, and info for KEYSTREAM_2 is:

    info =
    (
     10,
     h'71A6C7C5BA9AD47FE72DA4DC359BF6B276D3515968711B9A911C71FC096AEE0E',
     "KEYSTREAM_2",
     h'',
     10
    )

where the first value is the COSE algorithm value of the EDHOC AEAD algorithm and the last value is the length of PLAINTEXT_2

~~~~~~~~
info for KEYSTREAM_2 (CBOR Sequence) (49 bytes)
0a 58 20 71 a6 c7 c5 ba 9a d4 7f e7 2d a4 dc 35 9b f6 b2 76 d3 51 59
68 71 1b 9a 91 1c 71 fc 09 6a ee 0e 6b 4b 45 59 53 54 52 45 41 4d 5f
32 40 0a
~~~~~~~~
~~~~~~~~
KEYSTREAM_2 (Raw Value) (10 bytes)
b7 20 d1 30 db 51 5a 64 7d 01
~~~~~~~~

R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (10 bytes)
b2 68 f4 e3 7d 77 d9 ad 29 e5
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
d9 48 01 8b 41 90 f7 d1 61 82 4e b2 68 f4 e3 7d 77 d9 ad 29 e5 40
~~~~~~~~


## message_3

Since METHOD = 3, I authenticates using static DH.
  
I's static key pair for use with the EDHOC key exchange algorithm is:

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
71 1b 9a 91 1c 71 fc 09 6a ee 0e 4a b2 68 f4 e3 7d 77 d9 ad 29 e5
~~~~~~~~
  
~~~~~~~~
TH_3 (Raw Value) (32 bytes)
95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1 70 d4 9a
2b c3 87 4b 43 ae 18 29 18
~~~~~~~~
~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1 70
d4 9a 2b c3 87 4b 43 ae 18 29 18
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

  CRED_I is an RPK encoded as a UCCS:

    {                                              /UCCS/
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

  MAC_3 is computed through Expand() using the 
  EDHOC hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    MAC_3 = HKDF-Expand(PRK_4x3m, info, mac_length_3)

  Since METHOD = 3, mac_length_3 is given by the EDHOC MAC length.

  info for MAC_3 is:

    info =
    (
     10,
     h'952B9B9CDD53B6A792604F845E2BFB5406292AA170D49A2BC3874B43AE182918',
     "MAC_3",
     h'A10429A2027734322D35302D33312D46462D45462D33372D33322D333908A101
       A40101022920042158204A49D88CD5D841FAB7EF983E911D2578861F95884F9F
       5DC42A2EED33DE79ED77',
     8
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm,
  and the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (118 bytes)
0a 58 20 95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1
70 d4 9a 2b c3 87 4b 43 ae 18 29 18 65 4d 41 43 5f 33 58 4a a1 04 29
a2 02 77 34 32 2d 35 30 2d 33 31 2d 46 46 2d 45 46 2d 33 37 2d 33 32
2d 33 39 08 a1 01 a4 01 01 02 29 20 04 21 58 20 4a 49 d8 8c d5 d8 41
fa b7 ef 98 3e 91 1d 25 78 86 1f 95 88 4f 9f 5d c4 2a 2e ed 33 de 79
ed 77 08
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (8 bytes)
b1 b6 ba a5 b7 8c cd 39
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (9 bytes)
48 b1 b6 ba a5 b7 8c cd 39
~~~~~~~~

  Since METHOD = 3, Signature_or_MAC_3 is MAC_3:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (8 bytes)
b1 b6 ba a5 b7 8c cd 39
~~~~~~~~

~~~~~~~~
Signature_or_MAC_3 (CBOR Data Item) (9 bytes)
48 b1 b6 ba a5 b7 8c cd 39
~~~~~~~~

  I constructs the plaintext P_3ae:

    P_3ae =
    (
     ID_CRED_I / bstr / int,
     Signature_or_MAC_3,
     ? EAD_3
    )

  Since ID_CRED_I contains a single 'kid' parameter, only the
  int -10 is included in the plaintext.


~~~~~~~~
P_3ae (CBOR Sequence) (10 bytes)
29 48 b1 b6 ba a5 b7 8c cd 39
~~~~~~~~

  I constructs the associated data for message_3:

    A_3ae =
    (
     "Encrypt0",
     h'',
     TH_3
    )

~~~~~~~~
A_3ae (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 95 2b 9b 9c dd 53 b6 a7 92 60
4f 84 5e 2b fb 54 06 29 2a a1 70 d4 9a 2b c3 87 4b 43 ae 18 29 18
~~~~~~~~

  I constructs the input needed to derive the key K_3ae, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3ae = EDHOC-KDF(PRK_3e2m, TH_3, "K_3ae", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

  where length is the key length of EDHOC AEAD algorithm, 
  and info for K_3ae is:

    info =
    (
     10,
     h'952B9B9CDD53B6A792604F845E2BFB5406292AA170D49A2BC3874B43AE182918',
     "K_3ae",
     h'',
     16
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm,
  and the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_3ae (CBOR Sequence) (43 bytes)
0a 58 20 95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1
70 d4 9a 2b c3 87 4b 43 ae 18 29 18 65 4b 5f 33 61 65 40 10
~~~~~~~~
~~~~~~~~
K_3ae (Raw Value) (16 bytes)
de d3 52 81 bc 7c 7a c7 46 c3 aa cf e8 95 52 d4
~~~~~~~~

  I constructs the input needed to derive the nonce IV_3ae, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3ae = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3ae", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

  where length is the nonce length of EDHOC AEAD algorithm, 
  and info for IV_3ae is:

    info =
    (
     10,
     h'952B9B9CDD53B6A792604F845E2BFB5406292AA170D49A2BC3874B43AE182918',
     "IV_3ae",
     h'',
     13
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3ae (CBOR Sequence) (44 bytes)
0a 58 20 95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1
70 d4 9a 2b c3 87 4b 43 ae 18 29 18 66 49 56 5f 33 61 65 40 0d
~~~~~~~~
~~~~~~~~
IV_3ae (Raw Value) (13 bytes)
c4 91 e4 d9 81 e3 3f 94 c0 2e 12 83 ed
~~~~~~~~

  I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_3ae, additional data
  A_3ae, key K_3ae and nonce IV_3ae.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (18 bytes)
79 72 ae 79 9b a3 be e4 84 8e 94 1e 98 18 8e 4f 07 8a
~~~~~~~~

  message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (19 bytes)
52 79 72 ae 79 9b a3 be e4 84 8e 94 1e 98 18 8e 4f 07 8a
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (53 bytes)
58 20 95 2b 9b 9c dd 53 b6 a7 92 60 4f 84 5e 2b fb 54 06 29 2a a1 70
d4 9a 2b c3 87 4b 43 ae 18 29 18 52 79 72 ae 79 9b a3 be e4 84 8e 94
1e 98 18 8e 4f 07 8a
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b de 0c ee
4f 72 01 1b 24 70 8f 10 b1
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b de
0c ee 4f 72 01 1b 24 70 8f 10 b1
~~~~~~~~


## message_4

  No external authorization data:

EAD_4 (CBOR Sequence) (0 bytes)

  R constructs the plaintext P_4ae:

    P_4ae =
    (
     ? EAD_4
    )

P_4ae (CBOR Sequence) (0 bytes)

  R constructs the associated data for message_4:

    A_4ae =
    (
     "Encrypt0",
     h'',
     TH_4
    )

~~~~~~~~
A_4ae (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 a7 fa 7e 15 06 65 3c f5 87 ce
fb 9b 69 89 79 eb 5c 5f e6 7b de 0c ee 4f 72 01 1b 24 70 8f 10 b1
~~~~~~~~

  R constructs the input needed to derive the EDHOC message_4 key, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_4ae = EDHOC-Exporter("EDHOC_message_4_Key", h'', length)
          = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_message_4_Key", h'', length)
          = HKDF-Expand(PRK_4x3m, info, length)

  where length is the key length of the EDHOC AEAD algorithm, 
  and info for EDHOC_message_4_Key is:

    info =
    (
     10,
     h'A7FA7E1506653CF587CEFB9B698979EB5C5FE67BDE0CEE4F72011B24708F10B1',
     "EDHOC_message_4_Key"
     h'',
     16
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm,
  and the last value is the key length of EDHOC AEAD algorithm

~~~~~~~~
info for K_4ae (CBOR Sequence) (57 bytes)
0a 58 20 a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b
de 0c ee 4f 72 01 1b 24 70 8f 10 b1 73 45 44 48 4f 43 5f 6d 65 73 73
61 67 65 5f 34 5f 4b 65 79 40 10
~~~~~~~~
~~~~~~~~
K_4ae (Raw Value) (16 bytes)
bf c4 3b 25 2d 37 49 ad e1 f2 5f ff 07 05 a1 4e
~~~~~~~~

  R constructs the input needed to derive the EDHOC message_4 nonce, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

           IV_4ae = 
           = EDHOC-Exporter( "EDHOC_message_4_Nonce", h'', length )
           = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_message_4_Nonce", h'', length)
           = HKDF-Expand(PRK_4x3m, info, length)

  where length is the nonce length of EDHOC AEAD algorithm, 
  and info for EDHOC_message_4_Nonce is:

    info =
    (
     10,
     h'A7FA7E1506653CF587CEFB9B698979EB5C5FE67BDE0CEE4F72011B24708F10B1',
     "EDHOC_message_4_Nonce"
     h'',
     13
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4ae (CBOR Sequence) (59 bytes)
0a 58 20 a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b
de 0c ee 4f 72 01 1b 24 70 8f 10 b1 75 45 44 48 4f 43 5f 6d 65 73 73
61 67 65 5f 34 5f 4e 6f 6e 63 65 40 0d
~~~~~~~~
~~~~~~~~
IV_4ae (Raw Value) (13 bytes)
54 30 79 84 e1 3a 93 5c fd 4b 3f e0 15
~~~~~~~~

  R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_4ae, additional data
  A_4ae, key K_4ae and nonce IV_4ae.

~~~~~~~~
CIPHERTEXT_4 (8 bytes)
93 32 f1 01 74 2c 51 df
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 93 32 f1 01 74 2c 51 df
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

  The mapping from EDHOC connection identifiers to OSCORE Sender/Recipient IDs is defined in Section A.1of {{I-D.ietf-lake-edhoc}}.

  C_R is mapped to the Recipient ID of the server, i.e., the Sender ID of the client. Since C_R is byte valued it the OSCORE Sender/Recipient ID equals the byte string (in this case the empty byte string). 

~~~~~~~~
Client's OSCORE Sender ID (Raw Value) (0 bytes)
~~~~~~~~

  C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server. Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
0c
~~~~~~~~

  The OSCORE master secret is computed through Expand() using the 
  Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Secret =
    = EDHOC-Exporter("OSCORE Master Secret", h'', key_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Secret", h'', key_length)
    = HKDF-Expand(PRK_4x3m, info, key_length)

  where key_length is by default the key length of the Application AEAD 
  algorithm, and info for the OSCORE Master Secret is:

    info =
    (
     10, 
     h'A7FA7E1506653CF587CEFB9B698979EB5C5FE67BDE0CEE4F72011B24708F10B1',
     "OSCORE Master Secret"
     h'',
     16
    )

  where the first value is the COSE algorithm value of the Application AEAD algorithm,
  and the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (58 bytes)
0a 58 20 a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b
de 0c ee 4f 72 01 1b 24 70 8f 10 b1 74 4f 53 43 4f 52 45 20 4d 61 73
74 65 72 20 53 65 63 72 65 74 40 10

~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
6b e2 df 0b a9 ca 9a d1 61 0b 70 33 17 a0 78 c1 
~~~~~~~~

  The OSCORE master salt is computed through Expand() using the 
  Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE Master Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

  where salt_length is the length of the salt, and info for the OSCORE Master Salt is:

    info =
    (
     10,
     h'A7FA7E1506653CF587CEFB9B698979EB5C5FE67BDE0CEE4F72011B24708F10B1',
     "OSCORE Master Salt"
     h'',
     8
    )

  where the first value is the COSE algorithm value of the Application AEAD algorithm,
  and the last value is the length of the salt.


~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (56 bytes)
0a 58 20 a7 fa 7e 15 06 65 3c f5 87 ce fb 9b 69 89 79 eb 5c 5f e6 7b
de 0c ee 4f 72 01 1b 24 70 8f 10 b1 72 4f 53 43 4f 52 45 20 4d 61 73
74 65 72 20 53 61 6c 74 40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
c7 ba e4 50 27 2c 94 f6 
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
d5 cf 15 4f 45 6e 31 04 0d 71 8e d2 1d 53 64 5c
~~~~~~~~

The OSCORE Master Salt is derived with the updated PRK_4x3m:

OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
03 0f 98 e6 24 5e be ec
~~~~~~~~



# Authentication with signatures, X.509 identified by 'x5t'

In this example the Initiator (I) and Responder (R) are authenticated with digital signatures (METHOD = 0). The public keys are represented with dummy X.509 certificates identified by the COSE header parameter 'x5t'.


## message_1

  Both endpoints are authenticated with signatures, i.e. METHOD = 0:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
00 
~~~~~~~~

I selects cipher suite 0. A single cipher suite is encoded as an int:

~~~~~~~~
SUITES_I (CBOR Data Item) (1 bytes)
00
~~~~~~~~


I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
X (Raw Value) (Initiator's ephemeral private key) (32 bytes)
b0 26 b1 68 42 9b 21 3d 6b 42 1d f6 ab d0 64 1c d6 6d ca 2e e7 fd 59
77 10 4b b2 38 18 2e 5e a6
~~~~~~~~
~~~~~~~~
G_X (Raw Value) (Initiator's ephemeral public key) (32 bytes)
e3 1e c1 5e e8 03 94 27 df c4 72 7e f1 7e 2e 0e 69 c5 44 37 f3 c5 82
80 19 ef 0a 63 88 c1 25 52
~~~~~~~~
~~~~~~~~
G_X (CBOR Data Item) (Initiator's ephemeral public key) (34 bytes)
58 20 e3 1e c1 5e e8 03 94 27 df c4 72 7e f1 7e 2e 0e 69 c5 44 37 f3
c5 82 80 19 ef 0a 63 88 c1 25 52
~~~~~~~~

  I selects its connection identifier C_I to be the int 14:

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
     0,
     h'E31EC15EE8039427DFC4727EF17E2E0E69C54437F3C5828019EF0A6388C12552', 
     14
    )

~~~~~~~~
message_1 (CBOR Sequence) (37 bytes)
00 00 58 20 e3 1e c1 5e e8 03 94 27 df c4 72 7e f1 7e 2e 0e 69 c5 44
37 f3 c5 82 80 19 ef 0a 63 88 c1 25 52 0e
~~~~~~~~

## message_2

  R creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Y (Raw Value) (Responder's ephemeral private key) (32 bytes)
db 06 84 a8 12 54 66 41 3e 59 8d c2 67 73 7f 5f ef 0c 5a a2 29 fa a1
55 43 9f 60 08 5f d2 53 6d
~~~~~~~~
~~~~~~~~
G_Y (Raw Value) (Responder's ephemeral public key) (32 bytes)
e1 73 90 96 c5 c9 58 2c 12 98 91 81 66 d6 95 48 c7 8f 74 97 b2 58 c0
85 6a a2 01 98 93 a3 94 25
~~~~~~~~
~~~~~~~~
G_Y (CBOR Data Item) (Responder's ephemeral public key) (34 bytes)
58 20 e1 73 90 96 c5 c9 58 2c 12 98 91 81 66 d6 95 48 c7 8f 74 97 b2
58 c0 85 6a a2 01 98 93 a3 94 25
~~~~~~~~

  PRK_2e is specified in Section 4.1.1 of {{I-D.ietf-lake-edhoc}}.
  
  First, the ECDH shared secret G_XY is computed from G_X and Y, or G_Y and X:

~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
0b eb 98 d8 8f 49 67 7c 17 47 88 f8 87 bd cc d2 28 a1 88 39 2c cd 10
12 bd 31 70 d7 c8 85 65 66
~~~~~~~~

  Then, PRK_2e is calculated using Extract() determined by the EDHOC hash
  algorithm:

    PRK_2e = Extract(salt, G_XY) =
           = HMAC-SHA-256(salt, G_XY)

  where salt is the empty byte string:

salt (Raw Value) (0 bytes)

~~~~~~~~
PRK_2e (Raw Value) (32 bytes)
4e 57 dc e2 58 75 77 c4 34 69 7c 03 93 5c c6 a2 82 16 5a 88 76 05 11
fc 70 a8 c0 02 20 a5 ba 1a
~~~~~~~~

  Since METHOD = 0, R authenticates using signatures.
  R's signature key pair for use with the EDHOC signature algorithm is:

~~~~~~~~
SK_R (Raw Value) (Responders's private authentication key) (32 bytes)
bc 4d 4f 98 82 61 22 33 b4 02 db 75 e6 c4 cf 30 32 a7 0a 0d 2e 3e e6
d0 1b 11 dd de 5f 41 9c fc
~~~~~~~~
~~~~~~~~
PK_R (Raw Value) (Responders's public authentication key) (32 bytes)
27 ee f2 b0 8a 6f 49 6f ae da a6 c7 f9 ec 6a e3 b9 d5 24 24 58 0d 52
e4 9d a6 93 5e df 53 cd c5
~~~~~~~~

  PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.
  
  Since R authenticates with signatures PRK_3e2m = PRK_2e.

~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
4e 57 dc e2 58 75 77 c4 34 69 7c 03 93 5c c6 a2 82 16 5a 88 76 05 11
fc 70 a8 c0 02 20 a5 ba 1a
~~~~~~~~

  R selects its connection identifier C_R to be the int -19

~~~~~~~~
C_R (CBOR Data Item) (Connection identifier chosen by R) (1 bytes)
32
~~~~~~~~

The transcript hash TH_2 is calculated using the EDHOC hash algorithm:
 
TH_2 = H(H(message_1), G_Y, C_R)

~~~~~~~~
H(message_1) (Raw Value) (32 bytes)
ce ba 8d 4d a2 80 b1 61 c8 5a 19 47 81 a9 31 88 35 41 50 b4 9c 4f 93
2e 4a a0 8f f3 ed 11 04 65
~~~~~~~~

~~~~~~~~
H(message_1) (CBOR Data Item) (34 bytes)
58 20 ce ba 8d 4d a2 80 b1 61 c8 5a 19 47 81 a9 31 88 35 41 50 b4 9c
4f 93 2e 4a a0 8f f3 ed 11 04 65
~~~~~~~~

The input to calculate TH_2 is the CBOR sequence:

H(message_1), G_Y, C_R

~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (69 bytes)
58 20 ce ba 8d 4d a2 80 b1 61 c8 5a 19 47 81 a9 31 88 35 41 50 b4 9c
4f 93 2e 4a a0 8f f3 ed 11 04 65 58 20 e1 73 90 96 c5 c9 58 2c 12 98
91 81 66 d6 95 48 c7 8f 74 97 b2 58 c0 85 6a a2 01 98 93 a3 94 25 32
~~~~~~~~

~~~~~~~~
TH_2 (Raw Value) (32 bytes)
07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed 78 95 74 57 3f 24 44 3e
91 83 3d 68 cd dd 7f 9b 39
~~~~~~~~

~~~~~~~~
TH_2 (CBOR Data Item) (34 bytes)
58 20 07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed 78 95 74 57 3f 24
44 3e 91 83 3d 68 cd dd 7f 9b 39
~~~~~~~~

R constructs the remaining input needed to calculate MAC_2:

MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2", 
            << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2)

CRED_R is identified by a 64-bit hash: 

    ID_CRED_R =
    {
      34 : [-15, h'60780E9451BDC43C']
    }

  where the COSE header value 34 ('x5t') indicates a hash of an X.509 certficate,
  and the COSE algorithm -15 indicates the hash algorithm SHA-256 truncated to 64 bits.

ID_CRED_R (CBOR Data Item) (14 bytes)
a1 18 22 82 2e 48 60 78 0e 94 51 bd c4 3c

  CRED_R is a byte string acting as a dummy X.509 certificate:

~~~~~~~~
CRED_R (CBOR Data Item) (113 bytes)
58 6f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14
15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42
43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59
5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 
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
     10,
     h'0782DBB687C30288A30B706B074BED789574573F24443E91833D68CDDD7F9B39', 
     "MAC_2",
     h'A11822822E4860780E9451BDC43C586F000102030405060708090A0B0C0D0E0F10
       1112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031
       32333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152
       535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E', 
     32
    )
    
  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (172 bytes)
0a 58 20 07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed 78 95 74 57 3f
24 44 3e 91 83 3d 68 cd dd 7f 9b 39 65 4d 41 43 5f 32 58 7f a1 18 22
82 2e 48 60 78 0e 94 51 bd c4 3c 58 6f 00 01 02 03 04 05 06 07 08 09
0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e
4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65
66 67 68 69 6a 6b 6c 6d 6e 18 20
~~~~~~~~

~~~~~~~~
MAC_2 (Raw Value) (32 bytes)
cb b9 18 62 9b 8d 5f dc 2e fa 14 98 40 5b 5e 68 2c ad ab e3 31 e8 48
2c eb b6 49 44 ca 1b db 39
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (34 bytes)
58 20 cb b9 18 62 9b 8d 5f dc 2e fa 14 98 40 5b 5e 68 2c ad ab e3 31
e8 48 2c eb b6 49 44 ca 1b db 39 
~~~~~~~~



  Since METHOD = 0, Signature_or_MAC_2 is the 'signature' of the 
  COSE_Sign1 object.  

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
     h'CBB918629B8D5FDC2EFA1498405B5E682CADABE331E8482CEBB64944CA1BDB39'
    ]

~~~~~~~~
Message to be signed 2 (CBOR Data Item) (210 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 60 78 0e 94
51 bd c4 3c 58 93 58 20 07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed
78 95 74 57 3f 24 44 3e 91 83 3d 68 cd dd 7f 9b 39 58 6f 00 01 02 03
04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a
1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31
32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48
49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 58 20 cb b9 18 62 9b 8d
5f dc 2e fa 14 98 40 5b 5e 68 2c ad ab e3 31 e8 48 2c eb b6 49 44 ca
1b db 39
~~~~~~~~

  R signs using the private authentication key SK_R

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (64 bytes)
70 40 a7 57 ce 4f 1d bb 02 5b cc f9 8d 16 80 02 65 78 3c 44 6d 17 c2
08 9a 48 72 51 dd 80 92 fa b5 c4 18 4a ce ab d6 49 5f 2a 39 5b 88 9d
d3 d7 db 8a 01 64 fd f5 11 da 14 9c d2 b4 a6 db 46 0f
~~~~~~~~
~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (66 bytes)
58 40 70 40 a7 57 ce 4f 1d bb 02 5b cc f9 8d 16 80 02 65 78 3c 44 6d
17 c2 08 9a 48 72 51 dd 80 92 fa b5 c4 18 4a ce ab d6 49 5f 2a 39 5b
88 9d d3 d7 db 8a 01 64 fd f5 11 da 14 9c d2 b4 a6 db 46 0f
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
a1 18 22 82 2e 48 60 78 0e 94 51 bd c4 3c 58 40 70 40 a7 57 ce 4f 1d
bb 02 5b cc f9 8d 16 80 02 65 78 3c 44 6d 17 c2 08 9a 48 72 51 dd 80
92 fa b5 c4 18 4a ce ab d6 49 5f 2a 39 5b 88 9d d3 d7 db 8a 01 64 fd
f5 11 da 14 9c d2 b4 a6 db 46 0f
~~~~~~~~

  The input needed to calculate KEYSTREAM_2 is defined in Section 4.2 of {{I-D.ietf-lake-edhoc}}, using Expand() with the EDHOC hash algorithm:

    KEYSTREAM_2 = EDHOC-KDF(PRK_2e, TH_2, "KEYSTREAM_2", h'', length) =
                = HKDF-Expand(PRK_2e, info, length)

  where length is the length of PLAINTEXT_2, and info for KEYSTREAM_2 is:

    info = 
    (
     10,
     h'0782DBB687C30288A30B706B074BED789574573F24443E91833D68CDDD7F9B39', 
     "KEYSTREAM_2",
     h'', 
     80
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm
  and the last value is the length of PLAINTEXT_2

~~~~~~~~
info for KEYSTREAM_2 (CBOR Sequence) (50 bytes)
0a 58 20 07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed 78 95 74 57 3f
24 44 3e 91 83 3d 68 cd dd 7f 9b 39 6b 4b 45 59 53 54 52 45 41 4d 5f
32 40 18 50
~~~~~~~~

~~~~~~~~
KEYSTREAM_2 (Raw Value) (80 bytes)
50 05 ad 05 39 23 95 05 a1 93 61 18 01 27 3d ee 3f bb 66 2a 15 6f b5
fe 07 bc d1 9b bd 2c 3e 48 12 57 dd 5c 17 df f1 e9 ba 43 8e 7f 41 1f
65 f1 ee 28 3d 2f a3 4d 12 d6 f6 ae 5e f2 28 aa b9 5f d8 e5 e1 d0 aa
89 28 58 55 c2 91 3c 7d 54 a2 0e
~~~~~~~~

  R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (80 bytes)
f1 1d 8f 87 17 6b f5 7d af 07 30 a5 c5 1b 65 ae 4f fb c1 7d db 20 a8
45 05 e7 1d 62 30 3a be 4a 77 2f e1 18 7a c8 33 e1 20 0b fc 2e 9c 9f
f7 0b 5b ec 25 65 6d e6 c4 9f a9 84 67 a9 a0 37 6a 88 03 6f e0 b4 57
7c 39 82 41 5e 43 88 db 8f e4 01
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
message_2 (CBOR Sequence) (115 bytes)
58 70 e1 73 90 96 c5 c9 58 2c 12 98 91 81 66 d6 95 48 c7 8f 74 97 b2
58 c0 85 6a a2 01 98 93 a3 94 25 f1 1d 8f 87 17 6b f5 7d af 07 30 a5
c5 1b 65 ae 4f fb c1 7d db 20 a8 45 05 e7 1d 62 30 3a be 4a 77 2f e1
18 7a c8 33 e1 20 0b fc 2e 9c 9f f7 0b 5b ec 25 65 6d e6 c4 9f a9 84
67 a9 a0 37 6a 88 03 6f e0 b4 57 7c 39 82 41 5e 43 88 db 8f e4 01 32
~~~~~~~~


## message_3

  Since METHOD = 0, I authenticates using signatures. 
  I's signature key pair for use with the EDHOC signature algorithm is:

~~~~~~~~
SK_I (Raw Value) (Initiator's private authentication key) (32 bytes)
36 6a 58 59 a4 cd 65 cf ae af 05 66 c9 fc 7e 1a 93 30 6f de c1 77 63
e0 58 13 a7 0f 21 ff 59 db
~~~~~~~~

~~~~~~~~
PK_I (Raw Value) (Responders's public authentication key) (32 bytes)
ec 2c 2e b6 cd d9 57 82 a8 cd 0b 2e 9c 44 27 07 74 dc bd 31 bf be 23
13 ce 80 13 2e 8a 26 1c 04
~~~~~~~~

  PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.
  
  Since R authenticates with signatures PRK_4x3m = PRK_3e2m.

~~~~~~~~
PRK_4x3m (Raw Value) (32 bytes)
4e 57 dc e2 58 75 77 c4 34 69 7c 03 93 5c c6 a2 82 16 5a 88 76 05 11
fc 70 a8 c0 02 20 a5 ba 1a
~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:
 
TH_3 = H(TH_2, CIPHERTEXT_2)

~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (116 bytes)
58 20 07 82 db b6 87 c3 02 88 a3 0b 70 6b 07 4b ed 78 95 74 57 3f 24
44 3e 91 83 3d 68 cd dd 7f 9b 39 58 50 f1 1d 8f 87 17 6b f5 7d af 07
30 a5 c5 1b 65 ae 4f fb c1 7d db 20 a8 45 05 e7 1d 62 30 3a be 4a 77
2f e1 18 7a c8 33 e1 20 0b fc 2e 9c 9f f7 0b 5b ec 25 65 6d e6 c4 9f
a9 84 67 a9 a0 37 6a 88 03 6f e0 b4 57 7c 39 82 41 5e 43 88 db 8f e4
01
~~~~~~~~

~~~~~~~~
TH_3 (Raw Value) (32 bytes)
5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4 ee 14 87
80 c3 c2 e7 34 13 72 cb ad
~~~~~~~~

~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4 ee
14 87 80 c3 c2 e7 34 13 72 cb ad
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
a1 18 22 82 2e 48 81 d4 5b e0 63 29 d6 3a
~~~~~~~~

  CRED_I is a byte string acting as a dummy X.509 certificate:

~~~~~~~~
CRED_I (CBOR Data Item) (139 bytes)
58 89 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14
15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42
43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59
5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70
71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87
88
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
     10,
     h'5AA25B46397C2F145EB792ED0D17EA2B078C73E4EE148780C3C2E7341372CBAD',
     "MAC_3",
     h'A11822822E4881D45BE06329D63A5889000102030405060708090A0B0C0D0E0F
       101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F
       303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F
       505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F
       707172737475767778797A7B7C7D7E7F808182838485868788',
     32
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (198 bytes)
0a 58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4
ee 14 87 80 c3 c2 e7 34 13 72 cb ad 65 4d 41 43 5f 33 58 99 a1 18 22
82 2e 48 81 d4 5b e0 63 29 d6 3a 58 89 00 01 02 03 04 05 06 07 08 09
0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e
4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65
66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c
7d 7e 7f 80 81 82 83 84 85 86 87 88 18 20 
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (32 bytes)
3d 06 fd d8 8a eb da b4 b3 ee ca 69 3f de 93 40 52 3e 81 0f 4d ad 75
26 9f 5d ae a8 e3 6d 33 79
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (34 bytes)
58 20 3d 06 fd d8 8a eb da b4 b3 ee ca 69 3f de 93 40 52 3e 81 0f 4d
ad 75 26 9f 5d ae a8 e3 6d 33 79
~~~~~~~~

  Since METHOD = 0, Signature_or_MAC_3 is the 'signature' of the 
  COSE_Sign1 object.  

  I constructs the message to be signed:

    [ "Signature1", << ID_CRED_I >>,
     << TH_3, CRED_I, ? EAD_3 >>, MAC_3 ] =

    [
     "Signature1", 
     h'A11822822E4881D45BE06329D63A',
     h'58205AA25B46397C2F145EB792ED0D17EA2B078C73E4EE148780C3C2E7341372
       CBAD5889000102030405060708090A0B0C0D0E0F101112131415161718191A1B
       1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B
       3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B
       5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B
       7C7D7E7F808182838485868788',
     h'3D06FDD88AEBDAB4B3EECA693FDE9340523E810F4DAD75269F5DAEA8E36D3379'
    ]

~~~~~~~~
Message to be signed 3 (CBOR Data Item) (236 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 81 d4 5b e0
63 29 d6 3a 58 ad 58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea
2b 07 8c 73 e4 ee 14 87 80 c3 c2 e7 34 13 72 cb ad 58 89 00 01 02 03
04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a
1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31
32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48
49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76
77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 58 20 3d 06 fd
d8 8a eb da b4 b3 ee ca 69 3f de 93 40 52 3e 81 0f 4d ad 75 26 9f 5d
ae a8 e3 6d 33 79
~~~~~~~~

  R signs using the private authentication key SK_R:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (64 bytes)
74 8a 59 cb 36 b6 1d aa bd aa 7b 60 1a 0b 78 3d 44 9b 6f 2c 91 20 e1
00 96 b3 3a 1c 01 96 31 f3 d0 47 5e cb 92 e6 d3 d3 76 1d 30 9a 79 6d
90 92 ab ba b5 ba 00 fc 29 69 35 b4 1f 69 fb 92 1d 03
~~~~~~~~

  R constructs the plaintext:

    P_3ae =
    (
     ID_CRED_I / bstr / int,
     Signature_or_MAC_3,
     ? EAD_3
    )

~~~~~~~~
P_3ae (CBOR Sequence) (80 bytes)
a1 18 22 82 2e 48 81 d4 5b e0 63 29 d6 3a 58 40 74 8a 59 cb 36 b6 1d
aa bd aa 7b 60 1a 0b 78 3d 44 9b 6f 2c 91 20 e1 00 96 b3 3a 1c 01 96
31 f3 d0 47 5e cb 92 e6 d3 d3 76 1d 30 9a 79 6d 90 92 ab ba b5 ba 00
fc 29 69 35 b4 1f 69 fb 92 1d 03
~~~~~~~~

  I constructs the associated data for message_3:

    A_3ae =
    (
     "Encrypt0",
     h'',
     TH_3
    )

~~~~~~~~
A_3ae (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 5a a2 5b 46 39 7c 2f 14 5e b7
92 ed 0d 17 ea 2b 07 8c 73 e4 ee 14 87 80 c3 c2 e7 34 13 72 cb ad
~~~~~~~~

  I constructs the input needed to derive the key K_3ae, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3ae = EDHOC-KDF(PRK_3e2m, TH_3, "K_3ae", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

  where length is the key length of EDHOC AEAD algorithm, 
  and info for K_3ae is:

    info =
    (
     10,
     h'5AA25B46397C2F145EB792ED0D17EA2B078C73E4EE148780C3C2E7341372CBAD',
     "K_3ae",
     h'',
     16
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm,
  and the last value is the key length of EDHOC AEAD algorithm.


~~~~~~~~
info for K_3ae (CBOR Sequence) (43 bytes)
0a 58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4
ee 14 87 80 c3 c2 e7 34 13 72 cb ad 65 4b 5f 33 61 65 40 10
~~~~~~~~

~~~~~~~~
K_3ae (Raw Value) (16 bytes)
98 46 8b 5e 85 a1 6d bc 73 5e 12 6e b8 f3 2f 68
~~~~~~~~

  I constructs the input needed to derive the nonce IV_3ae, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3ae = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3ae", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

  where length is the nonce length of EDHOC AEAD algorithm, 
  and info for IV_3ae is:

    info =
    (
     10,
     h'5AA25B46397C2F145EB792ED0D17EA2B078C73E4EE148780C3C2E7341372CBAD',
     "IV_3ae",
     h'',
     13
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3ae (CBOR Sequence) (44 bytes)
0a 58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4
ee 14 87 80 c3 c2 e7 34 13 72 cb ad 66 49 56 5f 33 61 65 40 0d
~~~~~~~~

~~~~~~~~
IV_3ae (Raw Value) (13 bytes)
37 dc 12 8d 11 49 8f bb 00 36 e6 ff 9d
~~~~~~~~

  I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_3ae, additional data
  A_3ae, key K_3ae and nonce IV_3ae.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (88 bytes)
a8 38 fa 7a 01 d1 7e 65 41 e8 52 a4 3d 6c 07 a3 0e 82 82 9f ce f0 7d
21 83 c5 4f b7 22 62 90 1c 9d d6 d9 c6 bd 8e d0 18 be 45 94 2e 23 4f
21 23 97 8f e0 eb 21 fd c2 c0 82 f8 d1 ae 4e 0f 61 9a 3f 5b 88 a4 8c
b0 08 94 da d8 16 9f ae a9 c7 c0 d6 8f 9e 51 25 c4 e9 2e
~~~~~~~~

  message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (90 bytes)
58 58 a8 38 fa 7a 01 d1 7e 65 41 e8 52 a4 3d 6c 07 a3 0e 82 82 9f ce
f0 7d 21 83 c5 4f b7 22 62 90 1c 9d d6 d9 c6 bd 8e d0 18 be 45 94 2e
23 4f 21 23 97 8f e0 eb 21 fd c2 c0 82 f8 d1 ae 4e 0f 61 9a 3f 5b 88
a4 8c b0 08 94 da d8 16 9f ae a9 c7 c0 d6 8f 9e 51 25 c4 e9 2e
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (124 bytes)
58 20 5a a2 5b 46 39 7c 2f 14 5e b7 92 ed 0d 17 ea 2b 07 8c 73 e4 ee
14 87 80 c3 c2 e7 34 13 72 cb ad 58 58 a8 38 fa 7a 01 d1 7e 65 41 e8
52 a4 3d 6c 07 a3 0e 82 82 9f ce f0 7d 21 83 c5 4f b7 22 62 90 1c 9d
d6 d9 c6 bd 8e d0 18 be 45 94 2e 23 4f 21 23 97 8f e0 eb 21 fd c2 c0
82 f8 d1 ae 4e 0f 61 9a 3f 5b 88 a4 8c b0 08 94 da d8 16 9f ae a9 c7
c0 d6 8f 9e 51 25 c4 e9 2e
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30 36 7d 8e
00 5f 9f 63 33 40 d2 ca e3
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30 36
7d 8e 00 5f 9f 63 33 40 d2 ca e3
~~~~~~~~


## message_4

  No external authorization data:

~~~~~~~~
EAD_4 (CBOR Sequence) (0 bytes)
~~~~~~~~

  R constructs the plaintext P_4ae:

    P_4ae = 
    ( 
     ? EAD_4
    )

~~~~~~~~
P_4ae (CBOR Sequence) (0 bytes)
~~~~~~~~

  R constructs the associated data for message_4:

    A_4ae =
    (
     "Encrypt0",
     h'',
     TH_4
    )

~~~~~~~~
A_4ae (CBOR Data Item) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 d8 4a 43 c3 2b 48 1d be 5c 21
38 cb 9a b1 bd 58 97 0e 3c 30 36 7d 8e 00 5f 9f 63 33 40 d2 ca e3
~~~~~~~~

  R constructs the input needed to derive the EDHOC message_4 key, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_4ae = EDHOC-Exporter("EDHOC_message_4_Key", h'', length)
          = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_message_4_Key", h'', length)
          = HKDF-Expand(PRK_4x3m, info, length)

  where length is the key length of the EDHOC AEAD algorithm, 
  and info for EDHOC_message_4_Key is:

    info =
    (
     10,
     h'D84A43C32B481DBE5C2138CB9AB1BD58970E3C30367D8E005F9F633340D2CAE3',
     "EDHOC_message_4_Key"
     h'',
     16
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm,
  and the last value is the key length of EDHOC AEAD algorithm

~~~~~~~~
info for K_4ae (CBOR Sequence) (57 bytes)
0a 58 20 d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30
36 7d 8e 00 5f 9f 63 33 40 d2 ca e3 73 45 44 48 4f 43 5f 6d 65 73 73
61 67 65 5f 34 5f 4b 65 79 40 10
~~~~~~~~

~~~~~~~~
K_4ae (Raw Value) (16 bytes)
be f7 e1 59 a9 33 89 8c 25 a9 b0 85 a3 83 67 34
~~~~~~~~

 R constructs the input needed to derive the EDHOC message_4 nonce, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

           IV_4ae = 
           = EDHOC-Exporter( "EDHOC_message_4_Nonce", h'', length )
           = EDHOC-KDF(PRK_4x3m, TH_4, "EDHOC_message_4_Nonce", h'', length)
           = HKDF-Expand(PRK_4x3m, info, length)

  where length is the nonce length of EDHOC AEAD algorithm, 
  and info for EDHOC_message_4_Nonce is:

    info =
    (
     10,
     h'D84A43C32B481DBE5C2138CB9AB1BD58970E3C30367D8E005F9F633340D2CAE3',
     "EDHOC_message_4_Nonce"
     h'',
     13
    )

  where the first value is the COSE algorithm value of the EDHOC AEAD algorithm, 
  and the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4ae (CBOR Sequence) (59 bytes)
0a 58 20 d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30
36 7d 8e 00 5f 9f 63 33 40 d2 ca e3 75 45 44 48 4f 43 5f 6d 65 73 73
61 67 65 5f 34 5f 4e 6f 6e 63 65 40 0d
~~~~~~~~

~~~~~~~~
IV_4ae (Raw Value) (13 bytes)
47 56 e9 42 0d 99 3e f8 06 86 09 6e 45
~~~~~~~~

  R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_4ae, additional data
  A_4ae, key K_4ae and nonce IV_4ae.


~~~~~~~~
CIPHERTEXT_4 (8 bytes)
b1 5a db ba fc 31 30 89
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 b1 5a db ba fc 31 30 89
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
32
~~~~~~~~

  C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server. Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
0e
~~~~~~~~

  The OSCORE master secret is computed through Expand() using the 
  Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Secret =
    = EDHOC-Exporter("OSCORE Master Secret", h'', key_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Secret", h'', key_length)
    = HKDF-Expand(PRK_4x3m, info, key_length)

  where key_length is by default the key length of the Application AEAD 
  algorithm, and info for the OSCORE Master Secret is:

    info = 
    (
     10,
     h'D84A43C32B481DBE5C2138CB9AB1BD58970E3C30367D8E005F9F633340D2CAE3',
     "OSCORE Master Secret"
     h'',
     16
    )

  where the first value is the COSE algorithm value of the Application AEAD algorithm,
  and the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (58 bytes)
0a 58 20 d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30
36 7d 8e 00 5f 9f 63 33 40 d2 ca e3 74 4f 53 43 4f 52 45 20 4d 61 73
74 65 72 20 53 65 63 72 65 74 40 10
~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
9c 99 44 87 2b 2e 8a c1 9f 1d 24 a0 13 c4 b6 58
~~~~~~~~

  The OSCORE master salt is computed through Expand() using the 
  Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE Master Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

  where salt_length is the length of the salt, and info for the OSCORE Master Salt is:

    info = 
    (
     10, 
     h'D84A43C32B481DBE5C2138CB9AB1BD58970E3C30367D8E005F9F633340D2CAE3',
     "OSCORE Master Salt"
     h'', 
     8
    )

  where the first value is the COSE algorithm value of the Application AEAD algorithm,
  and the last value is the length of the salt.

~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (56 bytes)
0a 58 20 d8 4a 43 c3 2b 48 1d be 5c 21 38 cb 9a b1 bd 58 97 0e 3c 30
36 7d 8e 00 5f 9f 63 33 40 d2 ca e3 72 4f 53 43 4f 52 45 20 4d 61 73
74 65 72 20 53 61 6c 74 40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
b4 a5 c5 4a 74 de f1 03
~~~~~~~~


## Key Update

  Key update is defined in Section 4.4 of {{I-D.ietf-lake-edhoc}}.

    EDHOC-KeyUpdate(nonce):
    PRK_4x3m = Extract(nonce, PRK_4x3m)

~~~~~~~~
KeyUpdate Nonce (Raw Value) (16 bytes)
e6 f5 49 b8 58 1a a2 92 53 cf ce 68 07 53 a4 00
~~~~~~~~

~~~~~~~~
PRK_4x3m after KeyUpdate (Raw Value) (32 bytes)
26 78 00 73 f8 ce 0b eb 71 03 e0 c7 17 d1 6d db bb f6 7b b1 f0 77 53
ca 97 df ec 34 73 23 47 4d
~~~~~~~~

 The OSCORE Master Secret is derived with the updated PRK_4x3m:

    OSCORE Master Secret = HKDF-Expand(PRK_4x3m, info, key_length)

  where info and key_length are unchanged.

~~~~~~~~
OSCORE Master Secret after KeyUpdate (Raw Value) (16 bytes)
66 3c 19 31 3f bc 77 a1 95 52 e7 eb 6c 37 48 ba
~~~~~~~~

  The OSCORE Master Salt is derived with the updated PRK_4x3m:

    OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

  where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
78 b1 52 3e e0 1a 62 70
~~~~~~~~


# Security Considerations {#security}

This document contains examples of EDHOC {{I-D.ietf-lake-edhoc}} whose security considerations apply. The keys printed in these examples cannot be considered secret and must not be used.

# IANA Considerations {#iana}

There are no IANA considerations.

--- back


# Acknowledgments
{: numbered="no"}

--- fluff
