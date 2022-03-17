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
  street: Krakow
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

In this example I and R are authenticated with ephemeral-static Diffie-Hellman (METHOD = 3). I supports cipher suites 6 and 2 (in order of preference) and R only supports cipher suite 2. After an initial negotiation smessage exchange cipher suite 2 is used, which determines the algorithms:

* EDHOC AEAD algorithm = AES-CCM-16-64-128
* EDHOC hash algorithm = SHA-256
* EDHOC MAC length in bytes (Static DH) = 8
* EDHOC key exchange algorithm (ECDH curve) = P-256
* EDHOC signature algorithm = ES256
* Application AEAD algorithm = AES-CCM-16-64-128
* Application hash algorithm = SHA-256

The public keys are represented as raw public keys (RPK), encoded in an CWT Claims Set (CCS) and identified by the COSE header parameter 'kid'.



## message_1 (first time) {#m1_1}

Both endpoints are authenticated with signatures, i.e. METHOD = 3:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
03
~~~~~~~~

I selects its preferred cipher suite 6. A single cipher suite is encoded as an int:

~~~~~~~~
SUITES_I (CBOR Data Item) (1 bytes)
06
~~~~~~~~

I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Initiator's ephemeral private key
X (Raw Value) (32 bytes)
5c 41 72 ac a8 b8 2b 5a 62 e6 6f 72 22 16 f5 a1 0f 72 aa 69 f4 2c 1d
1c d3 cc d7 bf d2 9c a4 e9
~~~~~~~~
~~~~~~~~
Initiator's ephemeral public key
G_X (Raw Value) (32 bytes)
74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b 3d 8f 65 f3 26
20 b7 49 be e8 d2 78 ef a9
~~~~~~~~
~~~~~~~~
Initiator's ephemeral public key
G_X (CBOR Data Item) (34 bytes)
58 21 74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b 3d 8f 65
f3 26 20 b7 49 be e8 d2 78 ef a9
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
     h'741A13D7BA048FBB615E94386AA3B61BEA5B3D8F65F32620B749BEE8D278
     EFA9',
     14
    )

~~~~~~~~
message_1 (CBOR Sequence) (37 bytes)
00 06 58 21 74 1a 13 d7 ba 04 8f bb 61 5e 94 38 6a a3 b6 1b ea 5b 3d
8f 65 f3 26 20 b7 49 be e8 d2 78 ef a9 0e
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

Both endpoints are authenticated with static DH, i.e. METHOD = 3:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
03
~~~~~~~~
{: artwork-align="left"}

I selects cipher suite 2 and indicates the more preferred cipher suite(s), in this case 6, all encoded as the array [6, 2]:

~~~~~~~~
SUITES_I (CBOR Data Item) (3 bytes)
82 06 02
~~~~~~~~

I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Initiator's ephemeral private key
X (Raw Value) (32 bytes)
36 8e c1 f6 9a eb 65 9b a3 7d 5a 8d 45 b2 1b dc 02 99 dc ea a8 ef 23
5f 3c a4 2c e3 53 0f 95 25
~~~~~~~~

~~~~~~~~
Initiator's ephemeral public key, 'x'-coordinate
G_X (Raw Value) (32 bytes)
8a f6 f4 30 eb e1 8d 34 18 40 17 a9 a1 1b f5 11 c8 df f8 f8 34 73 0b
96 c1 b7 c8 db ca 2f c3 b6
~~~~~~~~
~~~~~~~~
Initiator's ephemeral public key, 'y'-coordinate
(Raw Value) (32 bytes)
51 e8 af 6c 6e db 78 16 01 ad 1d 9c 5f a8 bf 7a a1 57 16 c7 c0 6a 5d
03 85 03 c6 14 ff 80 c9 b3
~~~~~~~~
~~~~~~~~
Initiator's ephemeral public key, 'x'-coordinate
G_X (CBOR Data Item) (34 bytes)
58 20 8a f6 f4 30 eb e1 8d 34 18 40 17 a9 a1 1b f5 11 c8 df f8 f8 34
73 0b 96 c1 b7 c8 db ca 2f c3 b6
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

~~~~~~~~
EAD_1 (CBOR Sequence) (0 bytes)
~~~~~~~~

I constructs message_1:

    message_1 =
    (
     3,
     [6, 2],
     h'8AF6F430EBE18D34184017A9A11BF511C8DFF8F834730B96C1B7C8DBCA2F
     C3B6',
     -24
    )

~~~~~~~~
message_1 (CBOR Sequence) (39 bytes)
03 82 06 02 58 20 8a f6 f4 30 eb e1 8d 34 18 40 17 a9 a1 1b f5 11 c8
df f8 f8 34 73 0b 96 c1 b7 c8 db ca 2f c3 b6 37
~~~~~~~~

## message_2

R supports the selected cipher suite 2 and not the by I more preferred cipher suite(s) 6, so SUITES_I is acceptable.

R creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Responder's ephemeral private key
Y (Raw Value) (32 bytes)
e2 f4 12 67 77 20 5e 85 3b 43 7d 6e ac a1 e1 f7 53 cd cc 3e 2c 69 fa
88 4b 0a 1a 64 09 77 e4 18
~~~~~~~~

~~~~~~~~
Responder's ephemeral public key, 'x'-coordinate
G_Y (Raw Value) (32 bytes)
41 97 01 d7 f0 0a 26 c2 dc 58 7a 36 dd 75 25 49 f3 37 63 c8 93 42 2c
8e a0 f9 55 a1 3a 4f f5 d5
~~~~~~~~
~~~~~~~~
Responder's ephemeral public key, 'y'-coordinate
(Raw Value) (32 bytes)
5e 4f 0d d8 a3 da 0b aa 16 b9 d3 ad 56 a0 c1 86 0a 94 0a f8 59 14 91
5e 25 01 9b 40 24 17 e9 9d
~~~~~~~~
~~~~~~~~
Responder's ephemeral public key, 'x'-coordinate
G_Y (CBOR Data Item) (34 bytes)
58 20 41 97 01 d7 f0 0a 26 c2 dc 58 7a 36 dd 75 25 49 f3 37 63 c8 93
42 2c 8e a0 f9 55 a1 3a 4f f5 d5
~~~~~~~~

PRK_2e is specified in Section 4.1.1 of {{I-D.ietf-lake-edhoc}}.

First, the ECDH shared secret G_XY is computed from G_X and Y, or G_Y and X:

~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
2f 0c b7 e8 60 ba 53 8f bf 5c 8b de d0 09 f6 25 9b 4b 62 8f e1 eb 7d
be 93 78 e5 ec f7 a8 24 ba
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
fd 9e ef 62 74 87 e4 03 90 ca e9 22 51 2d b5 a6 47 c0 8d c9 0d eb 22
b7 2e ce 6f 15 6f f1 c3 96
~~~~~~~~

Since METHOD = 3, R authenticates using static DH.

R's static Diffie-Hellman key pair for use with the EDHOC key exchange algorithm is based on
the same curve as for the ephemeral keys, P-256:

~~~~~~~~
Responder's private authentication key
R (Raw Value) (32 bytes)
72 cc 47 61 db d4 c7 8f 75 89 31 aa 58 9d 34 8d 1e f8 74 a7 e3 03 ed
e2 f1 40 dc f3 e6 aa 4a ac
~~~~~~~~

~~~~~~~~
Responder's public authentication key, 'x'-coordinate
G_R (Raw Value) (32 bytes)
bb c3 49 60 52 6e a4 d3 2e 94 0c ad 2a 23 41 48 dd c2 17 91 a1 2a fb
cb ac 93 62 20 46 dd 44 f0
~~~~~~~~
~~~~~~~~
Responder's public authentication key, 'y'-coordinate
(Raw Value) (32 bytes)
45 19 e2 57 23 6b 2a 0c e2 02 3f 09 31 f1 f3 86 ca 7a fd a6 4f cd e0
10 8c 22 4c 51 ea bf 60 72
~~~~~~~~



PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with static DH (METHOD = 3), PRK_3e2m is derived
from G_RX using Extract() with the EDHOC hash algorithm:

    PRK_3e2m = Extract(PRK_2e, G_RX) =
             = HMAC-SHA-256(PRK_2e, G_RX)

where G_RX is the ECDH shared secret calculated from G_X and R, or G_R and X.

~~~~~~~~
G_RX (Raw Value) (ECDH shared secret) (32 bytes)
f2 b6 ee a0 22 20 b9 5e ee 5a 0b c7 01 f0 74 e0 0a 84 3e a0 24 22 f6
08 25 fb 26 9b 3e 16 14 23
~~~~~~~~
~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
af 4b 59 18 68 2a df 4c 96 fd 73 05 b6 9f 8f b7 8e fc 9a 23 0d d2 1f
4c 61 be 7d 3c 10 94 46 b3
~~~~~~~~

R selects its connection identifier C_R to be the int -8:

~~~~~~~~
C_R (raw value) (Connection identifier chosen by R) (0 bytes)
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
ca 02 ca bd a5 a8 90 27 49 b4 2f 71 10 50 bb 4d bd 52 15 3e 87 52 75
94 b3 9f 50 cd f0 19 88 8c
~~~~~~~~
~~~~~~~~
H(message_1) (CBOR Data Item) (34 bytes)
58 20 ca 02 ca bd a5 a8 90 27 49 b4 2f 71 10 50 bb 4d bd 52 15 3e 87
52 75 94 b3 9f 50 cd f0 19 88 8c
~~~~~~~~

The input to calculate TH_2 is the CBOR sequence:

H(message_1), G_Y, C_R

~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (69 bytes)
58 20 ca 02 ca bd a5 a8 90 27 49 b4 2f 71 10 50 bb 4d bd 52 15 3e 87
52 75 94 b3 9f 50 cd f0 19 88 8c 58 20 41 97 01 d7 f0 0a 26 c2 dc 58
7a 36 dd 75 25 49 f3 37 63 c8 93 42 2c 8e a0 f9 55 a1 3a 4f f5 d5 27
~~~~~~~~
~~~~~~~~
TH_2 (Raw Value) (32 bytes)
9b 99 cf d7 af dc bc c9 95 0a 63 73 50 7f 2a 81 01 33 19 62 56 97 e4
f9 bf 7a 44 8f c8 e6 33 ca
~~~~~~~~
~~~~~~~~
TH_2 (CBOR Data Item) (34 bytes)
58 20 9b 99 cf d7 af dc bc c9 95 0a 63 73 50 7f 2a 81 01 33 19 62 56
97 e4 f9 bf 7a 44 8f c8 e6 33 ca
~~~~~~~~

R constructs the remaining input needed to calculate MAC_2:

MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2",
            << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2)

CRED_R is identified by a 'kid' with integer value -19:

    ID_CRED_R =
    {
     4 : -19
    }

~~~~~~~~
ID_CRED_R (CBOR Data Item) (3 bytes)
a1 04 32
~~~~~~~~

CRED_R is an RPK encoded as a CCS:

    {                                              /CCS/
      2 : "example.edu",                           /sub/
      8 : {                                        /cnf/
        1 : {                                      /COSE_Key/
          1 : 2,                                   /kty/
          2 : -19,                                 /kid/
         -1 : 1,                                   /crv/
         -2 : h'BBC34960526EA4D32E940CAD2A234148
                DDC21791A12AFBCBAC93622046DD44F0', /x/
         -3 : h'4519E257236B2A0CE2023F0931F1F386
                CA7AFDA64FCDE0108C224C51EABF6072'  /y/
        }
      }
    }

~~~~~~~~
CRED_R (CBOR Data Item) (94 bytes)
a2 02 6b 65 78 61 6d 70 6c 65 2e 65 64 75 08 a1 01 a5 01 02 02 32 20
01 21 58 20 bb c3 49 60 52 6e a4 d3 2e 94 0c ad 2a 23 41 48 dd c2 17
91 a1 2a fb cb ac 93 62 20 46 dd 44 f0 22 58 20 45 19 e2 57 23 6b 2a
0c e2 02 3f 09 31 f1 f3 86 ca 7a fd a6 4f cd e0 10 8c 22 4c 51 ea bf
60 72
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_2 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_2 is computed through Expand() using the
EDHOC hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

MAC_2 = HKDF-Expand(PRK_3e2m, info, mac_length_2), where

info = ( TH_2, “MAC_2”, << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2 )

Since METHOD = 3, mac_length_2 is given by the EDHOC MAC length.

info for MAC_2 is:

    info =
    (
     h'9B99CFD7AFDCBCC9950A6373507F2A81013319625697E4F9BF7A448FC8E6
     33CA',
     "MAC_2",
     h'A10432A2026B6578616D706C652E65647508A101A5010202322001215820
     BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44
     F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C
     51EABF6072',
     8
    )

where the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (140 bytes)
58 20 9b 99 cf d7 af dc bc c9 95 0a 63 73 50 7f 2a 81 01 33 19 62 56
97 e4 f9 bf 7a 44 8f c8 e6 33 ca 65 4d 41 43 5f 32 58 61 a1 04 32 a2
02 6b 65 78 61 6d 70 6c 65 2e 65 64 75 08 a1 01 a5 01 02 02 32 20 01
21 58 20 bb c3 49 60 52 6e a4 d3 2e 94 0c ad 2a 23 41 48 dd c2 17 91
a1 2a fb cb ac 93 62 20 46 dd 44 f0 22 58 20 45 19 e2 57 23 6b 2a 0c
e2 02 3f 09 31 f1 f3 86 ca 7a fd a6 4f cd e0 10 8c 22 4c 51 ea bf 60
72 08
~~~~~~~~
~~~~~~~~
MAC_2 (Raw Value) (8 bytes)
33 24 d5 a4 af cd 43 26
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (9 bytes)
48 33 24 d5 a4 af cd 43 26
~~~~~~~~

Since METHOD = 3, Signature_or_MAC_2 is MAC_2:

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (8 bytes)
33 24 d5 a4 af cd 43 26
~~~~~~~~

~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (9 bytes)
48 33 24 d5 a4 af cd 43 26
~~~~~~~~

R constructs the plaintext:

    PLAINTEXT_2 =
    (
     ID_CRED_R / bstr / int,
     Signature_or_MAC_2,
     ? EAD_2
    )

Since ID_CRED_R contains a single 'kid' parameter, only the int -19 is included in the plaintext.

~~~~~~~~
PLAINTEXT_2 (CBOR Sequence) (10 bytes)
32 48 33 24 d5 a4 af cd 43 26
~~~~~~~~

The input needed to calculate KEYSTREAM_2 is defined in Section 4.2 of
{{I-D.ietf-lake-edhoc}}, using Expand() with the EDHOC hash algorithm:

    KEYSTREAM_2 = EDHOC-KDF(PRK_2e, TH_2, "KEYSTREAM_2", h'', length) =
                = HKDF-Expand(PRK_2e, info, length),


where length is the length of PLAINTEXT_2, and info for KEYSTREAM_2 is:

    info =
    (
     h'9B99CFD7AFDCBCC9950A6373507F2A81013319625697E4F9BF7A448FC8E6
     33CA',
     "KEYSTREAM_2",
     h'',
     10
    )

where last value is the length of PLAINTEXT_2.

~~~~~~~~
info for KEYSTREAM_2 (CBOR Sequence) (48 bytes)
58 20 9b 99 cf d7 af dc bc c9 95 0a 63 73 50 7f 2a 81 01 33 19 62 56
97 e4 f9 bf 7a 44 8f c8 e6 33 ca 6b 4b 45 59 53 54 52 45 41 4d 5f 32
40 0a
~~~~~~~~
~~~~~~~~
KEYSTREAM_2 (Raw Value) (10 bytes)
7b 86 c0 4a f7 3b 50 d3 1b 6f
~~~~~~~~

R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (10 bytes)
49 ce f3 6e 22 9f ff 1e 58 49
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
58 2a 41 97 01 d7 f0 0a 26 c2 dc 58 7a 36 dd 75 25 49 f3 37 63 c8 93
42 2c 8e a0 f9 55 a1 3a 4f f5 d5 49 ce f3 6e 22 9f ff 1e 58 49 27
~~~~~~~~


## message_3

Since METHOD = 3, I authenticates using static DH.

I's static  Diffie-Hellman key pair for use with the EDHOC key exchange algorithm is based on
the same curve as for the ephemeral keys, P-256:

~~~~~~~~
Initiator's private authentication key
I (Raw Value) (32 bytes)
fb 13 ad eb 65 18 ce e5 f8 84 17 66 08 41 14 2e 83 0a 81 fe 33 43 80
a9 53 40 6a 13 05 e8 70 6b
~~~~~~~~

~~~~~~~~
Initiator's public authentication key, 'x'-coordinate
G_I (Raw Value) (32 bytes)
ac 75 e9 ec e3 e5 0b fc 8e d6 03 99 88 95 22 40 5c 47 bf 16 df 96 66
0a 41 29 8c b4 30 7f 7e b6
~~~~~~~~
~~~~~~~~
Initiator's public authentication key, 'y'-coordinate
(Raw Value) (32 bytes)
6e 5d e6 11 38 8a 4b 8a 82 11 33 4a c7 d3 7e cb 52 a3 87 d2 57 e6 db
3c 2a 93 df 21 ff 3a ff c8
~~~~~~~~



PRK_4x3m is derived as specified in Section 4.1.3 of {{I-D.ietf-lake-edhoc}}.
Since I authenticates with static DH (METHOD = 3), PRK_4x3m is derived
from G_IY using Extract() with the EDHOC hash algorithm:

    PRK_4x3m = Extract(PRK_3e2m, G_IY) =
             = HMAC-SHA-256(PRK_3e2m, G_IY)

where G_IY is the ECDH shared secret calculated from G_I and Y, or G_Y and I.

~~~~~~~~
G_IY (Raw Value) (ECDH shared secret) (32 bytes)
08 0f 42 50 85 bc 62 49 08 9e ac 8f 10 8e a6 23 26 85 7e 12 ab 07 d7
20 28 ca 1b 5f 36 e0 04 b3
~~~~~~~~
~~~~~~~~
PRK_4x3m (Raw Value) (32 bytes)
4a 40 f2 ac a7 e1 d9 db af 2b 27 6b ce 75 f0 ce 6d 51 3f 75 a9 5a f8
90 5f 2a 14 f2 49 3b 24 77
~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:

TH_3 = H(TH_2, CIPHERTEXT_2)

~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (45 bytes)
58 20 9b 99 cf d7 af dc bc c9 95 0a 63 73 50 7f 2a 81 01 33 19 62 56
97 e4 f9 bf 7a 44 8f c8 e6 33 ca 4a 49 ce f3 6e 22 9f ff 1e 58 49
~~~~~~~~

~~~~~~~~
TH_3 (Raw Value) (32 bytes)
42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd a4 40
cf b1 3e c1 96 23 1f 36 24
~~~~~~~~
~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd
a4 40 cf b1 3e c1 96 23 1f 36 24
~~~~~~~~

I constructs the remaining input needed to calculate MAC_3:

    MAC_3 = EDHOC-KDF(PRK_4x3m, TH_3, "MAC_3",
            << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3)

CRED_I is identified by a 'kid' with integer value -12:

    ID_CRED_I =
    {
     4 : -12
    }


ID_CRED_I (CBOR Data Item) (3 bytes)
a1 04 2b

CRED_I is an RPK encoded as a CCS:

    {                                              /CCS/
      2 : "42-50-31-FF-EF-37-32-39",               /sub/
      8 : {                                        /cnf/
        1 : {                                      /COSE_Key/
          1 : 1,                                   /kty/
          2 : -10,                                 /kid/
         -1 : 4,                                   /crv/
         -2 : h'AC75E9ECE3E50BFC8ED6039988952240
                5C47BF16DF96660A41298CB4307F7EB6'  /x/
         -3 : h'6E5DE611388A4B8A8211334AC7D37ECB
                52A387D257E6DB3C2A93DF21FF3AFFC8'  /y/
        }
      }
    }


~~~~~~~~
CRED_I (CBOR Data Item) (106 bytes)
a2 02 77 34 32 2d 35 30 2d 33 31 2d 46 46 2d 45 46 2d 33 37 2d 33 32
2d 33 39 08 a1 01 a5 01 02 02 2b 20 01 21 58 20 ac 75 e9 ec e3 e5 0b
fc 8e d6 03 99 88 95 22 40 5c 47 bf 16 df 96 66 0a 41 29 8c b4 30 7f
7e b6 22 58 20 6e 5d e6 11 38 8a 4b 8a 82 11 33 4a c7 d3 7e cb 52 a3
87 d2 57 e6 db 3c 2a 93 df 21 ff 3a ff c8
~~~~~~~~

No external authorization data:

EAD_3 (CBOR Sequence) (0 bytes)

MAC_3 is computed through Expand() using the EDHOC hash algorithm, see
Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    MAC_3 = HKDF-Expand(PRK_4x3m, info, mac_length_3), where

info = ( TH_3, “MAC_3”, << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3 )

Since METHOD = 3, mac_length_3 is given by the EDHOC MAC length.

info for MAC_3 is:

    info =
    (
     h'426F8F65C17F6210392E9A16D51FE07160A25AC6FDA440CFB13EC196231F
     3624',
     "MAC_3",
     h'A1042BA2027734322D35302D33312D46462D45462D33372D33322D333908
     A101A50102022B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF
     16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37E
     CB52A387D257E6DB3C2A93DF21FF3AFFC8',
     8
    )

where the last value is the EDHOC MAC length.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (152 bytes)
58 20 42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd
a4 40 cf b1 3e c1 96 23 1f 36 24 65 4d 41 43 5f 33 58 6d a1 04 2b a2
02 77 34 32 2d 35 30 2d 33 31 2d 46 46 2d 45 46 2d 33 37 2d 33 32 2d
33 39 08 a1 01 a5 01 02 02 2b 20 01 21 58 20 ac 75 e9 ec e3 e5 0b fc
8e d6 03 99 88 95 22 40 5c 47 bf 16 df 96 66 0a 41 29 8c b4 30 7f 7e
b6 22 58 20 6e 5d e6 11 38 8a 4b 8a 82 11 33 4a c7 d3 7e cb 52 a3 87
d2 57 e6 db 3c 2a 93 df 21 ff 3a ff c8 08
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (8 bytes)
4c d5 3d 74 f0 a6 ed 8b
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (9 bytes)
48 4c d5 3d 74 f0 a6 ed 8b
~~~~~~~~

Since METHOD = 3, Signature_or_MAC_3 is MAC_3:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (8 bytes)
4c d5 3d 74 f0 a6 ed 8b
~~~~~~~~

~~~~~~~~
Signature_or_MAC_3 (CBOR Data Item) (9 bytes)
48 4c d5 3d 74 f0 a6 ed 8b
~~~~~~~~

I constructs the plaintext P_3:

    P_3 =
    (
     ID_CRED_I / bstr / int,
     Signature_or_MAC_3,
     ? EAD_3
    )

Since ID_CRED_I contains a single 'kid' parameter, only the
int -12 is included in the plaintext.


~~~~~~~~
P_3 (CBOR Sequence) (10 bytes)
2b 48 4c d5 3d 74 f0 a6 ed 8b
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
83 68 45 6e 63 72 79 70 74 30 40 58 20 42 6f 8f 65 c1 7f 62 10 39 2e
9a 16 d5 1f e0 71 60 a2 5a c6 fd a4 40 cf b1 3e c1 96 23 1f 36 24
~~~~~~~~

I constructs the input needed to derive the key K_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3 = EDHOC-KDF(PRK_3e2m, TH_3, "K_3", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

where length is the key length of EDHOC AEAD algorithm, and info for K_3 is:

    info =
    (
     h'426F8F65C17F6210392E9A16D51FE07160A25AC6FDA440CFB13EC196231F
     3624',
     "K_3",
     h'',
     16
    )

  where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_3 (CBOR Sequence) (40 bytes)
58 20 42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd
a4 40 cf b1 3e c1 96 23 1f 36 24 63 4b 5f 33 40 10
~~~~~~~~
~~~~~~~~
K_3 (Raw Value) (16 bytes)
4f 7c b2 4c 06 de 97 60 d7 73 fb 74 dd 68 57 29
~~~~~~~~

I constructs the input needed to derive the nonce IV_3, see Section 4.2 of
{{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3 = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

where length is the nonce length of EDHOC AEAD algorithm, and info for IV_3 is:

    info =
    (
     h'426F8F65C17F6210392E9A16D51FE07160A25AC6FDA440CFB13EC196231F3624',
     "IV_3",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3 (CBOR Sequence) (41 bytes)
58 20 42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd
a4 40 cf b1 3e c1 96 23 1f 36 24 64 49 56 5f 33 40 0d
~~~~~~~~
~~~~~~~~
IV_3 (Raw Value) (13 bytes)
01 df 75 c4 76 b5 d5 54 63 81 02 4a 89
~~~~~~~~

I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_3, additional data
A_3, key K_3 and nonce IV_3.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (18 bytes)
88 5c 63 fd 0b 17 f2 c3 f8 f1 0b c8 bf 3f 47 0e c8 a1
~~~~~~~~

message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (19 bytes)
52 88 5c 63 fd 0b 17 f2 c3 f8 f1 0b c8 bf 3f 47 0e c8 a1
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (53 bytes)
58 20 42 6f 8f 65 c1 7f 62 10 39 2e 9a 16 d5 1f e0 71 60 a2 5a c6 fd
a4 40 cf b1 3e c1 96 23 1f 36 24 52 88 5c 63 fd 0b 17 f2 c3 f8 f1 0b
c8 bf 3f 47 0e c8 a1
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32 43 9c
4c 7e c7 3c 2c 23 9e 34 50
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32
43 9c 4c 7e c7 3c 2c 23 9e 34 50
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
83 68 45 6e 63 72 79 70 74 30 40 58 20 ba 68 2e 71 65 e9 d4 84 bd 2e
bb 03 1c 09 da 1e a5 b8 2e b3 32 43 9c 4c 7e c7 3c 2c 23 9e 34 50
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
     h'BA682E7165E9D484BD2EBB031C09DA1EA5B82EB332439C4C7EC73C2C239
     E3450',
     "EDHOC_K_4",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_4 (CBOR Sequence) (46 bytes)
58 20 ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32
43 9c 4c 7e c7 3c 2c 23 9e 34 50 69 45 44 48 4f 43 5f 4b 5f 34 40 10
~~~~~~~~
~~~~~~~~
K_4 (Raw Value) (16 bytes)
4c ab dc 43 49 5d 37 0f 2b 03 f3 61 de c6 64 9d
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
     h'4BA682E7165E9D484BD2EBB031C09DA1EA5B82EB332439C4C7EC73C2C239E
     3450',
     "EDHOC_IV_4",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4 (CBOR Sequence) (47 bytes)
58 20 ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32
43 9c 4c 7e c7 3c 2c 23 9e 34 50 6a 45 44 48 4f 43 5f 49 56 5f 34 40
0d
~~~~~~~~
~~~~~~~~
IV_4 (Raw Value) (13 bytes)
4b 06 be f6 7c f6 c2 ef 76 e3 3a 2a 21
~~~~~~~~

  R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
  using the EDHOC AEAD algorithm with plaintext P_4, additional data
  A_4, key K_4 and nonce IV_4.

~~~~~~~~
CIPHERTEXT_4 (8 bytes)
b7 8d 96 39 ae 79 7b 08
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 b7 8d 96 39 ae 79 7b 08
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
Client's OSCORE Sender ID (Raw Value) (1 bytes)
27
~~~~~~~~

C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server.
Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
37
~~~~~~~~

The OSCORE Master Secret is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Secret =
    = EDHOC-Exporter("OSCORE_Secret", h'', key_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Secret", h'', key_length)
    = HKDF-Expand(PRK_4x3m, info, key_length)

where key_length is by default the key length of the Application AEAD algorithm, and info for the OSCORE Master Secret is:

    info =
    (
     h'BA682E7165E9D484BD2EBB031C09DA1EA5B82EB332439C4C7EC73C2C239E
     3450',
     "OSCORE_Secret",
     h'',
     16
    )

where the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (50 bytes)
58 20 ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32
43 9c 4c 7e c7 3c 2c 23 9e 34 50 6d 4f 53 43 4f 52 45 5f 53 65 63 72
65 74 40 10

~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
af 84 55 89 be b9 9d 0a 2b f4 42 7f fa 8d bb bc
~~~~~~~~

The OSCORE Master Salt is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE_Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

where salt_length is the length of the OSCORE Master Salt, and info for the OSCORE Master Salt is:

    info =
    (
     h'BA682E7165E9D484BD2EBB031C09DA1EA5B82EB332439C4C7EC73C2C239E
     3450',
     "OSCORE_Salt",
     h'',
     8
    )

where the last value is the length of the OSCORE Master Salt.


~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (55 bytes)
58 20 ba 68 2e 71 65 e9 d4 84 bd 2e bb 03 1c 09 da 1e a5 b8 2e b3 32
43 9c 4c 7e c7 3c 2c 23 9e 34 50 6b 4f 53 43 4f 52 45 5f 53 61 6c 74
40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
7b c0 9a f2 54 a6 59 29
~~~~~~~~


## Key Update

Key update is defined in Section 4.4 of {{I-D.ietf-lake-edhoc}}:

    EDHOC-KeyUpdate(nonce):
    PRK_4x3m = Extract(nonce, PRK_4x3m)

~~~~~~~~
KeyUpdate Nonce (Raw Value) (16 bytes)
05 bd 1f fd 85 c5 46 da 86 3c 97 0a 34 b7 43 a3
~~~~~~~~

~~~~~~~~
PRK_4x3m after KeyUpdate (Raw Value) (32 bytes)
f4 b6 07 c3 dd 08 cd a5 cf 96 34 4b 61 30 56 be d7 24 15 96 2c c1 55
08 e7 6d ee ab e8 f3 ae ac
~~~~~~~~

The OSCORE Master Secret is derived with the updated PRK_4x3m:

OSCORE Master Secret = HKDF-Expand(PRK_4x3m, info, key_length)

where info and key_length are unchanged.

~~~~~~~~
OSCORE Master Secret after KeyUpdate (Raw Value) (16 bytes)
78 2b e7 48 63 16 b8 0d 89 b6 b7 32 a3 4e 0e 43
~~~~~~~~

The OSCORE Master Salt is derived with the updated PRK_4x3m:

OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
1d fc 71 74 b0 2c 1e 14
~~~~~~~~



# Authentication with signatures, X.509 certificates identified by 'x5t'

In this example the Initiator (I) and Responder (R) are authenticated with digital signatures (METHOD = 0). Both I and R support cipher suite 0, which determines the algorithms:

* EDHOC AEAD algorithm = AES-CCM-16-64-128
* EDHOC hash algorithm = SHA-256
* EDHOC MAC length in bytes (Static DH) = 8
* EDHOC key exchange algorithm (ECDH curve) = X25519
* EDHOC signature algorithm = EdDSA
* Application AEAD algorithm = AES-CCM-16-64-128
* Application hash algorithm = SHA-256


The public keys are represented with X.509 certificates identified by the COSE header parameter 'x5t'.


## message_1

Both endpoints are authenticated with signatures, i.e. METHOD = 0:

~~~~~~~~
METHOD (CBOR Data Item) (1 bytes)
00
~~~~~~~~
{: artwork-align="left"}

I selects cipher suite 0. A single cipher suite is encoded as an int:

~~~~~~~~
SUITES_I (CBOR Data Item) (1 byte)
00
~~~~~~~~

I creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Initiator's ephemeral private key
X (Raw Value) (32 bytes)
89 2e c2 8e 5c b6 66 91 08 47 05 39 50 0b 70 5e 60 d0 08 d3 47 c5 81
7e e9 f3 32 7c 8a 87 bb 03
~~~~~~~~

~~~~~~~~
Initiator's ephemeral public key
G_X (Raw Value) (32 bytes)
31 f8 2c 7b 5b 9c bb f0 f1 94 d9 13 cc 12 ef 15 32 d3 28 ef 32 63 2a
48 81 a1 c0 70 1e 23 7f 04
~~~~~~~~
~~~~~~~~
Initiator's ephemeral public key
G_X (CBOR Data Item) (34 bytes)
58 20 31 f8 2c 7b 5b 9c bb f0 f1 94 d9 13 cc 12 ef 15 32 d3 28 ef 32
63 2a 48 81 a1 c0 70 1e 23 7f 04
~~~~~~~~


I selects its connection identifier C_I to be the int -14:

~~~~~~~~
C_I (Raw Value) (Connection identifier chosen by I) (int)
-14
~~~~~~~~
~~~~~~~~
C_I (CBOR Data Item) (Connection identifier chosen by I) (1 bytes)
2d
~~~~~~~~

No external authorization data:

EAD_1 (CBOR Sequence) (0 bytes)

I constructs message_1:

    message_1 =
    (
     0,
     0,
     h'31F82C7B5B9CBBF0F194D913CC12EF1532D328EF32632A4881A1C0701E237F04',
     -14
    )

~~~~~~~~
message_1 (CBOR Sequence) (37 bytes)
00 00 58 20 31 f8 2c 7b 5b 9c bb f0 f1 94 d9 13 cc 12 ef 15 32 d3 28
ef 32 63 2a 48 81 a1 c0 70 1e 23 7f 04 2d
~~~~~~~~

## message_2

R supports the most preferred and selected cipher suite 0, so SUITES_I is acceptable.

R creates an ephemeral key pair for use with the EDHOC key exchange algorithm:

~~~~~~~~
Responder's ephemeral private key
Y (Raw Value) (32 bytes)
e6 9c 23 fb f8 1b c4 35 94 24 46 83 7f e8 27 bf 20 6c 8f a1 0a 39 db
47 44 9e 5a 81 34 21 e1 e8
~~~~~~~~
~~~~~~~~
Responder's ephemeral public key
G_Y (Raw Value) (32 bytes)
dc 88 d2 d5 1d a5 ed 67 fc 46 16 35 6b c8 ca 74 ef 9e be 8b 38 7e 62
3a 36 0b a4 80 b9 b2 9d 1c
~~~~~~~~
~~~~~~~~
Responder's ephemeral public key
G_Y (CBOR Data Item) (34 bytes)
58 20 dc 88 d2 d5 1d a5 ed 67 fc 46 16 35 6b c8 ca 74 ef 9e be 8b 38
7e 62 3a 36 0b a4 80 b9 b2 9d 1c
~~~~~~~~

PRK_2e is specified in Section 4.1.1 of {{I-D.ietf-lake-edhoc}}.

First, the ECDH shared secret G_XY is computed from G_X and Y, or G_Y and X:

~~~~~~~~
G_XY (Raw Value) (ECDH shared secret) (32 bytes)
e5 cd f3 a9 86 cd ac 5b 7b f0 46 91 e2 b0 7c 08 e7 1f 53 99 8d 8f 84
2b 7c 3f b4 d8 39 cf 7b 28
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
c5 76 10 5d 95 b4 d8 c1 8e 8f 65 5f 54 68 80 a8 54 f2 da 10 6c e5 a3
a0 2d 8b 3e de 7b aa bc a6
~~~~~~~~

Since METHOD = 0, R authenticates using signatures. Since the selected cipher suite is 0, the EDHOC signature algorithm is EdDSA.

R's signature key pair using EdDSA:

~~~~~~~~
Responder's private authentication key
SK_R (Raw Value) (32 bytes)
ef 14 0f f9 00 b0 ab 03 f0 c0 8d 87 9c bb d4 b3 1e a7 1e 6e 7e e7 ff
cb 7e 79 55 77 7a 33 27 99
~~~~~~~~
~~~~~~~~
Responders's public authentication key
PK_R (Raw Value) (32 bytes)
a1 db 47 b9 51 84 85 4a d1 2a 0c 1a 35 4e 41 8a ac e3 3a a0 f2 c6 62
c0 0b 3a c5 5d e9 2f 93 59
~~~~~~~~

PRK_3e2m is specified in Section 4.1.2 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with signatures PRK_3e2m = PRK_2e.

~~~~~~~~
PRK_3e2m (Raw Value) (32 bytes)
c5 76 10 5d 95 b4 d8 c1 8e 8f 65 5f 54 68 80 a8 54 f2 da 10 6c e5 a3
a0 2d 8b 3e de 7b aa bc a6
~~~~~~~~

R selects its connection identifier C_R to be the int 23:

~~~~~~~~
C_R (Raw Value) (Connection identifier chosen by R) (int)
23
~~~~~~~~
~~~~~~~~
C_R (CBOR Data Item) (Connection identifier chosen by R) (1 bytes)
17
~~~~~~~~

The transcript hash TH_2 is calculated using the EDHOC hash algorithm:

TH_2 = H(H(message_1), G_Y, C_R)

~~~~~~~~
H(message_1) (Raw Value) (32 bytes)
c1 65 d6 a9 9d 1b ca fa ac 8d bf 2b 35 2a 6f 7d 71 a3 0b 43 9c 9d 64
d3 49 a2 38 48 03 8e d1 6b
~~~~~~~~

~~~~~~~~
H(message_1) (CBOR Data Item) (34 bytes)
58 20 c1 65 d6 a9 9d 1b ca fa ac 8d bf 2b 35 2a 6f 7d 71 a3 0b 43 9c
9d 64 d3 49 a2 38 48 03 8e d1 6b
~~~~~~~~

The input to calculate TH_2 is the CBOR sequence:

H(message_1), G_Y, C_R

~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (69 bytes)
58 20 c1 65 d6 a9 9d 1b ca fa ac 8d bf 2b 35 2a 6f 7d 71 a3 0b 43 9c
9d 64 d3 49 a2 38 48 03 8e d1 6b 58 20 dc 88 d2 d5 1d a5 ed 67 fc 46
16 35 6b c8 ca 74 ef 9e be 8b 38 7e 62 3a 36 0b a4 80 b9 b2 9d 1c 17
~~~~~~~~

~~~~~~~~
TH_2 (Raw Value) (32 bytes)
3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42 ad ca 36 72 82 26 d2 22 15
97 fd 8c 7f e6 b0 e2 ca 75
~~~~~~~~

~~~~~~~~
TH_2 (CBOR Data Item) (34 bytes)
58 20 3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42 ad ca 36 72 82 26 d2
22 15 97 fd 8c 7f e6 b0 e2 ca 75
~~~~~~~~

R constructs the remaining input needed to calculate MAC_2:

MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2",
            << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2)

CRED_R is identified by a 64-bit hash:

    ID_CRED_R =
    {
      34 : [-15, h'79F2A41B510C1F9B']
    }

where the COSE header value 34 ('x5t') indicates a hash of an X.509 certficate,
and the COSE algorithm -15 indicates the hash algorithm SHA-256 truncated to 64 bits.

ID_CRED_R (CBOR Data Item) (14 bytes)
a1 18 22 82 2e 48 79 f2 a4 1b 51 0c 1f 9b

CRED_R is a CBOR byte string of the DER encoding of the X.509 certificate in {{resp-cer}}:

~~~~~~~~
CRED_R (Raw Value) (241 bytes)
3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504
030C124544484F4320526F6F742045643235353139301E170D323230333136303832
3433365A170D3239313233313233303030305A30223120301E06035504030C174544
484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1
DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506
032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FEC
FAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C1
52CB02
~~~~~~~~

~~~~~~~~
CRED_R (CBOR Data Item) (243 bytes)
58 f1 30 81 ee 30 81 a1 a0 03 02 01 02 02 04 62 31 9e c4 30 05 06 03
2b 65 70 30 1d 31 1b 30 19 06 03 55 04 03 0c 12 45 44 48 4f 43 20 52
6f 6f 74 20 45 64 32 35 35 31 39 30 1e 17 0d 32 32 30 33 31 36 30 38
32 34 33 36 5a 17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 22 31
20 30 1e 06 03 55 04 03 0c 17 45 44 48 4f 43 20 52 65 73 70 6f 6e 64
65 72 20 45 64 32 35 35 31 39 30 2a 30 05 06 03 2b 65 70 03 21 00 a1
db 47 b9 51 84 85 4a d1 2a 0c 1a 35 4e 41 8a ac e3 3a a0 f2 c6 62 c0
0b 3a c5 5d e9 2f 93 59 30 05 06 03 2b 65 70 03 41 00 b7 23 bc 01 ea
b0 92 8e 8b 2b 6c 98 de 19 cc 38 23 d4 6e 7d 69 87 b0 32 47 8f ec fa
f1 45 37 a1 af 14 cc 8b e8 29 c6 b7 30 44 10 18 37 eb 4a bc 94 95 65
d8 6d ce 51 cf ae 52 ab 82 c1 52 cb 02
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_2 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_2 is computed through Expand() using the EDHOC hash algorithm, Section 4.2 of {{I-D.ietf-lake-edhoc}}:

MAC_2 = HKDF-Expand(PRK_3e2m, info, mac_length_2), where

info = ( TH_2, “MAC_2”, << ID_CRED_R, CRED_R, ? EAD_2 >>, mac_length_2 )

Since METHOD = 0, mac_length_2 is given by the EDHOC hash algorithm.

info for MAC_2 is:

    info =
    (
     h'3C3E0E79269592A2F4B3CCE01642ADCA36728226D2221597FD8C7FE6B0E2CA75',
     "MAC_2",
     h'A11822822E4879F2A41B510C1F9B58F13081EE3081A1A003020102020462319EC4
     300506032B6570301D311B301906035504030C124544484F4320526F6F7420456432
     35353139301E170D3232303331363038323433365A170D3239313233313233303030
     305A30223120301E06035504030C174544484F4320526573706F6E64657220456432
     35353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE3
     3AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B
     6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B730441018
     37EB4ABC949565D86DCE51CFAE52AB82C152CB02',
     32
    )

where the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_2 (CBOR Sequence) (302 bytes)
58 20 3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42 ad ca 36 72 82 26 d2
22 15 97 fd 8c 7f e6 b0 e2 ca 75 65 4d 41 43 5f 32 59 01 01 a1 18 22
82 2e 48 79 f2 a4 1b 51 0c 1f 9b 58 f1 30 81 ee 30 81 a1 a0 03 02 01
02 02 04 62 31 9e c4 30 05 06 03 2b 65 70 30 1d 31 1b 30 19 06 03 55
04 03 0c 12 45 44 48 4f 43 20 52 6f 6f 74 20 45 64 32 35 35 31 39 30
1e 17 0d 32 32 30 33 31 36 30 38 32 34 33 36 5a 17 0d 32 39 31 32 33
31 32 33 30 30 30 30 5a 30 22 31 20 30 1e 06 03 55 04 03 0c 17 45 44
48 4f 43 20 52 65 73 70 6f 6e 64 65 72 20 45 64 32 35 35 31 39 30 2a
30 05 06 03 2b 65 70 03 21 00 a1 db 47 b9 51 84 85 4a d1 2a 0c 1a 35
4e 41 8a ac e3 3a a0 f2 c6 62 c0 0b 3a c5 5d e9 2f 93 59 30 05 06 03
2b 65 70 03 41 00 b7 23 bc 01 ea b0 92 8e 8b 2b 6c 98 de 19 cc 38 23
d4 6e 7d 69 87 b0 32 47 8f ec fa f1 45 37 a1 af 14 cc 8b e8 29 c6 b7
30 44 10 18 37 eb 4a bc 94 95 65 d8 6d ce 51 cf ae 52 ab 82 c1 52 cb
02 18 20
~~~~~~~~

~~~~~~~~
MAC_2 (Raw Value) (32 bytes)
4b f7 66 29 bd b9 38 ab 7d 41 97 c5 1b 27 94 a8 ad 17 c3 bf 54 2b 15
3f 42 7d c8 a8 b1 59 3b 90
~~~~~~~~

~~~~~~~~
MAC_2 (CBOR Data Item) (34 bytes)
58 20 4b f7 66 29 bd b9 38 ab 7d 41 97 c5 1b 27 94 a8 ad 17 c3 bf 54
2b 15 3f 42 7d c8 a8 b1 59 3b 90
~~~~~~~~



Since METHOD = 0, Signature_or_MAC_2 is the 'signature' of the COSE_Sign1 object.

R constructs the message to be signed:

    [ "Signature1", << ID_CRED_R >>,
     << TH_2, CRED_R, ? EAD_2 >>, MAC_2 ] =

    [
     "Signature1",
     h'A11822822E4879F2A41B510C1F9B',
     h'58203C3E0E79269592A2F4B3CCE01642ADCA36728226D2221597FD8C7FE6B0E2
     CA7558F13081EE3081A1A003020102020462319EC4300506032B6570301D311B30
     1906035504030C124544484F4320526F6F742045643235353139301E170D323230
     3331363038323433365A170D3239313233313233303030305A30223120301E0603
     5504030C174544484F4320526573706F6E6465722045643235353139302A300506
     032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3A
     C55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823
     D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC9495
     65D86DCE51CFAE52AB82C152CB02',
     h'4BF76629BDB938AB7D4197C51B2794A8AD17C3BF542B153F427DC8A8B1593B90'
    ]

~~~~~~~~
Message to be signed 2 (CBOR Data Item) (341 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 79 f2 a4 1b
51 0c 1f 9b 59 01 15 58 20 3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42
ad ca 36 72 82 26 d2 22 15 97 fd 8c 7f e6 b0 e2 ca 75 58 f1 30 81 ee
30 81 a1 a0 03 02 01 02 02 04 62 31 9e c4 30 05 06 03 2b 65 70 30 1d
31 1b 30 19 06 03 55 04 03 0c 12 45 44 48 4f 43 20 52 6f 6f 74 20 45
64 32 35 35 31 39 30 1e 17 0d 32 32 30 33 31 36 30 38 32 34 33 36 5a
17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 22 31 20 30 1e 06 03
55 04 03 0c 17 45 44 48 4f 43 20 52 65 73 70 6f 6e 64 65 72 20 45 64
32 35 35 31 39 30 2a 30 05 06 03 2b 65 70 03 21 00 a1 db 47 b9 51 84
85 4a d1 2a 0c 1a 35 4e 41 8a ac e3 3a a0 f2 c6 62 c0 0b 3a c5 5d e9
2f 93 59 30 05 06 03 2b 65 70 03 41 00 b7 23 bc 01 ea b0 92 8e 8b 2b
6c 98 de 19 cc 38 23 d4 6e 7d 69 87 b0 32 47 8f ec fa f1 45 37 a1 af
14 cc 8b e8 29 c6 b7 30 44 10 18 37 eb 4a bc 94 95 65 d8 6d ce 51 cf
ae 52 ab 82 c1 52 cb 02 58 20 4b f7 66 29 bd b9 38 ab 7d 41 97 c5 1b
27 94 a8 ad 17 c3 bf 54 2b 15 3f 42 7d c8 a8 b1 59 3b 90
~~~~~~~~

R signs using the private authentication key SK_R

~~~~~~~~
Signature_or_MAC_2 (Raw Value) (64 bytes)
39 a1 29 6e 81 f3 8e 01 8a c9 8f ab 94 c7 96 ea 95 1a 89 db 2b 86 6a
8f 2a d1 aa 9f 64 63 9f ef c9 31 74 f0 de 86 8c 32 60 d4 8a c8 9d b9
f6 95 41 a1 24 21 a0 86 eb 43 b0 a2 eb 44 c8 9e 91 07
~~~~~~~~
~~~~~~~~
Signature_or_MAC_2 (CBOR Data Item) (66 bytes)
58 40 39 a1 29 6e 81 f3 8e 01 8a c9 8f ab 94 c7 96 ea 95 1a 89 db 2b
86 6a 8f 2a d1 aa 9f 64 63 9f ef c9 31 74 f0 de 86 8c 32 60 d4 8a c8
9d b9 f6 95 41 a1 24 21 a0 86 eb 43 b0 a2 eb 44 c8 9e 91 07
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
a1 18 22 82 2e 48 79 f2 a4 1b 51 0c 1f 9b 58 40 39 a1 29 6e 81 f3 8e
01 8a c9 8f ab 94 c7 96 ea 95 1a 89 db 2b 86 6a 8f 2a d1 aa 9f 64 63
9f ef c9 31 74 f0 de 86 8c 32 60 d4 8a c8 9d b9 f6 95 41 a1 24 21 a0
86 eb 43 b0 a2 eb 44 c8 9e 91 07
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
58 20 3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42 ad ca 36 72 82 26 d2
22 15 97 fd 8c 7f e6 b0 e2 ca 75 6b 4b 45 59 53 54 52 45 41 4d 5f 32
40 18 50
~~~~~~~~

~~~~~~~~
KEYSTREAM_2 (Raw Value) (80 bytes)
48 0a db a1 4e ce c9 d0 e6 b6 07 a5 97 19 c4 72 9b 23 d2 be 47 31 5e
64 cd 5c c7 65 42 e1 7e 36 ae 77 e7 29 8e 0e 95 bc d7 fc ab 5f 6a 7b
01 59 45 98 93 e7 de fc 61 50 74 e9 70 2f cb 9b c6 9b 57 cf f7 64 cc
5f 63 08 f4 14 7d 70 bf 34 af 18
~~~~~~~~

R calculates CIPHERTEXT_2 as XOR between PLAINTEXT_2 and KEYSTREAM_2:

~~~~~~~~
CIPHERTEXT_2 (Raw Value) (80 bytes)
e9 12 f9 23 60 86 b0 22 42 ad 56 a9 88 82 9c 32 a2 82 fb d0 c6 c2 d0
65 47 95 48 ce d6 26 e8 dc 3b 6d 6e f2 a5 88 ff 33 fd 2d 01 c0 0e 18
9e b6 8c a9 e7 17 00 7a ed 62 14 3d fa e7 56 22 30 0e 16 6e d3 45 6c
d9 88 4b 44 b6 96 34 77 aa 3e 1f
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
58 70 dc 88 d2 d5 1d a5 ed 67 fc 46 16 35 6b c8 ca 74 ef 9e be 8b 38
7e 62 3a 36 0b a4 80 b9 b2 9d 1c e9 12 f9 23 60 86 b0 22 42 ad 56 a9
88 82 9c 32 a2 82 fb d0 c6 c2 d0 65 47 95 48 ce d6 26 e8 dc 3b 6d 6e
f2 a5 88 ff 33 fd 2d 01 c0 0e 18 9e b6 8c a9 e7 17 00 7a ed 62 14 3d
fa e7 56 22 30 0e 16 6e d3 45 6c d9 88 4b 44 b6 96 34 77 aa 3e 1f 17
~~~~~~~~


## message_3

Since METHOD = 0, I authenticates using signatures. Since the selected cipher suite is 0, the EDHOC signature algorithm is EdDSA.

I's signature key pair using EdDSA:

~~~~~~~~
Initiator's private authentication key
SK_I (Raw Value) (32 bytes)
4c 5b 25 87 8f 50 7c 6b 9d ae 68 fb d4 fd 3f f9 97 53 3d b0 af 00 b2
5d 32 4e a2 8e 6c 21 3b c8
~~~~~~~~

~~~~~~~~
Initiator's public authentication key
PK_I (Raw Value) (32 bytes)
ed 06 a8 ae 61 a8 29 ba 5f a5 45 25 c9 d0 7f 48 dd 44 a3 02 f4 3e 0f
23 d8 cc 20 b7 30 85 14 1e
~~~~~~~~

PRK_4x3m is specified in Section 4.1.3 of {{I-D.ietf-lake-edhoc}}.

Since R authenticates with signatures PRK_4x3m = PRK_3e2m.

~~~~~~~~
PRK_4x3m (Raw Value) (32 bytes)
c5 76 10 5d 95 b4 d8 c1 8e 8f 65 5f 54 68 80 a8 54 f2 da 10 6c e5 a3
a0 2d 8b 3e de 7b aa bc a6
~~~~~~~~

The transcript hash TH_3 is calculated using the EDHOC hash algorithm:

TH_3 = H(TH_2, CIPHERTEXT_2)

~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (116 bytes)
58 20 3c 3e 0e 79 26 95 92 a2 f4 b3 cc e0 16 42 ad ca 36 72 82 26 d2
22 15 97 fd 8c 7f e6 b0 e2 ca 75 58 50 e9 12 f9 23 60 86 b0 22 42 ad
56 a9 88 82 9c 32 a2 82 fb d0 c6 c2 d0 65 47 95 48 ce d6 26 e8 dc 3b
6d 6e f2 a5 88 ff 33 fd 2d 01 c0 0e 18 9e b6 8c a9 e7 17 00 7a ed 62
14 3d fa e7 56 22 30 0e 16 6e d3 45 6c d9 88 4b 44 b6 96 34 77 aa 3e
1f
~~~~~~~~

~~~~~~~~
TH_3 (Raw Value) (32 bytes)
04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5 fc 02
c8 12 56 da bb 1b 60 c7 de
~~~~~~~~

~~~~~~~~
TH_3 (CBOR Data Item) (34 bytes)
58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5
fc 02 c8 12 56 da bb 1b 60 c7 de
~~~~~~~~

I constructs the remaining input needed to calculate MAC_3:

    MAC_3 = EDHOC-KDF(PRK_4x3m, TH_3, "MAC_3",
            << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3)

CRED_I is identified by a 64-bit hash:

    ID_CRED_I =
    {
      34 : [-15, h'C24AB2FD7643C79F']
    }

where the COSE header value 34 ('x5t') indicates a hash of an X.509 certficate,
and the COSE algorithm -15 indicates the hash algorithm SHA-256 truncated to 64 bits.

~~~~~~~~
ID_CRED_I (CBOR Data Item) (14 bytes)
a1 18 22 82 2e 48 c2 4a b2 fd 76 43 c7 9f
~~~~~~~~

CRED_I is a CBOR byte string of the DER encoding of the X.509 certificate in {{init-cer}}:

~~~~~~~~
CRED_I (Raw Value) (241 bytes)
3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504
030C124544484F4320526F6F742045643235353139301E170D323230333136303832
3430305A170D3239313233313233303030305A30223120301E06035504030C174544
484F4320496E69746961746F722045643235353139302A300506032B6570032100ED
06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506
032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B392
75AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A0
0B430B
~~~~~~~~

~~~~~~~~
CRED_I (CBOR Data Item) (243 bytes)
58 f1 30 81 ee 30 81 a1 a0 03 02 01 02 02 04 62 31 9e a0 30 05 06 03
2b 65 70 30 1d 31 1b 30 19 06 03 55 04 03 0c 12 45 44 48 4f 43 20 52
6f 6f 74 20 45 64 32 35 35 31 39 30 1e 17 0d 32 32 30 33 31 36 30 38
32 34 30 30 5a 17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 22 31
20 30 1e 06 03 55 04 03 0c 17 45 44 48 4f 43 20 49 6e 69 74 69 61 74
6f 72 20 45 64 32 35 35 31 39 30 2a 30 05 06 03 2b 65 70 03 21 00 ed
06 a8 ae 61 a8 29 ba 5f a5 45 25 c9 d0 7f 48 dd 44 a3 02 f4 3e 0f 23
d8 cc 20 b7 30 85 14 1e 30 05 06 03 2b 65 70 03 41 00 52 12 41 d8 b3
a7 70 99 6b cf c9 b9 ea d4 e7 e0 a1 c0 db 35 3a 3b df 29 10 b3 92 75
ae 48 b7 56 01 59 81 85 0d 27 db 67 34 e3 7f 67 21 22 67 dd 05 ee ff
27 b9 e7 a8 13 fa 57 4b 72 a0 0b 43 0b
~~~~~~~~

No external authorization data:

~~~~~~~~
EAD_3 (CBOR Sequence) (0 bytes)
~~~~~~~~

MAC_3 is computed through Expand() using the
EDHOC hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    MAC_3 = HKDF-Expand(PRK_4x3m, info, mac_length_3), where

info = ( TH_3, “MAC_3”, << ID_CRED_I, CRED_I, ? EAD_3 >>, mac_length_3 )

Since METHOD = 0, mac_length_3 is given by the EDHOC hash algorithm.

info for MAC_3 is:

    info =
    (
     h'04634D66B7E982F3508363B30624C8869143D775E5FC02C81256DABB1B60C7DE',
     "MAC_3",
     h'A11822822E48C24AB2FD7643C79F58F13081EE3081A1A003020102020462319EA0
     300506032B6570301D311B301906035504030C124544484F4320526F6F7420456432
     35353139301E170D3232303331363038323430305A170D3239313233313233303030
     305A30223120301E06035504030C174544484F4320496E69746961746F7220456432
     35353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44
     A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCF
     C9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67
     212267DD05EEFF27B9E7A813FA574B72A00B430B',
     32
    )

where the last value is the output size of the EDHOC hash algorithm.

~~~~~~~~
info for MAC_3 (CBOR Sequence) (302 bytes)
58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5
fc 02 c8 12 56 da bb 1b 60 c7 de 65 4d 41 43 5f 33 59 01 01 a1 18 22
82 2e 48 c2 4a b2 fd 76 43 c7 9f 58 f1 30 81 ee 30 81 a1 a0 03 02 01
02 02 04 62 31 9e a0 30 05 06 03 2b 65 70 30 1d 31 1b 30 19 06 03 55
04 03 0c 12 45 44 48 4f 43 20 52 6f 6f 74 20 45 64 32 35 35 31 39 30
1e 17 0d 32 32 30 33 31 36 30 38 32 34 30 30 5a 17 0d 32 39 31 32 33
31 32 33 30 30 30 30 5a 30 22 31 20 30 1e 06 03 55 04 03 0c 17 45 44
48 4f 43 20 49 6e 69 74 69 61 74 6f 72 20 45 64 32 35 35 31 39 30 2a
30 05 06 03 2b 65 70 03 21 00 ed 06 a8 ae 61 a8 29 ba 5f a5 45 25 c9
d0 7f 48 dd 44 a3 02 f4 3e 0f 23 d8 cc 20 b7 30 85 14 1e 30 05 06 03
2b 65 70 03 41 00 52 12 41 d8 b3 a7 70 99 6b cf c9 b9 ea d4 e7 e0 a1
c0 db 35 3a 3b df 29 10 b3 92 75 ae 48 b7 56 01 59 81 85 0d 27 db 67
34 e3 7f 67 21 22 67 dd 05 ee ff 27 b9 e7 a8 13 fa 57 4b 72 a0 0b 43
0b 18 20
~~~~~~~~

~~~~~~~~
MAC_3 (Raw Value) (32 bytes)
47 0a 28 e5 db f3 6c a0 a8 00 70 f8 95 27 ae 9f 87 94 94 dd a1 58 19
e3 2a aa 4c 44 54 6d ae 0f
~~~~~~~~

~~~~~~~~
MAC_3 (CBOR Data Item) (34 bytes)
58 20 47 0a 28 e5 db f3 6c a0 a8 00 70 f8 95 27 ae 9f 87 94 94 dd a1
58 19 e3 2a aa 4c 44 54 6d ae 0f
~~~~~~~~

Since METHOD = 0, Signature_or_MAC_3 is the 'signature' of the
COSE_Sign1 object.

I constructs the message to be signed:

    [ "Signature1", << ID_CRED_I >>,
     << TH_3, CRED_I, ? EAD_3 >>, MAC_3 ] =

    [
     "Signature1",
     h'A11822822E48C24AB2FD7643C79F',
     h'582004634D66B7E982F3508363B30624C8869143D775E5FC02C81256DABB1B60C
     7DE58F13081EE3081A1A003020102020462319EA0300506032B6570301D311B3019
     06035504030C124544484F4320526F6F742045643235353139301E170D323230333
     1363038323430305A170D3239313233313233303030305A30223120301E06035504
     030C174544484F4320496E69746961746F722045643235353139302A300506032B6
     570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B730
     85141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353
     A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7
     A813FA574B72A00B430B',
     h'470A28E5DBF36CA0A80070F89527AE9F879494DDA15819E32AAA4C44546DAE0F'
    ]

~~~~~~~~
Message to be signed 3 (CBOR Data Item) (341 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 c2 4a b2 fd
76 43 c7 9f 59 01 15 58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24
c8 86 91 43 d7 75 e5 fc 02 c8 12 56 da bb 1b 60 c7 de 58 f1 30 81 ee
30 81 a1 a0 03 02 01 02 02 04 62 31 9e a0 30 05 06 03 2b 65 70 30 1d
31 1b 30 19 06 03 55 04 03 0c 12 45 44 48 4f 43 20 52 6f 6f 74 20 45
64 32 35 35 31 39 30 1e 17 0d 32 32 30 33 31 36 30 38 32 34 30 30 5a
17 0d 32 39 31 32 33 31 32 33 30 30 30 30 5a 30 22 31 20 30 1e 06 03
55 04 03 0c 17 45 44 48 4f 43 20 49 6e 69 74 69 61 74 6f 72 20 45 64
32 35 35 31 39 30 2a 30 05 06 03 2b 65 70 03 21 00 ed 06 a8 ae 61 a8
29 ba 5f a5 45 25 c9 d0 7f 48 dd 44 a3 02 f4 3e 0f 23 d8 cc 20 b7 30
85 14 1e 30 05 06 03 2b 65 70 03 41 00 52 12 41 d8 b3 a7 70 99 6b cf
c9 b9 ea d4 e7 e0 a1 c0 db 35 3a 3b df 29 10 b3 92 75 ae 48 b7 56 01
59 81 85 0d 27 db 67 34 e3 7f 67 21 22 67 dd 05 ee ff 27 b9 e7 a8 13
fa 57 4b 72 a0 0b 43 0b 58 20 47 0a 28 e5 db f3 6c a0 a8 00 70 f8 95
27 ae 9f 87 94 94 dd a1 58 19 e3 2a aa 4c 44 54 6d ae 0f
~~~~~~~~

R signs using the private authentication key SK_R:

~~~~~~~~
Signature_or_MAC_3 (Raw Value) (64 bytes)
63 a0 fc 1d 1f a9 00 82 69 34 07 75 f4 2f f2 c8 a6 27 67 27 15 a1 0d
6f 49 b8 05 ef 57 a7 1b d1 68 e0 a8 e8 63 31 02 c9 58 6b 31 6b 84 f1
a6 44 52 00 4f fc dc 66 6c 24 56 e6 d9 fb 72 0c dd 07
~~~~~~~~

~~~~~~~~
Signature_or_MAC_3 (CBOR Data Item) (66 bytes)
58 40 63 a0 fc 1d 1f a9 00 82 69 34 07 75 f4 2f f2 c8 a6 27 67 27 15
a1 0d 6f 49 b8 05 ef 57 a7 1b d1 68 e0 a8 e8 63 31 02 c9 58 6b 31 6b
84 f1 a6 44 52 00 4f fc dc 66 6c 24 56 e6 d9 fb 72 0c dd 07
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
a1 18 22 82 2e 48 c2 4a b2 fd 76 43 c7 9f 58 40 63 a0 fc 1d 1f a9 00
82 69 34 07 75 f4 2f f2 c8 a6 27 67 27 15 a1 0d 6f 49 b8 05 ef 57 a7
1b d1 68 e0 a8 e8 63 31 02 c9 58 6b 31 6b 84 f1 a6 44 52 00 4f fc dc
66 6c 24 56 e6 d9 fb 72 0c dd 07
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
83 68 45 6e 63 72 79 70 74 30 40 58 20 04 63 4d 66 b7 e9 82 f3 50 83
63 b3 06 24 c8 86 91 43 d7 75 e5 fc 02 c8 12 56 da bb 1b 60 c7 de
~~~~~~~~

I constructs the input needed to derive the key K_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    K_3 = EDHOC-KDF(PRK_3e2m, TH_3, "K_3", h'', length) =
                = HKDF-Expand(PRK_3e2m, info, length),

where length is the key length of EDHOC AEAD algorithm, and info for K_3 is:

    info =
    (
     h'04634D66B7E982F3508363B30624C8869143D775E5FC02C81256DABB1B60C7DE',
     "K_3",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.


~~~~~~~~
info for K_3 (CBOR Sequence) (40 bytes)
58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5
fc 02 c8 12 56 da bb 1b 60 c7 de 63 4b 5f 33 40 10
~~~~~~~~

~~~~~~~~
K_3 (Raw Value) (16 bytes)
5f 80 51 0f e4 31 8a 78 04 df c3 3d ea 50 1b 57
~~~~~~~~

I constructs the input needed to derive the nonce IV_3, see Section 4.2 of {{I-D.ietf-lake-edhoc}}, using the EDHOC hash algorithm:

    IV_3 = EDHOC-KDF(PRK_3e2m, TH_3, "IV_3", h'', length) =
           = HKDF-Expand(PRK_3e2m, info, length),

where length is the nonce length of EDHOC AEAD algorithm, and info for IV_3 is:

    info =
    (
     h'04634D66B7E982F3508363B30624C8869143D775E5FC02C81256DABB1B60C7DE',
     "IV_3",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_3 (CBOR Sequence) (41 bytes)
58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5
fc 02 c8 12 56 da bb 1b 60 c7 de 64 49 56 5f 33 40 0d
~~~~~~~~

~~~~~~~~
IV_3 (Raw Value) (13 bytes)
be ab 44 63 11 38 ef 59 1e 18 a8 52 00
~~~~~~~~

I calculates CIPHERTEXT_3 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_3, additional data
A_3, key K_3 and nonce IV_3.

~~~~~~~~
CIPHERTEXT_3 (Raw Value) (88 bytes)
0a 21 aa aa 20 4a 69 ec e8 eb c2 a7 b3 57 ab 5a ae d0 46 13 89 85 29
91 2f 2c 8a 67 24 cb 11 4e c9 2c dd 3d fe e8 c5 4c 11 92 36 b4 d1 e8
46 41 6a e7 8c 25 aa 0f 93 df 2d e5 51 aa 13 e3 14 97 ca e6 61 a5 fd
39 2a cd 40 58 25 4b ad f2 4d ee 95 50 38 7d 71 06 43 4a
~~~~~~~~

message_3 is the CBOR bstr encoding of CIPHERTEXT_3:

~~~~~~~~
message_3 (CBOR Sequence) (90 bytes)
58 58 0a 21 aa aa 20 4a 69 ec e8 eb c2 a7 b3 57 ab 5a ae d0 46 13 89
85 29 91 2f 2c 8a 67 24 cb 11 4e c9 2c dd 3d fe e8 c5 4c 11 92 36 b4
d1 e8 46 41 6a e7 8c 25 aa 0f 93 df 2d e5 51 aa 13 e3 14 97 ca e6 61
a5 fd 39 2a cd 40 58 25 4b ad f2 4d ee 95 50 38 7d 71 06 43 4a
~~~~~~~~

The transcript hash TH_4 is calculated using the EDHOC hash algorithm:

TH_4 = H(TH_3, CIPHERTEXT_3)

~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (124 bytes)
58 20 04 63 4d 66 b7 e9 82 f3 50 83 63 b3 06 24 c8 86 91 43 d7 75 e5
fc 02 c8 12 56 da bb 1b 60 c7 de 58 58 0a 21 aa aa 20 4a 69 ec e8 eb
c2 a7 b3 57 ab 5a ae d0 46 13 89 85 29 91 2f 2c 8a 67 24 cb 11 4e c9
2c dd 3d fe e8 c5 4c 11 92 36 b4 d1 e8 46 41 6a e7 8c 25 aa 0f 93 df
2d e5 51 aa 13 e3 14 97 ca e6 61 a5 fd 39 2a cd 40 58 25 4b ad f2 4d
ee 95 50 38 7d 71 06 43 4a
~~~~~~~~

~~~~~~~~
TH_4 (Raw Value) (32 bytes)
99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2 87 c1
2d 95 8f 65 d2 6f ab 56 fa
~~~~~~~~

~~~~~~~~
TH_4 (CBOR Data Item) (34 bytes)
58 20 99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2
87 c1 2d 95 8f 65 d2 6f ab 56 fa
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
83 68 45 6e 63 72 79 70 74 30 40 58 20 99 3a 29 90 96 31 78 04 3a 15
1d 1e 10 fa 0a c9 68 fd 9c 24 e2 87 c1 2d 95 8f 65 d2 6f ab 56 fa
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
     h'993A2990963178043A151D1E10FA0AC968FD9C24E287C12D958F65D26FAB56FA',
     "EDHOC_K_4",
     h'',
     16
    )

where the last value is the key length of EDHOC AEAD algorithm.

~~~~~~~~
info for K_4 (CBOR Sequence) (46 bytes)
58 20 99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2
87 c1 2d 95 8f 65 d2 6f ab 56 fa 69 45 44 48 4f 43 5f 4b 5f 34 40 10
~~~~~~~~

~~~~~~~~
K_4 (Raw Value) (16 bytes)
0f eb f2 83 64 6d c3 fc 62 0f 56 12 f8 07 02 6e
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
     h'993A2990963178043A151D1E10FA0AC968FD9C24E287C12D958F65D26FAB56FA',
     "EDHOC_IV_4",
     h'',
     13
    )

where the last value is the nonce length of EDHOC AEAD algorithm.

~~~~~~~~
info for IV_4 (CBOR Sequence) (47 bytes)
58 20 99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2
87 c1 2d 95 8f 65 d2 6f ab 56 fa 6a 45 44 48 4f 43 5f 49 56 5f 34 40
0d
~~~~~~~~

~~~~~~~~
IV_4 (Raw Value) (13 bytes)
45 9b 8b 89 1b 5c 98 af 26 5d 78 55 3d
~~~~~~~~

R calculates CIPHERTEXT_4 as 'ciphertext' of COSE_Encrypt0 applied
using the EDHOC AEAD algorithm with plaintext P_4, additional data
A_4, key K_4 and nonce IV_4.


~~~~~~~~
CIPHERTEXT_4 (8 bytes)
31 d9 3d 50 3b a3 f9 5d
~~~~~~~~

message_4 is the CBOR bstr encoding of CIPHERTEXT_4:

~~~~~~~~
message_4 (CBOR Sequence) (9 bytes)
48 31 d9 3d 50 3b a3 f9 5d
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
17
~~~~~~~~

C_I is mapped to the Recipient ID of the client, i.e., the Sender ID of the server. Since C_I is a numeric, it is converted to a byte string equal to its CBOR encoded form.

~~~~~~~~
Server's OSCORE Sender ID (Raw Value) (1 bytes)
2d
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
     h'993A2990963178043A151D1E10FA0AC968FD9C24E287C12D958F65D26FAB56FA',
     "OSCORE_Secret",
     h'',
     16
    )

where the last value is the key length of Application AEAD algorithm.

~~~~~~~~
info for OSCORE Master Secret (CBOR Sequence) (50 bytes)
58 20 99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2
87 c1 2d 95 8f 65 d2 6f ab 56 fa 6d 4f 53 43 4f 52 45 5f 53 65 63 72
65 74 40 10
~~~~~~~~

~~~~~~~~
OSCORE Master Secret (Raw Value) (16 bytes)
99 31 3e 45 90 5e 15 f1 29 0f 7d d6 f4 58 36 01
~~~~~~~~

The OSCORE Master Salt is computed through Expand() using the Application hash algorithm, see Section 4.2 of {{I-D.ietf-lake-edhoc}}:

    OSCORE Master Salt =
    = EDHOC-Exporter("OSCORE_Salt", h'', salt_length)
    = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE_Salt", h'', salt_length)
    = HKDF-Expand(PRK_4x3m, info, salt_length)

where salt_length is the length of the OSCORE Master Salt, and info for the OSCORE Master Salt is:

    info =
    (
     h'993A2990963178043A151D1E10FA0AC968FD9C24E287C12D958F65D26FAB56FA',
     "OSCORE_Salt",
     h'',
     8
    )

where the last value is the length of the OSCORE Master Salt.

~~~~~~~~
info for OSCORE Master Salt (CBOR Sequence) (48 bytes)
58 20 99 3a 29 90 96 31 78 04 3a 15 1d 1e 10 fa 0a c9 68 fd 9c 24 e2
87 c1 2d 95 8f 65 d2 6f ab 56 fa 6b 4f 53 43 4f 52 45 5f 53 61 6c 74
40 08
~~~~~~~~

~~~~~~~~
OSCORE Master Salt (Raw Value) (8 bytes)
a8 49 e3 e5 d3 fe 5d 90
~~~~~~~~


## Key Update

Key update is defined in Section 4.4 of {{I-D.ietf-lake-edhoc}}.

    EDHOC-KeyUpdate(nonce):
    PRK_4x3m = Extract(nonce, PRK_4x3m)

~~~~~~~~
KeyUpdate Nonce (Raw Value) (16 bytes)
d6 be 16 96 02 b8 bc ea a0 11 58 fd b8 20 89 0c
~~~~~~~~

~~~~~~~~
PRK_4x3m after KeyUpdate (Raw Value) (32 bytes)
48 c6 4f 39 75 9c f6 95 16 8b 04 f9 b1 d0 ed 5d 34 2a 0d c2 3d 56 b9
a3 9d df ad 74 15 24 43 14
~~~~~~~~

The OSCORE Master Secret is derived with the updated PRK_4x3m:

    OSCORE Master Secret = HKDF-Expand(PRK_4x3m, info, key_length)

where info and key_length are unchanged.

~~~~~~~~
OSCORE Master Secret after KeyUpdate (Raw Value) (16 bytes)
3f f3 47 13 4e 74 a6 c6 55 a1 18 0b 2b f2 35 35
~~~~~~~~

The OSCORE Master Salt is derived with the updated PRK_4x3m:

    OSCORE Master Salt = HKDF-Expand(PRK_4x3m, info, salt_length)

where info and salt_length are unchanged.

~~~~~~~~
OSCORE Master Salt after KeyUpdate (Raw Value) (8 bytes)
28 b6 08 ad bb fc aa 2c
~~~~~~~~

## Certificates



### Responder Certificate {#resp-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1647419076 (0x62319ec4)
        Signature Algorithm: ED25519
        Issuer: CN = EDHOC Root Ed25519
        Validity
            Not Before: Mar 16 08:24:36 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN = EDHOC Responder Ed25519
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    a1:db:47:b9:51:84:85:4a:d1:2a:0c:1a:35:4e:41:
                    8a:ac:e3:3a:a0:f2:c6:62:c0:0b:3a:c5:5d:e9:2f:
                    93:59
    Signature Algorithm: ED25519
    Signature Value:
        b7:23:bc:01:ea:b0:92:8e:8b:2b:6c:98:de:19:cc:38:23:d4:
        6e:7d:69:87:b0:32:47:8f:ec:fa:f1:45:37:a1:af:14:cc:8b:
        e8:29:c6:b7:30:44:10:18:37:eb:4a:bc:94:95:65:d8:6d:ce:
        51:cf:ae:52:ab:82:c1:52:cb:02
~~~~~~~~

### Initiator Certificate {#init-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1647419040 (0x62319ea0)
        Signature Algorithm: ED25519
        Issuer: CN = EDHOC Root Ed25519
        Validity
            Not Before: Mar 16 08:24:00 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN = EDHOC Initiator Ed25519
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ed:06:a8:ae:61:a8:29:ba:5f:a5:45:25:c9:d0:7f:
                    48:dd:44:a3:02:f4:3e:0f:23:d8:cc:20:b7:30:85:
                    14:1e
    Signature Algorithm: ED25519
    Signature Value:
        52:12:41:d8:b3:a7:70:99:6b:cf:c9:b9:ea:d4:e7:e0:a1:c0:
        db:35:3a:3b:df:29:10:b3:92:75:ae:48:b7:56:01:59:81:85:
        0d:27:db:67:34:e3:7f:67:21:22:67:dd:05:ee:ff:27:b9:e7:
        a8:13:fa:57:4b:72:a0:0b:43:0b
~~~~~~~~


### Common Root Certificate {#root-cer}

~~~~~~~~
        Version: 3 (0x2)
        Serial Number: 1647418996 (0x62319e74)
        Signature Algorithm: ED25519
        Issuer: CN = EDHOC Root Ed25519
        Validity
            Not Before: Mar 16 08:23:16 2022 GMT
            Not After : Dec 31 23:00:00 2029 GMT
        Subject: CN = EDHOC Root Ed25519
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    2b:7b:3e:80:57:c8:64:29:44:d0:6a:fe:7a:71:d1:
                    c9:bf:96:1b:62:92:ba:c4:b0:4f:91:66:9b:bb:71:
                    3b:e4
    Signature Algorithm: ED25519
    Signature Value:
        4b:b5:2b:bf:15:39:b7:1a:4a:af:42:97:78:f2:9e:da:7e:81:
        46:80:69:8f:16:c4:8f:2a:6f:a4:db:e8:25:41:c5:82:07:ba:
        1b:c9:cd:b0:c2:fa:94:7f:fb:f0:f0:ec:0e:e9:1a:7f:f3:7a:
        94:d9:25:1f:a5:cd:f1:e6:7a:0f
~~~~~~~~



# Security Considerations {#security}

This document contains examples of EDHOC {{I-D.ietf-lake-edhoc}} whose security considerations apply. The keys printed in these examples cannot be considered secret and must not be used.

# IANA Considerations {#iana}

There are no IANA considerations.

--- back


# Acknowledgments
{: numbered="no"}

--- fluff
