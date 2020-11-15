

# Test Vectors {#vectors}

This appendix provides detailed test vectors to ease implementation and ensure interoperability. In addition to hexadecimal, all CBOR data items and sequences are given in CBOR diagnostic notation. The test vectors use 1 byte key identifiers, 1 byte connection IDs, and the default mapping to CoAP where the Initiator acts as CoAP client (this means that corr = 1). 

## Test Vectors for EDHOC Authenticated with Signature Keys (RPK)

EDHOC with signature authentication is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (Signature Authentication)
0
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on the Initiator and the Responder, see {{cipher-suites}}.

### Input for the Initiator {#rpk-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's private authentication key (32 bytes)
53 21 fc 01 c2 98 20 06 3a 72 50 8f c6 39 25 1d c8 30 e2 f7 68 3e b8 e3
8a f1 64 a5 b9 af 9b e3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's public authentication key (32 bytes)
42 4c 75 6a b7 7c c6 fd ec f0 b3 ec fc ff b7 53 10 c0 15 bf 5c ba 2e c0
a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Initiator's public authentication key (1 byte)
a2 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I =
<< {
  1:  1,
 -1:  6,
 -2:  h'424c756ab77cc6fdecf0b3ecfcffb75310c015bf5cba2ec0a236e6650c8ab9c7
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 06 21 58 20 42 4c 75 6a b7 7c c6 fd ec f0 b3 ec fc ff
b7 53 10 c0 15 bf 5c ba 2e c0 a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a2':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{ 
  4:  h'a2'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_I contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only the kid_I is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a2 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_I (in plaintext) (CBOR-encoded) (2 bytes)
41 a2 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#rpk-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
the Responder's private authentication key (32 bytes)
74 56 b3 a3 e5 8d 8d 26 dd 36 bc 75 d5 5b 88 63 a8 5d 34 72 f4 a0 1f 02
24 62 1b 1c b8 16 6d a9 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
the Responder's public authentication key (32 bytes)
1b 66 1e e5 d5 ef 16 72 a2 d8 77 cd 5b c2 0f 46 30 dc 78 a1 14 de 65 9c
7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify V's public authentication key (1 byte)
a3 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R =
<< {
  1:  1,
 -1:  6,
 -2:  h'1b661ee5d5ef1672a2d877cd5bc20f4630dc78a114de659c7e504d0f529a6bd3
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 06 21 58 20 1b 66 1e e5 d5 ef 16 72 a2 d8 77 cd 5b c2
0f 46 30 dc 78 a1 14 de 65 9c 7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a3':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{ 
  4:  h'a3'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_R contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only the kid_R is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_R (in plaintext) (CBOR-encoded) (2 bytes)
41 a3 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-rpk-1}

From the input parameters (in {{rpk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
1
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (32 bytes)
d4 d8 1a ba fa d9 08 a0 cc ef ef 5a d6 b0 5d 50 27 02 f1 c1 6f 23 2c 25
92 93 09 ac 44 1b 95 8e 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb 71 91 2d 6d
b8 f4 af 98 0d 2d b8 3a 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (1 byte)
c3 
~~~~~~~~~~~~~~~~~~~~~~~

No AD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  1,
  0,
  h'b1a3e89460e88d3a8d54211dc95f0b903ff205eb71912d6db8f4af980d2db83a',
  h'c3'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
01 00 58 20 b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb
71 91 2d 6d b8 f4 af 98 0d 2d b8 3a 41 c3 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-rpk-2}

Since TYPE mod 4 equals 1, C_I is omitted from data_2.


~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
17 cd c7 bc a3 f2 a0 bd a6 0c 6d e5 b9 6f 82 a3 62 39 b4 4b de 39 7a 38
62 d5 29 ba 8b 3d 7c 62 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db 8c 32
0e 5d 49 f3 02 a9 64 74 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.


~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'8db577f9b9c2744798987db557bf31ca48acd205a9db8c320e5d49f302a96474',
  h'c4'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db
8c 32 0e 5d 49 f3 02 a9 64 74 41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-rpk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.


~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (74 bytes)
01 00 58 20 b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb
71 91 2d 6d b8 f4 af 98 0d 2d b8 3a 41 c3 58 20 8d b5 77 f9 b9 c2 74 47
98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db 8c 32 0e 5d 49 f3 02 a9 64 74
41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da
68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b
11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

#### Signature Computation {#tv-rpk-2-sign}

COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-v}}:

* protected = bstr .cbor ID_CRED_R 

* payload = CRED_R

And from {{tv-rpk-2}}:

* external_aad = TH_2

The Sig_structure M_R to be signed is: \[ "Signature1", << ID_CRED_R >>, TH_2, CRED_R \] , as defined in {{asym-msg2-proc}}:


~~~~~~~~~~~~~~~~~~~~~~~
M_R =
[
  "Signature1",
  << { 4: h'a3' } >>,
  h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2afdd870355',
  << {
    1:  1,
   -1:  6,
   -2:  h'1b661ee5d5ef1672a2d877cd5bc20f4630dc78a114de659c7e504d0f529a6b
            d3'
  } >>
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string ToBeSigned:

~~~~~~~~~~~~~~~~~~~~~~~
M_R (message to be signed with Ed25519) (CBOR-encoded) (93 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 44 a1 04 41 a3 58 20 55 50 b3 dc 59
84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd
87 03 55 58 28 a3 01 01 20 06 21 58 20 1b 66 1e e5 d5 ef 16 72 a2 d8 77
cd 5b c2 0f 46 30 dc 78 a1 14 de 65 9c 7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~

The message is signed using the private authentication key of V, and produces the following signature:

~~~~~~~~~~~~~~~~~~~~~~~
V's signature (64 bytes)
52 3d 99 6d fd 9e 2f 77 c7 68 71 8a 30 c3 48 77 8c 5e b8 64 dd 53 7e 55
5e 4a 00 05 e2 09 53 07 13 ca 14 62 0d e8 18 7e 81 99 6e e8 04 d1 53 b8
a1 f6 08 49 6f dc d9 3d 30 fc 1c 8b 45 be cc 06 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-rpk-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
c6 1e 09 09 a1 9d 64 24 01 63 ec 26 2e 9c c4 f8 8c e7 7b e1 23 c5 ab 53
8d 26 b0 69 22 a5 20 67 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
ba 9c 2c a1 c5 62 14 a6 e0 f6 13 ed a8 91 86 8a 4c a3 e3 fa bc c7 79 8f
dc 01 60 80 07 59 16 71 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2af
                dd870355']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 55 50 b3 dc 59 84 b0 20
9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd 87 03 55

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
da d7 44 af 07 c4 da 27 d1 f0 a3 8a 0c 4b 87 38 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2af
                dd870355']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e
30 33 2b 11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
fb a1 65 d9 08 da a7 8e 4f 84 41 42 d0 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-rpk-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* plaintext = CBOR Sequence of the items kid_R, signature, in this order.

with kid_R taken from {{rpk-tv-input-v}}, and signature as calculated in {{tv-rpk-2-sign}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2  (68 bytes)
41 a3 58 40 52 3d 99 6d fd 9e 2f 77 c7 68 71 8a 30 c3 48 77 8c 5e b8 64
dd 53 7e 55 5e 4a 00 05 e2 09 53 07 13 ca 14 62 0d e8 18 7e 81 99 6e e8
04 d1 53 b8 a1 f6 08 49 6f dc d9 3d 30 fc 1c 8b 45 be cc 06 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2afdd870355'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e
a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-rpk-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (76 bytes)
1e 6b fe 0e 77 99 ce f0 66 a3 4f 08 ef aa 90 00 6d b4 4c 90 1c f7 9b 23
85 3a b9 7f d8 db c8 53 39 d5 ed 80 87 78 3c f7 a4 a7 e0 ea 38 c2 21 78
9f a3 71 be 64 e9 3c 43 a7 db 47 d1 e3 fb 14 78 8e 96 7f dd 78 d8 80 78
e4 9b 78 bf 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-rpk-2}} and {{tv-rpk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).


~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'8db577f9b9c2744798987db557bf31ca48acd205a9db8c320e5d49f302a96474',
  h'c4',
  h'1e6bfe0e7799cef066a34f08efaa90006db44c901cf79b23853ab97fd8dbc85339d5
    ed8087783cf7a4a7e0ea38c221789fa371be64e93c43a7db47d1e3fb14788e967fdd
    78d88078e49b78bf'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (114 bytes)
58 20 8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db
8c 32 0e 5d 49 f3 02 a9 64 74 41 c4 58 4c 1e 6b fe 0e 77 99 ce f0 66 a3
4f 08 ef aa 90 00 6d b4 4c 90 1c f7 9b 23 85 3a b9 7f d8 db c8 53 39 d5
ed 80 87 78 3c f7 a4 a7 e0 ea 38 c2 21 78 9f a3 71 be 64 e9 3c 43 a7 db
47 d1 e3 fb 14 78 8e 96 7f dd 78 d8 80 78 e4 9b 78 bf 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-rpk-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.


~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c4'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (114 bytes)
58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b
11 da 68 1d c2 af dd 87 03 55 58 4c 1e 6b fe 0e 77 99 ce f0 66 a3 4f 08
ef aa 90 00 6d b4 4c 90 1c f7 9b 23 85 3a b9 7f d8 db c8 53 39 d5 ed 80
87 78 3c f7 a4 a7 e0 ea 38 c2 21 78 9f a3 71 be 64 e9 3c 43 a7 db 47 d1
e3 fb 14 78 8e 96 7f dd 78 d8 80 78 e4 9b 78 bf 41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79
07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37
4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

#### Signature Computation {#tv-rpk-3-sign}

COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-u}}:

* protected = bstr .cbor ID_CRED_I 

* payload = CRED_I

And from {{tv-rpk-3}}:

* external_aad = TH_3

The Sig_structure M_I to be signed is: \[ "Signature1", << ID_CRED_I >>, TH_3, CRED_I \] , as defined in {{asym-msg3-proc}}:


~~~~~~~~~~~~~~~~~~~~~~~
M_I =
[
  "Signature1",
  << { 4: h'a2' } >>,
  h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e7854367fc22',
  << {
    1:  1,
   -1:  6,
   -2:  h'424c756ab77cc6fdecf0b3ecfcffb75310c015bf5cba2ec0a236e6650c8ab9
            c7'
  } >>
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string ToBeSigned:

~~~~~~~~~~~~~~~~~~~~~~~
M_I (message to be signed with Ed25519) (CBOR-encoded) (93 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 44 a1 04 41 a2 58 20 21 cc b6 78 b7
91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43
67 fc 22 58 28 a3 01 01 20 06 21 58 20 42 4c 75 6a b7 7c c6 fd ec f0 b3
ec fc ff b7 53 10 c0 15 bf 5c ba 2e c0 a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~

The message is signed using the private authentication key of U, and produces the following signature:

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's signature (64 bytes)
5c 7d 7d 64 c9 61 c5 f5 2d cf 33 91 25 92 a1 af f0 2c 33 62 b0 e7 55 0e
4b c5 66 b7 0c 20 61 f3 c5 f6 49 e5 ed 32 3d 30 a2 6c 61 2f bb 5c bd 25
f3 1c 27 22 8c ea ec 64 29 31 95 41 fe 07 8e 0e 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-rpk-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0 ).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.


~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
c6 1e 09 09 a1 9d 64 24 01 63 ec 26 2e 9c c4 f8 8c e7 7b e1 23 c5 ab 53
8d 26 b0 69 22 a5 20 67 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
ba 9c 2c a1 c5 62 14 a6 e0 f6 13 ed a8 91 86 8a 4c a3 e3 fa bc c7 79 8f
dc 01 60 80 07 59 16 71 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e785
                4367fc22']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 21 cc b6 78 b7 91 14 96
09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes. 

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
e1 ac d4 76 f5 96 a4 60 72 44 a8 da 8c ff 49 df 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e785
                4367fc22']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2
7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
de 53 02 13 ab a2 6a 47 1a 51 f3 d6 fb 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-rpk-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* plaintext = CBOR Sequence of the items kid_I, signature, in this order.

with kid_I taken from {{rpk-tv-input-u}}, and signature as calculated in {{tv-rpk-3-sign}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_3  (68 bytes)
41 a2 58 40 5c 7d 7d 64 c9 61 c5 f5 2d cf 33 91 25 92 a1 af f0 2c 33 62
b0 e7 55 0e 4b c5 66 b7 0c 20 61 f3 c5 f6 49 e5 ed 32 3d 30 a2 6c 61 2f
bb 5c bd 25 f3 1c 27 22 8c ea ec 64 29 31 95 41 fe 07 8e 0e 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e7854367fc22'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 21 cc b6 78 b7 91 14 96 09 55 88
5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-rpk-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (76 bytes)
de 4a 83 3d 48 b6 64 74 14 2c c9 bd ce 87 d9 3a f8 35 57 9c 2d bf 1b 9e
2f b4 dc 66 60 0d ba c6 bb 3c c0 5c 29 0e f3 5d 51 5b 4d 7d 64 83 f5 09
61 43 b5 56 44 cf af d1 ff aa 7f 2b a3 86 36 57 83 1d d2 e5 bd 04 04 38
60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-rpk-3}} and {{tv-rpk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).


~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c4',
  h'de4a833d48b66474142cc9bdce87d93af835579c2dbf1b9e2fb4dc66600dbac6bb3c
    c05c290ef35d515b4d7d6483f5096143b55644cfafd1ffaa7f2ba3863657831dd2e5
    bd04043860140dc8'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (80 bytes)
41 c4 58 4c de 4a 83 3d 48 b6 64 74 14 2c c9 bd ce 87 d9 3a f8 35 57 9c
2d bf 1b 9e 2f b4 dc 66 60 0d ba c6 bb 3c c0 5c 29 0e f3 5d 51 5b 4d 7d
64 83 f5 09 61 43 b5 56 44 cf af d1 ff aa 7f 2b a3 86 36 57 83 1d d2 e5
bd 04 04 38 60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

#### OSCORE Security Context Derivation

From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}.

First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3

~~~~~~~~~~~~~~~~~~~~~~~
( TH_3, CIPHERTEXT_3 ) (CBOR Sequence) (112 bytes)
58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37
4a 79 07 f3 e7 85 43 67 fc 22 58 4c de 4a 83 3d 48 b6 64 74 14 2c c9 bd
ce 87 d9 3a f8 35 57 9c 2d bf 1b 9e 2f b4 dc 66 60 0d ba c6 bb 3c c0 5c
29 0e f3 5d 51 5b 4d 7d 64 83 f5 09 61 43 b5 56 44 cf af d1 ff aa 7f 2b
a3 86 36 57 83 1d d2 e5 bd 04 04 38 60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 value (32 bytes)
51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd 67 3a b4 d3 8c 34 81 96 09 ee
0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (CBOR-encoded) (34 bytes)
58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd 67 3a b4 d3 8c 34 81 96
09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L.

For Master Secret:

L for Master Secret = 16

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Secret =
[
  "OSCORE Master Secret",
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'51ed3932bcbae8901c1d4deb94bd673ab4d38c34819609ee0d5c9da6
                e9807fe5']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Secret) (CBOR-encoded) (68 bytes)
84 74 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 65 63 72 65 74 83 f6
f6 f6 83 f6 f6 f6 83 18 80 40 58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb
94 bd 67 3a b4 d3 8c 34 81 96 09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Secret value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
09 02 9d b0 0c 3e 01 27 42 c3 a8 69 04 07 4c 0e 
~~~~~~~~~~~~~~~~~~~~~~~

For Master Salt:

L for Master Salt = 8

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Salt =
[
  "OSCORE Master Salt",
  [ null, null, null ],
  [ null, null, null ],
  [ 64, h'', h'51ed3932bcbae8901c1d4deb94bd673ab4d38c34819609ee0d5c9da6
                e9807fe5']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Salt) (CBOR-encoded) (66 bytes)
84 72 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 61 6c 74 83 f6 f6 f6
83 f6 f6 f6 83 18 40 40 58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd
67 3a b4 d3 8c 34 81 96 09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Salt value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
81 02 97 22 a2 30 4a 06 
~~~~~~~~~~~~~~~~~~~~~~~

The Client's Sender ID takes the value of C_R:

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

The Server's Sender ID takes the value of C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (1 byte)
c3 
~~~~~~~~~~~~~~~~~~~~~~~

The algorithms are those negociated in the cipher suite:

~~~~~~~~~~~~~~~~~~~~~~~
AEAD Algorithm
10
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
HMAC Algorithm
5
~~~~~~~~~~~~~~~~~~~~~~~

## Test Vectors for EDHOC Authenticated with Symmetric Keys (PSK)

Symmetric EDHOC is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (Symmetric Authentication)
1
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on the Initiator and the Responder, see {{cipher-suites}}.

### Input for the Initiator {#psk-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (32 bytes)
f4 0c ea f8 6e 57 76 92 33 32 b8 d8 fd 3b ef 84 9c ad b1 9c 69 96 bc 27
2a f1 f6 48 d9 56 6a 4c 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral public key (value of G_X) (32 bytes)
ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43 0f 58 88 97
cb 57 49 61 cf a9 80 6f 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by the Initiator (value of C_I) (1 byte)
c1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Pre-shared Key (PSK) (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify PSK (1 byte)
a1 
~~~~~~~~~~~~~~~~~~~~~~~

So ID_PSK is defined as the following:

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK =
{
  4:h'a1'
}
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the pre-shared key.

Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid is used when added to the plaintext (see {{sym-overview}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid (in plaintext) (CBOR-encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#psk-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
d9 81 80 87 de 72 44 ab c1 b5 fc f2 8e 55 e4 2c 7f f9 c6 78 c0 60 51 81
f3 7a c5 d7 41 4a 7b 95 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral public key (value of G_Y) (32 bytes)
fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d
94 6f 6b 09 a9 cb dc 06 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by the Responder (value of C_R) (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Pre-shared Key (PSK) (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify PSK (1 byte)
a1 
~~~~~~~~~~~~~~~~~~~~~~~

So ID_PSK is defined as the following:

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK =
{
  4:h'a1'
}
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the pre-shared key.

Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid is used when added to the plaintext (see {{sym-overview}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid (in plaintext) (CBOR-encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-psk-1}

From the input parameters (in {{psk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
5
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43 0f 58 88 97
cb 57 49 61 cf a9 80 6f 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (CBOR encoded) (2 bytes)
41 c1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid of ID_PSK (CBOR encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

No UAD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  5,
  0,
  h'ab2fca32898322c208fb2dab5048bd43c355c6430f588897cb574961cfa9806f',
  h'c1',
  h'a1'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (40 bytes)
05 00 58 20 ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43
0f 58 88 97 cb 57 49 61 cf a9 80 6f 41 c1 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-psk-2}

Since TYPE mod 4 equals 1, C_I is omitted from data_2.

~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d
94 6f 6b 09 a9 cb dc 06 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'fc3b339367a5225d53a92d380323afd035d7817b6d1be47d946f6b09a9cbdc06',
  h'c2'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b
e4 7d 94 6f 6b 09 a9 cb dc 06 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-psk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (76 bytes)
05 00 58 20 ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43
0f 58 88 97 cb 57 49 61 cf a9 80 6f 41 c1 41 a1 58 20 fc 3b 33 93 67 a5
22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d 94 6f 6b 09 a9 cb
dc 06 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34
1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35
8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-psk-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the symmetric case, salt is the PSK:

~~~~~~~~~~~~~~~~~~~~~~~
salt (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
d5 75 05 50 6d 8f 30 a8 60 a0 63 d0 1b 5b 7a d7 6a 09 4f 70 61 3b 4a e6
6c 5a 90 e5 c2 1f 23 11 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
aa b2 f1 3c cb 1a 4f f7 96 a9 7a 32 a4 d2 fb 62 47 ef 0b 6b 06 da 04 d3
d1 06 39 4b 28 76 e2 8c 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07
                dee170ca']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 16 4f 44 d8 56 dd 15 22
2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34 1c db 7b 07 de e1 70 ca

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
ac 42 6e 5e 7d 7a d6 ae 3b 19 aa bd e0 f6 25 57 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).
info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07
                dee170ca']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b
40 f7 35 8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
ff 11 2e 1c 26 8a a2 a7 7c c3 ee 6c 4d 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-psk-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* empty plaintext, since AD_2 is omitted

* empty plaintext, since AD_2 is omitted

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07dee170ca'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 16 4f 44 d8 56 dd 15 22 2f a4 63
f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-psk-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (8 bytes)
ba 38 b9 a3 fc 1a 58 e9 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-psk-2}} and {{tv-psk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).

~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'fc3b339367a5225d53a92d380323afd035d7817b6d1be47d946f6b09a9cbdc06',
  h'c2',
  h'ba38b9a3fc1a58e9'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (45 bytes)
58 20 fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b
e4 7d 94 6f 6b 09 a9 cb dc 06 41 c2 48 ba 38 b9 a3 fc 1a 58 e9 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-psk-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.

~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c2'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-psk-2-ciph}}), and TH_2 ({{tv-psk-2}}), compute the input to the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (45 bytes)
58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35
8d 34 1c db 7b 07 de e1 70 ca 48 ba 38 b9 a3 fc 1a 58 e9 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54
81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52
89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-psk-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the symmetric case, salt is the PSK:

~~~~~~~~~~~~~~~~~~~~~~~
salt (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
d5 75 05 50 6d 8f 30 a8 60 a0 63 d0 1b 5b 7a d7 6a 09 4f 70 61 3b 4a e6
6c 5a 90 e5 c2 1f 23 11 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
aa b2 f1 3c cb 1a 4f f7 96 a9 7a 32 a4 d2 fb 62 47 ef 0b 6b 06 da 04 d3
d1 06 39 4b 28 76 e2 8c 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8a
                f566d7fe']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 11 98 aa b3 ed db 61 b8
a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes.

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
fe 75 e3 44 27 f8 3a ad 84 16 83 c6 6f a3 8a 62 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8a
                f566d7fe']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76
bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3, so 13 bytes.

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
60 0a 33 b4 16 de 08 23 52 67 71 ec 8a 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-psk-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* empty plaintext, since AD_3 is omitted

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8af566d7fe'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 11 98 aa b3 ed db 61 b8 a1 b1 93
a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-psk-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (8 bytes)
51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-psk-3}} and {{tv-psk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).

~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c2',
  h'5129079261454004'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (11 bytes)
41 c2 48 51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

#### OSCORE Security Context Derivation

From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}.

First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3

~~~~~~~~~~~~~~~~~~~~~~~
( TH_3, CIPHERTEXT_3 ) (CBOR Sequence) (43 bytes)
58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52
89 54 81 b5 2b 8a f5 66 d7 fe 48 51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 value (32 bytes)
df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5 be b7 57 41 3f a7 b6 a9 cf 28
3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (CBOR-encoded) (34 bytes)
58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5 be b7 57 41 3f a7 b6 a9
cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L.

For Master Secret:

L for Master Secret = 16

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Secret =
[
  "OSCORE Master Secret",
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'df7c9b06f5dc0ee8860b396c78c5beb757413fa7b6a9cf283ddb4cd4
                c1fde43c']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Secret) (CBOR-encoded) (68 bytes)
84 74 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 65 63 72 65 74 83 f6
f6 f6 83 f6 f6 f6 83 18 80 40 58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c
78 c5 be b7 57 41 3f a7 b6 a9 cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Secret value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
8d 36 8f 09 26 2d c5 52 7f e7 19 e6 6c 91 63 75 
~~~~~~~~~~~~~~~~~~~~~~~

For Master Salt:

L for Master Salt = 8

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Salt =
[
  "OSCORE Master Salt",
  [ null, null, null ],
  [ null, null, null ],
  [ 64, h'', h'df7c9b06f5dc0ee8860b396c78c5beb757413fa7b6a9cf283ddb4cd4
                c1fde43c']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Salt) (CBOR-encoded) (66 bytes)
84 72 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 61 6c 74 83 f6 f6 f6
83 f6 f6 f6 83 18 40 40 58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5
be b7 57 41 3f a7 b6 a9 cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Salt value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
4d b7 06 58 c5 e9 9f b6 
~~~~~~~~~~~~~~~~~~~~~~~

The Client's Sender ID takes the value of C_R:

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

The Server's Sender ID takes the value of C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (1 byte)
c1 
~~~~~~~~~~~~~~~~~~~~~~~

The algorithms are those negociated in the cipher suite:

~~~~~~~~~~~~~~~~~~~~~~~
AEAD Algorithm
10
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
HMAC Algorithm
5
~~~~~~~~~~~~~~~~~~~~~~~


## Test Vectors for EDHOC Authenticated with Static Diffie-Hellman Keys

EDHOC with static Diffie-Hellman keys and MAC authentication is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (MAC Authentication)
3
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on Initiator and Responder, see {{cipher-suites}}.

### Input for the Initiator {#ss-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's private static DH authentication key (I) (32 bytes)
be 55 8a 0e 56 34 23 ff 74 f6 d7 7a 36 8c 35 9d 4c 21 be d2 ef 1d 09 41
0d 71 6c 0a e2 64 9c 19 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's public static DH authentication key (G_I) (32 bytes)
6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc
c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Initiator's public DH authentication key (kid_I) (1 byte)
a7 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I =
<< {
  1:  1,
 -1:  4,
 -2:  h'6e5d6876a178156ca0b81dc80f81060fa1a5d13513d614bcc28537ef98900644
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81
06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a7':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{ 
  4:  h'a7'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_I contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only kid_I is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (in protected header) (CBOR-encoded) (5 bytes)
44 a1 04 41 a7 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_I (in plaintext) (CBOR-encoded) (2 bytes)
41 a7 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#ss-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Responder's private static DH authentication key (R) (32 bytes)
25 d8 0d 45 a1 1b 37 2d 5a 23 57 f9 96 ed 04 8e 26 14 ab 8a 40 66 2b 89
91 2a 83 77 9d 58 2c 85 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Responder's private static DH authentication key (G_R) (32 bytes)
32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af
89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Responder's public authentication key (kid_R) (1 byte)
a8 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R =
<< {
  1:  1,
 -1:  4,
 -2:  h'328244f6cdf5f1272250d7cfbba26834fbef25e846db8baf890faa8d7ef6e673
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2
68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a8':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{ 
  4:  h'a8'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_R contains a single 'kid' parameter, ID_CRED_R is used when transported in the protected header of the COSE Object, but only the kid_R is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (in protected header) (CBOR-encoded) (5 bytes)
44 a1 04 41 a8 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_R (in plaintext) (CBOR-encoded) (2 bytes)
41 a8 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-ss-1}

From the input parameters (in {{rpk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
13
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (I) (32 bytes)
11 34 9f 62 e8 d8 13 ed 79 d2 7d 57 dd 41 b9 af ec 4d d9 5e c4 d2 88 0e
72 0d 50 e6 37 fe c9 19 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb c7 79 cb 36
74 a9 42 91 fd 9b 1a 08 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (1 byte)
c7 
~~~~~~~~~~~~~~~~~~~~~~~

No AD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  13,
  0,
  h'6522d22d5087466ea1229bfbeeb8529e56e1d9cbc779cb3674a94291fd9b1a08',
  h'c7'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
0d 00 58 20 65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb
c7 79 cb 36 74 a9 42 91 fd 9b 1a 08 41 c7 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-ss-2}

Since corr equals 1, C_I is omitted from data_2.

The Responder generates an ephemeral ECDH key pair:

~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
25 08 17 7e 3f 55 3e c0 5f 24 26 f5 0f 21 0c 7a bf 54 2e 53 23 b8 45 9e
17 52 33 be 6e 67 bb 91 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da 89 a6
78 07 7f 8b 79 6a 3f 65 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder also choses a connection identifier:

~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c8 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.


~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'4acd374173cc6f2b55c759ef6e782ca307e79821f4da89a678077f8b796a3f65',
  h'c8'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da
89 a6 78 07 7f 8b 79 6a 3f 65 41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-ss-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.


~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (74 bytes)
0d 00 58 20 65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb
c7 79 cb 36 74 a9 42 91 fd 9b 1a 08 41 c7 58 20 4a cd 37 41 73 cc 6f 2b
55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da 89 a6 78 07 7f 8b 79 6a 3f 65
41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23
18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

#### MAC Computation {#tv-ss-2-mac}

Since method equals 3, a COSE_Encrypt0 is calculated.

##### Key and Nonce Computation {#tv-ss-2-key-mac}

The key and nonce for calculating the MAC are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2 = HMAC-SHA-256 (salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the ECDH shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
12 2d f9 44 2b 2e 81 3c 3a 00 29 04 af 63 99 e0 f3 1c d5 96 7d 49 2a e6
02 0b c2 d7 7c cb 4f 28 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_2 (32 bytes)
f1 8c ca 1d af 06 1a f1 40 94 19 26 19 a4 dd 5e 9e 41 94 fc 42 fe 5e 20
d0 27 9d 8d d3 1f ad 8f 
~~~~~~~~~~~~~~~~~~~~~~~

PRK_R = HKDF-Extract (PRK_2, G_RX)

G_RX is the ECDH shared secret calculated from G_X received in {{tv-ss-1}} and R in {{ss-tv-input-v}}, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_RX (32 bytes)
5f 40 10 ca 84 52 1e 2d e8 71 7c f4 d9 66 ab 33 96 86 6c 4c 74 f3 85 96
dd 8f 23 b6 c4 83 99 2e 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_R (32 bytes)
08 4a 87 01 49 07 ed 85 12 90 42 55 e1 8a df a8 39 53 92 28 29 48 8f f4
66 44 87 1e 07 1d 42 80 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_R is the output of HKDF-Expand(PRK_R, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_R =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_R) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4f 92 2e 15 50 2c ec fb
04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_R, so 16 bytes.

From these parameters, K_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_R (16 bytes)
54 3b aa 32 53 c2 6e df e8 a7 00 93 62 98 94 ea 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_R is the output of HKDF-Expand(PRK_R, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_R =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_R) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b
24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_R, so 13 bytes.

From these parameters, IV_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_R (13 bytes)
1d 41 f4 41 cf e6 2f 07 19 84 17 41 14 
~~~~~~~~~~~~~~~~~~~~~~~

##### MAC Computation {#tv-ss-2-mac-comp}

COSE_Encrypt0 is computed with the following parameters.

* protected header = CBOR-encoded ID_CRED_R

* external_aad = CBOR Sequence of TH_2 and CRED_R, in this order

* empty plaintext


~~~~~~~~~~~~~~~~~~~~~~~
Protected header: ID_CRED_R (CBOR-encoded) (5 bytes)
44 a1 04 41 a8 
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the following:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_2 , CRED_R ) (CBOR Sequence) (72 bytes)
4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23
18 e0 ed 18 26 cb 21 c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27
22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73

~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_2 , CRED_R ) (CBOR Sequence) (CBOR-encoded) (74 bytes)
58 48 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5
f1 27 22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6
e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_R =
[
  "Encrypt0",
  h'a10441a8',
  h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed1826cb21c3a301
    012004215820328244f6cdf5f1272250d7cfbba26834fbef25e846db8baf890faa8d
    7ef6e673'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_R (CBOR-encoded) (89 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 a8 58 48 4f 92 2e 15 50 2c ec
fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21
c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2 68
34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-2-key}}:

* key = K_R

* nonce = IV_R

Using the parameters above, the ciphertext CIPHERTEXT_R can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_R (9 bytes)
00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-ss-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2  = HMAC-SHA-256(salt, G_XY) as defined in {{tv-ss-2-key-mac}}


~~~~~~~~~~~~~~~~~~~~~~~
PRK_2 (32 bytes)
f1 8c ca 1d af 06 1a f1 40 94 19 26 19 a4 dd 5e 9e 41 94 fc 42 fe 5e 20
d0 27 9d 8d d3 1f ad 8f 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK_2, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4f 92 2e 15 50 2c ec fb
04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
73 e3 58 ef b5 7b 8f fa 15 c0 a2 ee 3e ed ed e1 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b
24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
2c 41 5f 98 b2 9a 9c f7 0f 87 8c d0 d3 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-ss-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* plaintext = CBOR Sequence of the items kid_R, CIPHERTEXT_R, in this order.

with kid_R taken from {{ss-tv-input-v}}, and CIPHERTEXT_R as calculated in {{tv-ss-2-mac-comp}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2  (12 bytes)
41 a8 49 00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed1826cb21c3'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af
d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (20 bytes)
21 31 6c 24 04 22 65 0f 93 98 75 17 97 be 3e c2 98 d1 3e bd 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-ss-2}} and {{tv-ss-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).


~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'4acd374173cc6f2b55c759ef6e782ca307e79821f4da89a678077f8b796a3f65',
  h'c8',
  h'21316c240422650f9398751797be3ec298d13ebd'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (57 bytes)
58 20 4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da
89 a6 78 07 7f 8b 79 6a 3f 65 41 c8 54 21 31 6c 24 04 22 65 0f 93 98 75
17 97 be 3e c2 98 d1 3e bd 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-ss-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.


~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c8 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c8'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (57 bytes)
58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 54 21 31 6c 24 04 22 65 0f 93 98 75 17 97
be 3e c2 98 d1 3e bd 41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74
c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15
1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

#### MAC Computation {#tv-ss-3-mac}

Since method equals 3, a COSE_Encrypt0 is calculated.

##### Key and Nonce Computation {#tv-ss-3-key-mac}

The key and nonce for calculating the MAC are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_I = HMAC-SHA-256 (PRK_3, G_IY)

with PRK_3 = PRK_R.

G_IY is the ECDH shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_IY (32 bytes)
9f 70 4c 69 61 ae 11 4e 0f 06 53 e3 fa 72 0d 98 9d e4 79 63 b5 6f a3 a3
c3 c6 5f 0a 5b 6b 7f 20 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_I (32 bytes)
f1 df af 80 cb 4b b6 a8 1c 83 ad 2e d7 bb ed d5 ac bc 7b b2 b2 a8 a5 ea
8d fb 24 b9 45 1f fe 20 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_I is the output of HKDF-Expand(PRK_I, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_I =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_I) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4d 2d 24 a8 fc 09 04 02
8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_I, so 16 bytes.

From these parameters, K_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_I (16 bytes)
78 00 55 60 2a 5a d1 72 eb a4 76 f7 e3 ff 48 c8 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_I is the output of HKDF-Expand(PRK_I, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_I =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_I) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa
57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_I, so 13 bytes.

From these parameters, IV_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_I (13 bytes)
e1 1e bc 09 e7 cf 76 10 84 d8 00 56 1e 
~~~~~~~~~~~~~~~~~~~~~~~

##### MAC Computation {#tv-ss-3-mac-comp}

COSE_Encrypt0 is computed with the following parameters.

* protected header = CBOR-encoded ID_CRED_I

* external_aad = CBOR Sequence of TH_3 and CRED_I, in this order

* empty plaintext


~~~~~~~~~~~~~~~~~~~~~~~
Protected header: ID_CRED_I (CBOR-encoded) (5 bytes)
44 a1 04 41 a7 
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the following:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_3 , CRED_I ) (CBOR Sequence) (72 bytes)
4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74
c0 c4 bf 6c ce dd b0 3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c
a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44

~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_3 , CRED_I ) (CBOR Sequence) (CBOR-encoded) (74 bytes)
58 48 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15
1c 74 c0 c4 bf 6c ce dd b0 3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78
15 6c a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90
06 44 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_I is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_I =
[
  "Encrypt0",
  h'a10441a7',
  h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6cceddb03ea301
    0120042158206e5d6876a178156ca0b81dc80f81060fa1a5d13513d614bcc28537ef
    98900644'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_I (CBOR-encoded) (89 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 a7 58 48 4d 2d 24 a8 fc 09 04
02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0
3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81 06
0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-3-key}}:

* key = K_I

* nonce = IV_I

Using the parameters above, the ciphertext CIPHERTEXT_I can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_I (9 bytes)
00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-ss-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_3 = PRK_R = HMAC-SHA-256(PRK_2, G_RX) as defined in {{tv-ss-2-mac}}


~~~~~~~~~~~~~~~~~~~~~~~
PRK_3 (32 bytes)
08 4a 87 01 49 07 ed 85 12 90 42 55 e1 8a df a8 39 53 92 28 29 48 8f f4
66 44 87 1e 07 1d 42 80 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK_3, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4d 2d 24 a8 fc 09 04 02
8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes.

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
70 77 e4 d6 23 66 84 52 88 b7 00 ae 03 f8 a7 aa 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa
57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3, so 13 bytes.

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
e2 40 36 1e 0b 74 45 c6 d3 64 40 82 0d 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-ss-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* plaintext = CBOR Sequence of the items kid_R, CIPHERTEXT_R, in this order.

with kid_R taken from {{ss-tv-input-v}}, and CIPHERTEXT_R as calculated in {{tv-ss-2-mac-comp}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_3  (12 bytes)
41 a7 49 00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6cceddb03e'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40
62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (20 bytes)
d2 85 38 ee f7 ae 1b 9d 7d 89 57 18 48 a9 08 86 e0 69 43 2b 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-ss-3}} and {{tv-ss-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_I, CIPHERTEXT_3).


~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c7',
  h'd28538eef7ae1b9d7d89571848a90886e069432b'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (23 bytes)
41 c8 54 d2 85 38 ee f7 ae 1b 9d 7d 89 57 18 48 a9 08 86 e0 69 43 2b 
~~~~~~~~~~~~~~~~~~~~~~~

