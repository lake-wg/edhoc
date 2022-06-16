---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-ietf-lake-edhoc-latest
abbrev: EDHOC

ipr: trust200902
area: SEC
workgroup: LAKE Working Group
cat: std
consensus: true

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
- name: Francesca Palombini
  surname: Palombini
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: francesca.palombini@ericsson.com

normative:

  RFC2119:
  RFC3279:
  RFC3552:
  RFC5116:
  RFC5280:
  RFC5869:
  RFC6090:
  RFC6960:
  RFC6979:
  RFC7252:
  RFC7624:
  RFC7748:
  RFC7959:
  RFC8174:
  RFC8376:
  RFC8392:
  RFC8410:
  RFC8610:
  RFC8613:
  RFC8724:
  RFC8742:
  RFC8747:
  RFC8949:
  RFC9175:
  I-D.ietf-cose-x509:
  I-D.ietf-cose-rfc8152bis-algs:
  I-D.ietf-cose-rfc8152bis-struct:

informative:

  RFC2986:
  RFC6194:
  RFC7228:
  RFC7258:
  RFC7296:
  RFC8366:
  RFC8446:
  RFC8937:
  RFC9000:
  RFC9147:
  RFC9176:
  I-D.ietf-lake-reqs:
  I-D.ietf-lake-traces:
  I-D.ietf-core-oscore-edhoc:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-core-oscore-key-update:
  I-D.ietf-lwig-curve-representations:
  I-D.ietf-lwig-security-protocol-comparison:
  I-D.selander-ace-ake-authz:
  I-D.mattsson-cfrg-det-sigs-with-noise:
  I-D.arkko-arch-internet-threat-model-guidance:
  I-D.ietf-rats-eat:

  SP-800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A Revision 3"
    author:
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: A. Roginsky
      -
        ins: A. Vassilev
      -
        ins: R. Davis
    date: April 2018

  Degabriele11:
    target: https://eprint.iacr.org/2011/615
    title: On the Joint Security of Encryption and Signature in EMV
    author:
      -
        ins: J. P. Degabriele
      -
        ins: A. Lehmann
      -
        ins: K. G. Paterson
      -
        ins: N. P. Smart
      -
        ins: M. Strefler
    date: December 2011


  SECG:
    target: https://www.secg.org/sec1-v2.pdf
    title: Standards for Efficient Cryptography 1 (SEC 1)
    date: May 2009

  SIGMA:
    target: https://webee.technion.ac.il/~hugo/sigma-pdf.pdf
    title: SIGMA - The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols (Long version)
    author:
      -
        ins: H. Krawczyk
    date: June 2003

  HKDFpaper:
    target: https://eprint.iacr.org/2010/264.pdf
    title: "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
    author:
      -
        ins: H. Krawczyk
    date: May 2010

  Thormarker21:
    target: https://eprint.iacr.org/2021/509.pdf
    title: "On using the same key pair for Ed25519 and an X25519 based KEM"
    author:
      -
        ins: E. Thormarker
    date: April 2021

  CNSA:
    target: https://apps.nsa.gov/iaarchive/programs/iad-initiatives/cnsa-suite.cfm
    title: Commercial National Security Algorithm Suite
    author:
      -
        ins: (Placeholder)
    date: August 2015

  Norrman20:
    target: https://arxiv.org/abs/2007.11427
    title: Formal Analysis of EDHOC Key Establishment for Constrained IoT Devices
    author:
      -
        ins: K. Norrman
      -
        ins: V. Sundararajan
      -
        ins: A. Bruni
    date: September 2020

  Bruni18:
    target: https://www.springerprofessional.de/en/formal-verification-of-ephemeral-diffie-hellman-over-cose-edhoc/16284348
    title: Formal Verification of Ephemeral Diffie-Hellman Over COSE (EDHOC)
    author:
      -
        ins: A. Bruni
      -
        ins: T. Sahl Jørgensen
      -
        ins: T. Grønbech Petersen
      -
        ins: C. Schürmann
    date: November 2018

  CborMe:
    target: http://cbor.me/
    title: CBOR Playground
    author:
      -
        ins: C. Bormann
    date: May 2018

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a very compact and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys. EDHOC provides mutual authentication, forward secrecy, and identity protection. EDHOC is intended for usage in constrained scenarios and a main use case is to establish an OSCORE security context. By reusing COSE for cryptography, CBOR for encoding, and CoAP for transport, the additional code size can be kept very low.

--- middle

# Introduction

## Motivation

Many Internet of Things (IoT) deployments require technologies which are highly performant in constrained environments {{RFC7228}}. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and power. The connectivity for these settings may also exhibit constraints such as unreliable and lossy channels, highly restricted bandwidth, and dynamic topology. The IETF has acknowledged this problem by standardizing a range of lightweight protocols and enablers designed for the IoT, including the Constrained Application Protocol (CoAP, {{RFC7252}}), Concise Binary Object Representation (CBOR, {{RFC8949}}), and Static Context Header Compression (SCHC, {{RFC8724}}).

The need for special protocols targeting constrained IoT deployments extends also to the security domain {{I-D.ietf-lake-reqs}}. Important characteristics in constrained environments are the number of round trips and protocol message sizes, which if kept low can contribute to good performance by enabling transport over a small number of radio frames, reducing latency due to fragmentation or duty cycles, etc. Another important criteria is code size, which may be prohibitive for certain deployments due to device capabilities or network load during firmware update. Some IoT deployments also need to support a variety of underlying transport technologies, potentially even with a single connection.

Some security solutions for such settings exist already. CBOR Object Signing and Encryption (COSE, {{I-D.ietf-cose-rfc8152bis-struct}}) specifies basic application-layer security services efficiently encoded in CBOR. Another example is Object Security for Constrained RESTful Environments (OSCORE, {{RFC8613}}) which is a lightweight communication security extension to CoAP using CBOR and COSE. In order to establish good quality cryptographic keys for security protocols such as COSE and OSCORE, the two endpoints may run an authenticated Diffie-Hellman key exchange protocol, from which shared secret keying material can be derived. Such a key exchange protocol should also be lightweight; to prevent bad performance in case of repeated use, e.g., due to device rebooting or frequent rekeying for security reasons; or to avoid latencies in a network formation setting with many devices authenticating at the same time.

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a lightweight authenticated key exchange protocol providing good security properties including forward secrecy, identity protection, and cipher suite negotiation. Authentication can be based on raw public keys (RPK) or public key certificates and requires the application to provide input on how to verify that endpoints are trusted. This specification emphasizes the possibility to reference rather than to transport credentials in order to reduce message overhead, but the latter is also supported. EDHOC does not currently support pre-shared key (PSK) authentication as authentication with static Diffie-Hellman public keys by reference produces equally small message sizes but with much simpler key distribution and identity protection.

EDHOC makes use of known protocol constructions, such as SIGMA {{SIGMA}} and Extract-and-Expand {{RFC5869}}. EDHOC uses COSE for cryptography and identification of credentials (including COSE_Key, CBOR Web Token (CWT), CWT Claims Set (CCS), X.509, and CBOR encoded X.509 (C509) certificates, see {{auth-cred}}). COSE provides crypto agility and enables the use of future algorithms and credential types targeting IoT.

EDHOC is designed for highly constrained settings making it especially suitable for low-power wide area networks {{RFC8376}} such as Cellular IoT, 6TiSCH, and LoRaWAN. A main objective for EDHOC is to be a lightweight authenticated key exchange for OSCORE, i.e., to provide authentication and session key establishment for IoT use cases such as those built on CoAP {{RFC7252}} involving 'things' with embedded microcontrollers, sensors, and actuators. By reusing the same lightweight primitives as OSCORE (CBOR, COSE, CoAP) the additional code size can be kept very low. Note that while CBOR and COSE primitives are built into the protocol messages, EDHOC is not bound to a particular transport.

A typical setting is when one of the endpoints is constrained or in a constrained network, and the other endpoint is a node on the Internet (such as a mobile phone). Thing-to-thing interactions over constrained networks are also relevant since both endpoints would then benefit from the lightweight properties of the protocol. EDHOC could, e.g., be run when a device connects for the first time, or to establish fresh keys which are not revealed by a later compromise of the long-term keys.

## Message Size Examples

Compared to the DTLS 1.3 handshake {{RFC9147}} with ECDHE and connection ID, the EDHOC message size when transferred in CoAP can be less than 1/6 when RPK authentication is used, see {{I-D.ietf-lwig-security-protocol-comparison}}. {{fig-sizes}} shows examples of EDHOC message sizes based on the assumptions in Section 2 of {{I-D.ietf-lwig-security-protocol-comparison}}, comparing different kinds of authentication keys and COSE header parameters for identification: static Diffie-Hellman keys or signature keys, either in CBOR Web Token (CWT) / CWT Claims Set (CCS) {{RFC8392}} identified by a key identifier using 'kid' {{I-D.ietf-cose-rfc8152bis-struct}}, or in X.509 certificates identified by a hash value using 'x5t' {{I-D.ietf-cose-x509}}.

~~~~~~~~~~~~~~~~~~~~~~~
========================================================
                    Static DH Keys        Signature Keys
                    --------------        --------------
                    kid        x5t        kid        x5t
--------------------------------------------------------
message_1            37         37         37         37
message_2            45         58        102        115
message_3            19         33         77         90
--------------------------------------------------------
Total               101        128        216        242
========================================================
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-sizes title="Examples of EDHOC message sizes in bytes." artwork-align="center"}

## Document Structure

The remainder of the document is organized as follows: {{background}} outlines EDHOC authenticated with signature keys, {{overview}} describes the protocol elements of EDHOC, including formatting of the ephemeral public keys, {{key-der}} specifies the key derivation, {{asym}} specifies message processing for EDHOC authenticated with signature keys or static Diffie-Hellman keys, {{error}} describes the error messages, and {{transfer}} shows how to transfer EDHOC with CoAP and establish an OSCORE security context.


## Terminology and Requirements Language {#term}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

Readers are expected to be familiar with the terms and concepts described in CBOR {{RFC8949}}, CBOR Sequences {{RFC8742}}, COSE structures and processing {{I-D.ietf-cose-rfc8152bis-struct}}, COSE algorithms {{I-D.ietf-cose-rfc8152bis-algs}}, CWT and CWT Claims Set {{RFC8392}}, and the Concise Data Definition Language (CDDL, {{RFC8610}}), which is used to express CBOR data structures. Examples of CBOR and CDDL are provided in {{CBOR}}. When referring to CBOR, this specification always refers to Deterministically Encoded CBOR as specified in Sections 4.2.1 and 4.2.2 of {{RFC8949}}. The single output from authenticated encryption (including the authentication tag) is called "ciphertext", following {{RFC5116}}.


# EDHOC Outline {#background}

EDHOC specifies different authentication methods of the ephemeral Diffie-Hellman key exchange: signature keys and static Diffie-Hellman keys. This section outlines the signature key based method. Further details of protocol elements and other authentication methods are provided in the remainder of this document.

SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 {{RFC7296}} and (D)TLS 1.3 {{RFC8446}}{{RFC9147}}, EDHOC authenticated with signature keys is built on a variant of the SIGMA protocol which provides identity protection of the initiator (SIGMA-I) against active attackers, and like IKEv2, EDHOC implements the MAC-then-Sign variant of the SIGMA-I protocol shown in {{fig-sigma}}.

~~~~~~~~~~~
Initiator                                                   Responder
|                                G_X                                |
+------------------------------------------------------------------>|
|                                                                   |
|      G_Y, Enc( ID_CRED_R, Sig( R; MAC( CRED_R, G_X, G_Y ) ) )     |
|<------------------------------------------------------------------+
|                                                                   |
|        AEAD( ID_CRED_I, Sig( I; MAC( CRED_I, G_Y, G_X ) ) )       |
+------------------------------------------------------------------>|
|                                                                   |
~~~~~~~~~~~
{: #fig-sigma title="MAC-then-Sign variant of the SIGMA-I protocol used by EDHOC."}
{: artwork-align="center"}

The parties exchanging messages are called Initiator (I) and Responder (R). They exchange ephemeral public keys, compute a shared secret key PRK_out, and derive symmetric application keys used to protect application data.

* G_X and G_Y are the ECDH ephemeral public keys of I and R, respectively.

* CRED_I and CRED_R are the authentication credentials containing the public authentication keys of I and R, respectively.

* ID_CRED_I and ID_CRED_R are used to identify and optionally transport the credentials of the Initiator and the Responder, respectively.

* Sig(I; . ) and Sig(R; . ) denote signatures made with the private authentication key of I and R, respectively.

* Enc(), AEAD(), and MAC() denotes encryption, authenticated encryption with additional data, and message authentication code using keys derived from the shared secret.

In order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Transcript hashes (hashes of message data) TH_2, TH_3, TH_4 used for key derivation and as additional authenticated data.

* Computationally independent keys derived from the ECDH shared secret and used for authenticated encryption of different messages.

* An optional fourth message giving key confirmation to I in deployments where no protected application data is sent from R to I.

* A keying material exporter and a key update function with forward secrecy.

* Verification of the selected cipher suite.

* Method types and error handling.

* Selection of connection identifiers C_I and C_R which may be used in EDHOC to identify protocol state.

* Transport of external authorization data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR, COSE, and CoAP libraries.

To simplify for implementors, the use of CBOR and COSE in EDHOC is summarized in {{CBORandCOSE}}. Test vectors including CBOR diagnostic notation are provided in {{I-D.ietf-lake-traces}}.

# Protocol Elements {#overview}

## General

The EDHOC protocol consists of three mandatory messages (message_1, message_2, message_3) between Initiator and Responder, an optional fourth message (message_4), and an error message. All EDHOC messages are CBOR Sequences {{RFC8742}}, and are deterministically encoded. {{fig-flow}} illustrates an EDHOC message flow with the optional fourth message as well as the content of each message. The protocol elements in the figure are introduced in {{overview}} and {{asym}}. Message formatting and processing are specified in {{asym}} and {{error}}.

Application data may be protected using the agreed application algorithms (AEAD, hash) in the selected cipher suite (see {{cs}}) and the application can make use of the established connection identifiers C_I and C_R (see {{ci}}). EDHOC may be used with the media type application/edhoc+cbor-seq defined in {{media-type}}.

The Initiator can derive symmetric application keys after creating EDHOC message_3, see {{exporter}}. Protected application data can therefore be sent in parallel or together with EDHOC message_3. EDHOC message_4 is typically not sent.

~~~~~~~~~~~
Initiator                                                   Responder
|                 METHOD, SUITES_I, G_X, C_I, EAD_1                 |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|       G_Y, Enc( ID_CRED_R, Signature_or_MAC_2, EAD_2 ), C_R       |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|            AEAD( ID_CRED_I, Signature_or_MAC_3, EAD_3 )           |
+------------------------------------------------------------------>|
|                             message_3                             |
|                                                                   |
|                           AEAD( EAD_4 )                           |
|<- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                             message_4                             |
~~~~~~~~~~~
{: #fig-flow title="EDHOC message flow including the optional fourth message."}
{: artwork-align="center"}


## Method {#method}

The data item METHOD in message_1 (see {{asym-msg1-form}}), is an integer specifying the authentication method. EDHOC supports authentication with signature or static Diffie-Hellman keys, as defined in the four authentication methods: 0, 1, 2, and 3, see {{fig-method-types}}. When using a static Diffie-Hellman key the authentication is provided by a Message Authentication Code (MAC) computed from an ephemeral-static ECDH shared secret which enables significant reductions in message sizes.

The Initiator and the Responder need to have agreed on a single method to be used for EDHOC, see {{applicability}}.

~~~~~~~~~~~
+-------------+--------------------+--------------------+
| Method Type | Initiator          | Responder          |
|       Value | Authentication Key | Authentication Key |
+-------------+--------------------+--------------------+
|           0 | Signature Key      | Signature Key      |
|           1 | Signature Key      | Static DH Key      |
|           2 | Static DH Key      | Signature Key      |
|           3 | Static DH Key      | Static DH Key      |
+-------------+--------------------+--------------------+
~~~~~~~~~~~
{: #fig-method-types title="Authentication Keys for Method Types"}
{: artwork-align="center"}

EDHOC does not have a dedicated message field to indicate protocol version. Breaking changes to EDHOC can be introduced by specifying and registering new methods.

## Connection Identifiers {#ci}

EDHOC includes the selection of connection identifiers (C_I, C_R) identifying a connection for which keys are agreed.

Connection identifiers may be used to correlate EDHOC messages and facilitate the retrieval of protocol state during EDHOC execution (see {{transport}}) or in subsequent applications of  EDHOC, e.g., in OSCORE (see {{ci-oscore}}). The connection identifiers do not have any cryptographic purpose in EDHOC except facilitating the retrieval of security data associated to the protocol state.

Connection identifiers in EDHOC are intrinsically byte strings. Most constrained devices only have a few connections for which short identifiers may be sufficient. In some cases minimum length identifiers are necessary to comply with overhead requirements. However, CBOR byte strings - with the exception of the empty byte string h’’ which encodes as one byte (0x40) - are encoded as two or more bytes. To enable one-byte encoding of certain byte strings while maintaining CBOR encoding, EDHOC represents certain byte string identifiers as CBOR ints on the wire, see {{bstr-repr}}.


### Selection of Connection Identifiers

C_I and C_R are chosen by I and R, respectively. The Initiator selects C_I and sends it in message_1 for the Responder to use as a reference to the connection in communications with the Initiator. The Responder selects C_R and sends it in message_2 for the Initiator to use as a reference to the connection in communications with the Responder.

If connection identifiers are used by an application protocol for which EDHOC establishes keys then the selected connection identifiers SHALL adhere to the requirements for that protocol, see {{ci-oscore}} for an example.

### Representation of Byte String Identifiers {#bstr-repr}

To allow identifiers with minimal overhead on the wire, certain byte strings are defined to have integer representations.

The integers with one-byte CBOR encoding are -24, ..., 23, see {{fig-int-one-byte}}. This correspondence between integers and byte strings is a natural mapping between the byte strings with CBOR diagnostic notation h'00', h'01', ..., h'37' (except h'18', h'19', ..., h'1F') and integers which are CBOR encoded as one byte.

~~~~~~~~~~~
Integer:                -24  -23   ...   -2   -1    0    1   ...   23
CBOR encoding (1 byte):  37   36   ...   21   20   00   01   ...   17
~~~~~~~~~~~
{: #fig-int-one-byte title="One-Byte CBOR Encoded Integers"}
{: artwork-align="center"}

The byte strings which coincide with a one-byte CBOR encoding of an integer MUST be represented by the CBOR encoding of that integer. Other byte strings are encoded as normal CBOR byte strings.

For example:

* h'21' is represented by 0x21 (CBOR encoding of the integer -2), not by 0x4121.
* h'0D' is represented by 0x0D (CBOR encoding of the integer 13), not by 0x410D.
* h'18' is represented by 0x4118.
* h'38' is represented by 0x4138.
* h'ABCD' is represented by 0x42ABCD.

One way to view this representation of byte strings is as a transport encoding: A byte string which parses as a CBOR int in the range -24, ..., 23 is just copied directly into the message, a byte string which doesn't is encoded as a CBOR bstr during transport.


### Use of Connection Identifiers with OSCORE {#ci-oscore}

For OSCORE, the choice of connection identifier results in the endpoint selecting its Recipient ID, see Section 3.1 of {{RFC8613}}, for which certain uniqueness requirements apply, see Section 3.3 of {{RFC8613}}. Therefore, the Initiator and the Responder MUST NOT select connection identifiers such that it results in same OSCORE Recipient ID. Since the connection identifier is a byte string, it is converted to an OSCORE Recipient ID equal to the byte string.

Examples:
   * A connection identifier 0xFF (represented in the EDHOC message as the CBOR byte string 0x41FF, see {{bstr-repr}}) is converted to the OSCORE Recipient ID 0xFF
   * A connection identifier 0x21 (represented in the EDHOC message as the CBOR int 0x21, see {{bstr-repr}}) is converted to the OSCORE Recipient ID 0x21.


## Transport {#transport}

Cryptographically, EDHOC does not put requirements on the lower layers. EDHOC is not bound to a particular transport layer and can even be used in environments without IP. In addition to transport of messages including errors, the transport is responsible, where necessary, to handle:

* message loss,
* message reordering,
* message duplication,
* fragmentation,
* demultiplex EDHOC messages from other types of messages,
* denial-of-service protection,
* message correlation.

The Initiator and the Responder need to have agreed on a transport to be used for EDHOC, see {{applicability}}.

### Use of Connection Identifiers for EDHOC Message Correlation {#ci-edhoc}

The transport needs to support the correlation between EDHOC messages and facilitate the retrieval of protocol state and security context during EDHOC protocol execution, including an indication of a message being message_1. The correlation may reuse existing mechanisms in the transport protocol. For example, the CoAP Token may be used to correlate EDHOC messages in a CoAP response and an associated CoAP request.

Connection identifiers may be used to correlate EDHOC messages and facilitate the retrieval of protocol state/security context during EDHOC protocol execution.  Transports that do not inherently provide correlation across all EDHOC messages of an exchange can send connection identifiers along with EDHOC messages to gain that required capability, e.g., by prepending the appropriate connection identifier (when available from the EDHOC protocol) to the EDHOC message. Transport of EDHOC in CoAP payloads is described in {{coap}}, which also shows how to use connection identifiers and message_1 indication with CoAP.

## Authentication Parameters {#auth-key-id}

EDHOC supports various settings for how the other endpoint's authentication (public) key may be transported, identified, and trusted.

EDHOC performs the following authentication related operations:

* EDHOC transports information about credentials in ID_CRED_I and ID_CRED_R (described in {{id_cred}}). Based on this information, the authentication credentials CRED_I and CRED_R (described in {{auth-cred}}) can be obtained. EDHOC may also transport certain authentication related information as External Authorization Data (see {{AD}}).
* EDHOC uses the authentication credentials in two ways (see {{asym-msg2-proc}} and {{asym-msg3-proc}}):
    * The authentication credential is input to the integrity verification using the MAC fields.
    * The authentication key of the authentication credential is used with the Signature_or_MAC field to verify proof-of-possession of the private key.

Other authentication related verifications are out of scope for EDHOC, and is the responsibility of the application. In particular, the authentication credential needs to be validated in the context of the connection for which EDHOC is used, see {{auth-validation}}. EDHOC MUST allow the application to read received information about credential (ID_CRED_R, ID_CRED_I). EDHOC MUST have access to the authentication key and the authentication credential.

Note that the type of authentication key, authentication credential, and the identification of the credential have a large impact on the message size. For example, the Signature_or_MAC field is much smaller with a static DH key than with a signature key. A CCS is much smaller than a self-signed certificate/CWT, but if it is possible to reference the credential with a COSE header like 'kid', then that is in turn much smaller than a CCS.

### Authentication Keys {#auth-keys}

The authentication key (i.e., the public key used for authentication) MUST be a signature key or static Diffie-Hellman key. The Initiator and the Responder MAY use different types of authentication keys, e.g., one uses a signature key and the other uses a static Diffie-Hellman key.

The authentication key algorithm needs to be compatible with the method and the cipher suite (see {{cs}}). The authentication key algorithm needs to be compatible with the EDHOC key exchange algorithm when static Diffie-Hellman authentication is used, and compatible with the EDHOC signature algorithm when signature authentication is used.

Note that for most signature algorithms, the signature is determined by the signature algorithm and the authentication key algorithm together. When using static Diffie-Hellman keys the Initiator's and Responder's private authentication keys are denoted I and R, respectively, and the public authentication keys are denoted G_I and G_R, respectively.

For X.509 certificates the authentication key is represented with a SubjectPublicKeyInfo field. For CWT and CCS (see {{auth-cred}})) the authentication key is represented with a 'cnf' claim {{RFC8747}} containing a COSE_Key {{I-D.ietf-cose-rfc8152bis-struct}}.


### Authentication Credentials {#auth-cred}

The authentication credentials, CRED_I and CRED_R, contain the public authentication key of the Initiator and the Responder, respectively.

EDHOC relies on COSE for identification of credentials (see {{id_cred}}), for example X.509 certificates {{RFC5280}}, C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}, CWTs {{RFC8392}} and CWT Claims Sets (CCS) {{RFC8392}}. When the identified credential is a chain or a bag, the authentication credential CRED_x is just the end entity X.509 or C509 certificate / CWT.

Since CRED_R is used in the integrity verification, see {{asym-msg2-proc}}, it needs to be specified such that it is identical when used by Initiator or Responder. Similarly for CRED_I, see {{asym-msg3-proc}}. The Initiator and Responder are expected to agree on a specific encoding of the credential, see {{applicability}}.

It is RECOMMENDED that the COSE 'kid' parameter, when used to identify the authentication credential, refers to a specific encoding. The Initiator and Responder SHOULD use an available authentication credential (transported in EDHOC or otherwise provisioned) without re-encoding. If for some reason re-encoding of the authentication credential may occur, then a potential common encoding for CBOR based credentials is bytewise lexicographic order of their deterministic encodings as specified in Section 4.2.1 of {{RFC8949}}.

* When the authentication credential is an X.509 certificate, CRED_x SHALL be the DER encoded certificate, encoded as a bstr {{I-D.ietf-cose-x509}}.
* When the authentication credential is a C509 certificate, CRED_x SHALL be the C509Certificate {{I-D.ietf-cose-cbor-encoded-cert}}.
* When the authentication credential is a COSE_Key in a CWT, CRED_x SHALL be the untagged CWT.
* When the authentication credential is a COSE_Key but not in a CWT, CRED_x SHALL be an untagged CCS.
   * Naked COSE_Keys are thus dressed as CCS when used in EDHOC, which is done by prefixing the COSE_Key with 0xA108A101.

An example of a CRED_x is shown below:

~~~~~~~~~~~
{                                              /CCS/
  2 : "42-50-31-FF-EF-37-32-39",               /sub/
  8 : {                                        /cnf/
    1 : {                                      /COSE_Key/
      1 : 1,                                   /kty/
      2 : h'00',                               /kid/
     -1 : 4,                                   /crv/
     -2 : h'b1a3e89460e88d3a8d54211dc95f0b90   /x/
            3ff205eb71912d6db8f4af980d2db83a'
    }
  }
}
~~~~~~~~~~~
{: title="CWT Claims Set (CCS) containing an X25519 static Diffie-Hellman key and an EUI-64 identity."}


### Identification of Credentials {#id_cred}

ID_CRED_R and ID_CRED_I are transported in message_2 and message_3, respectively, see {{asym-msg2-proc}} and {{asym-msg3-proc}}. They are used to identify and optionally transport credentials:

* ID_CRED_R is intended to facilitate for the Initiator to retrieve the authentication credential CRED_R and the authentication key of R.

* ID_CRED_I is intended to facilitate for the Responder to retrieve the authentication credential CRED_I and the authentication key of I.

ID_CRED_x may contain the authentication credential CRED_x, but for many settings it is not necessary to transport the authentication credential within EDHOC, for example, it may be pre-provisioned or acquired out-of-band over less constrained links. ID_CRED_I and ID_CRED_R do not have any cryptographic purpose in EDHOC since the authentication credentials are integrity protected.

EDHOC relies on COSE for identification of credentials and supports all credential types for which COSE header parameters are defined including X.509 certificates ({{I-D.ietf-cose-x509}}), C509 certificates ({{I-D.ietf-cose-cbor-encoded-cert}}), CWT ({{cwt-header-param}}) and CWT Claims Set (CCS) ({{cwt-header-param}}).

ID_CRED_I and ID_CRED_R are COSE header maps and contains one or more COSE header parameters. ID_CRED_I and ID_CRED_R MAY contain different header parameters. The header parameters typically provide some information about the format of the credential.

Note that COSE header parameters in ID_CRED_x are used to identify the sender's credential. There is therefore no reason to use the "-sender" header parameters, such as x5t-sender, defined in Section 3 of {{I-D.ietf-cose-x509}}. Instead, the corresponding parameter without "-sender", such as x5t, SHOULD be used.

Example: X.509 certificates can be identified by a hash value using the 'x5t' parameter:

* ID_CRED_x = { 34 : COSE_CertHash }, for x = I or R,

Example: CWT or CCS can be identified by a key identifier using the 'kid' parameter:

* ID_CRED_x = { 4 : key_id_x }, where key_id_x : kid, for x = I or R.

The value of a COSE 'kid' parameter is a byte string. To allow one-byte encodings of ID_CRED_x with key identifiers 'kid', which is useful in scenarios with only a few keys, the integer representation of identifiers in {{bstr-repr}} MUST be applied. For details, see {{asym-msg2-proc}} and {{asym-msg3-proc}}.

As stated in Section 3.1 of {{I-D.ietf-cose-rfc8152bis-struct}}, applications MUST NOT assume that 'kid' values are unique and several keys associated with a 'kid' may need to be checked before the correct one is found. Applications might use additional information such as 'kid context' or lower layers to determine which key to try first. Applications should strive to make ID_CRED_x as unique as possible, since the recipient may otherwise have to try several keys.

See {{COSE}} for more examples.

## Cipher Suites {#cs}

An EDHOC cipher suite consists of an ordered set of algorithms from the "COSE Algorithms" and "COSE Elliptic Curves" registries as well as the EDHOC MAC length. All algorithm names and definitions follows from COSE {{I-D.ietf-cose-rfc8152bis-algs}}. Note that COSE sometimes uses peculiar names such as ES256 for ECDSA with SHA-256, A128 for AES-128, and Ed25519 for the curve edwards25519. Algorithms need to be specified with enough parameters to make them completely determined. The MAC length MUST be at least 8 bytes. Any cryptographic algorithm used in the COSE header parameters in ID_CRED is selected independently of the cipher suite. EDHOC is currently only specified for use with key exchange algorithms of type ECDH curves, but any Key Encapsulation Method (KEM), including Post-Quantum Cryptography (PQC) KEMs, can be used in method 0, see {{pqc}}. Use of other types of key exchange algorithms to replace static DH authentication (method 1,2,3) would likely require a specification updating EDHOC with new methods.

EDHOC supports all signature algorithms defined by COSE. Just like in (D)TLS 1.3 {{RFC8446}}{{RFC9147}} and IKEv2 {{RFC7296}}, a signature in COSE is determined by the signature algorithm and the authentication key algorithm together, see {{auth-keys}}. The exact details of the authentication key algorithm depend on the type of authentication credential. COSE supports different formats for storing the public authentication keys including COSE_Key and X.509, which use different names and ways to represent the authentication key and the authentication key algorithm.

An EDHOC cipher suite consists of the following parameters:

* EDHOC AEAD algorithm
* EDHOC hash algorithm
* EDHOC MAC length in bytes (Static DH)
* EDHOC key exchange algorithm (ECDH curve)
* EDHOC signature algorithm
* Application AEAD algorithm
* Application hash algorithm

Each cipher suite is identified with a pre-defined integer label.

EDHOC can be used with all algorithms and curves defined for COSE. Implementations can either use any combination of COSE algorithms and parameters to define their own private cipher suite, or use one of the pre-defined cipher suites. Private cipher suites can be identified with any of the four values -24, -23, -22, -21. The pre-defined cipher suites are listed in the IANA registry ({{suites-registry}}) with initial content outlined here:

*   Cipher suites 0-3, based on AES-CCM, are intended for constrained IoT where message overhead is a very important factor. Note that AES-CCM-16-64-128 and AES-CCM-16-64-128 are compatible with the IEEE CCM\* mode.
      * Cipher suites 1 and 3 use a larger tag length (128-bit) in EDHOC than in the Application AEAD algorithm (64-bit).

*   Cipher suites 4 and 5, based on ChaCha20, are intended for less constrained applications and only use 128-bit tag lengths.

*   Cipher suite 6, based on AES-GCM, is for general non-constrained applications. It consists of high performance algorithms that are widely used in non-constrained applications.

*   Cipher suites 24 and 25 are intended for high security applications such as government use and financial applications. These cipher suites do not share any algorithms. Cipher suite 24 consists of algorithms from the CNSA suite {{CNSA}}.

The different methods ({{method}}) use the same cipher suites, but some algorithms are not used in some methods. The EDHOC signature algorithm is not used in methods without signature authentication.

The Initiator needs to have a list of cipher suites it supports in order of preference. The Responder needs to have a list of cipher suites it supports. SUITES_I contains cipher suites supported by the Initiator, formatted and processed as detailed in {{asym-msg1-form}} to secure the cipher suite negotiation. Examples of cipher suite negotiation are given in {{ex-neg}}.


## Ephemeral Public Keys {#cose_key}

The ephemeral public keys in EDHOC (G_X and G_Y) use compact representation of elliptic curve points, see {{comrep}}. In COSE compact representation is achieved by formatting the ECDH ephemeral public keys as COSE_Keys of type EC2 or OKP according to Sections 7.1 and 7.2 of {{I-D.ietf-cose-rfc8152bis-algs}}, but only including the 'x' parameter in G_X and G_Y. For Elliptic Curve Keys of type EC2, compact representation MAY be used also in the COSE_Key.  If the COSE implementation requires a 'y' parameter, the value y = false SHALL be used. COSE always use compact output for Elliptic Curve Keys of type EC2.

## External Authorization Data (EAD) {#AD}

In order to reduce round trips and the number of messages or to simplify processing, external security applications may be integrated into EDHOC by transporting authorization related data in the messages.

EDHOC allows opaque external authorization data (EAD) to be sent in each of the four EDHOC messages (EAD_1, EAD_2, EAD_3, EAD_4).

External authorization data is a CBOR sequence (see {{CBOR}}) consisting of one or more (ead_label, ead_value) pairs as defined below:

~~~~~~~~~~~ CDDL
ead = 1* (
  ead_label : int,
  ead_value : bstr,
)
~~~~~~~~~~~

A security application using external authorization data need to register an ead_label, specify the ead_value format for each message (see {{iana-ead}}), and describe processing and security considerations.

The EAD fields of EDHOC must not be used for generic application data. Examples of the use of EAD is provided in {{ead-appendix}}.



## Application Profile {#applicability}

EDHOC requires certain parameters to be agreed upon between Initiator and Responder. Some parameters can be negotiated through the protocol execution (specifically, cipher suite, see {{cs}}) but other parameters are only communicated and may not be negotiated (e.g., which authentication method is used, see {{method}}). Yet other parameters need to be known out-of-band.

The purpose of an application profile is to describe the intended use of EDHOC to allow for the relevant processing and verifications to be made, including things like:

1. How the endpoint detects that an EDHOC message is received. This includes how EDHOC messages are transported, for example in the payload of a CoAP message with a certain Uri-Path or Content-Format; see {{coap}}.
   * The method of transporting EDHOC messages may also describe data carried along with the messages that are needed for the transport to satisfy the requirements of {{transport}}, e.g., connection identifiers used with certain messages, see {{coap}}.
1. Authentication method (METHOD; see {{method}}).
3. Profile for authentication credentials (CRED_I, CRED_R; see {{auth-cred}}), e.g., profile for certificate or CCS, including supported authentication key algorithms (subject public key algorithm in X.509 or C509 certificate).
4. Type used to identify credentials (ID_CRED_I, ID_CRED_R; see {{id_cred}}).
5. Use and type of external authorization data (EAD_1, EAD_2, EAD_3, EAD_4; see {{AD}}).
6. Identifier used as the identity of the endpoint; see {{identities}}.
7. If message_4 shall be sent/expected, and if not, how to ensure a protected application message is sent from the Responder to the Initiator; see {{m4}}.

The application profile may also contain information about supported cipher suites. The procedure for selecting and verifying a cipher suite is still performed as described in {{asym-msg1-form}} and {{wrong-selected}}, but it may become simplified by this knowledge.

An example of an application profile is shown in {{appl-temp}}.

For some parameters, like METHOD, ID_CRED_x, type of EAD, the receiver is able to verify compliance with the application profile, and if it needs to fail because of incompliance, to infer the reason why the protocol failed.

For other parameters, like the profile of CRED_x in the case that it is not transported, it may not be possible to verify that incompliance with the application profile was the reason for failure: Integrity verification in message_2 or message_3 may fail not only because of wrong credential. For example, in case the Initiator uses public key certificate by reference (i.e., not transported within the protocol) then both endpoints need to use an identical data structure as CRED_I or else the integrity verification will fail.

Note that it is not necessary for the endpoints to specify a single transport for the EDHOC messages. For example, a mix of CoAP and HTTP may be used along the path, and this may still allow correlation between messages.

The application profile may be dependent on the identity of the other endpoint, or other information carried in an EDHOC message, but it then applies only to the later phases of the protocol when such information is known. (The Initiator does not know the identity of the Responder before having verified message_2, and the Responder does not know the identity of the Initiator before having verified message_3.)

Other conditions may be part of the application profile, such as target application or use (if there is more than one application/use) to the extent that EDHOC can distinguish between them. In case multiple application profiles are used, the receiver needs to be able to determine which is applicable for a given session, for example based on URI or external authorization data type.




# Key Derivation {#key-der}

## Keys for EDHOC Message Processing

EDHOC uses Extract-and-Expand {{RFC5869}} with the EDHOC hash algorithm in the selected cipher suite to derive keys used in message processing. This section defines Extract ({{extract}}) and Expand ({{expand}}), and how to use them to derive PRK_out ({{prkout}}) which is the shared secret key resulting from a successful EDHOC exchange.

Extract is used to derive fixed-length uniformly pseudorandom keys (PRK) from ECDH shared secrets. Expand is used to define EDHOC-KDF for generating MACs and for deriving output keying material (OKM) from PRKs.

 In EDHOC a specific message is protected with a certain pseudorandom key, but how the key is derived depends on the method as detailed in {{asym}}.

<!-- A diagram of the EDHOC key schedule can be found in Figure 2 of {{Vucinic22}}. TBD: Rewrite the diagram -->

### Extract {#extract}

The pseudorandom keys (PRKs) used for EDHOC message processing are derived using Extract:

~~~~~~~~~~~~~~~~~~~~~~~
   PRK = Extract( salt, IKM )
~~~~~~~~~~~~~~~~~~~~~~~

where the input keying material (IKM) and salt are defined for each PRK below.

The definition of Extract depends on the EDHOC hash algorithm of the selected cipher suite:

* if the EDHOC hash algorithm is SHA-2, then Extract( salt, IKM ) = HKDF-Extract( salt, IKM ) {{RFC5869}}
* if the EDHOC hash algorithm is SHAKE128, then Extract( salt, IKM ) = KMAC128( salt, IKM, 256, "" )
* if the EDHOC hash algorithm is SHAKE256, then Extract( salt, IKM ) = KMAC256( salt, IKM, 512, "" )

The rest of the section defines the pseudorandom keys PRK_2e, PRK_3e2m and PRK_4e3m; their use is shown in {{fig-edhoc-kdf}}.

#### PRK_2e

The pseudorandom key PRK_2e is derived with the following input:

* The salt SHALL be a zero-length byte string. Note that {{RFC5869}} specifies that if the salt is not provided, it is set to a string of zeros (see Section 2.2 of {{RFC5869}}). For implementation purposes, not providing the salt is the same as setting the salt to the zero-length byte string (0x).

* The IKM SHALL be the ephemeral-ephemeral ECDH shared secret G_XY (calculated from G_X and Y or G_Y and X) as defined in Section 6.3.1 of {{I-D.ietf-cose-rfc8152bis-algs}}. The use of G_XY gives forward secrecy, in the sense that compromise of the private authentication keys does not compromise past session keys.

Example: Assuming the use of curve25519, the ECDH shared secret G_XY is the output of the X25519 function {{RFC7748}}:

~~~~~~~~~~~~~~~~~~~~~~~
   G_XY = X25519( Y, G_X ) = X25519( X, G_Y )
~~~~~~~~~~~~~~~~~~~~~~~

Example: Assuming the use of SHA-256 the extract phase of HKDF produces PRK_2e as follows:

~~~~~~~~~~~~~~~~~~~~~~~
   PRK_2e = HMAC-SHA-256( salt, G_XY )
~~~~~~~~~~~~~~~~~~~~~~~

where salt = 0x (zero-length byte string).

#### PRK_3e2m

The pseudorandom key PRK_3e2m is derived as follows:

If the Responder authenticates with a static Diffie-Hellman key, then PRK_3e2m = Extract( SALT_3e2m, G_RX ), where

* SALT_3e2m is derived from PRK_2e, see {{expand}}, and
* G_RX is the ECDH shared secret calculated from G_R and X, or G_X and R (the Responder's private authentication key, see {{auth-keys}}),

else PRK_3e2m = PRK_2e.

#### PRK_4e3m

The pseudorandom key PRK_4e3m is derived as follows:

If the Initiator authenticates with a static Diffie-Hellman key, then PRK_4e3m = Extract( SALT_4e3m, G_IY ), where

* SALT_4e3m is derived from PRK_3e2m, see {{expand}}, and
* G_IY is the ECDH shared secret calculated from G_I and Y, or G_Y and I (the Initiator's private authentication key, see {{auth-keys}}),

else PRK_4e3m = PRK_3e2m.


### Expand and EDHOC-KDF {#expand}

The output keying material (OKM) - including keys, IVs, and salts - are derived from the PRKs using the EDHOC-KDF, which is defined through Expand:

~~~~~~~~~~~~~~~~~~~~~~~
   OKM = EDHOC-KDF( PRK, label, context, length )
       = Expand( PRK, info, length )
~~~~~~~~~~~~~~~~~~~~~~~

where info is encoded as the CBOR sequence

~~~~~~~~~~~ CDDL
info = (
  label : uint,
  context : bstr,
  length : uint,
)
~~~~~~~~~~~

where

  + label is a uint

  + context is a bstr

  + length is the length of OKM in bytes

When EDHOC-KDF is used to derive OKM for EDHOC message processing, then context includes one of the transcript hashes TH_2, TH_3, or TH_4 defined in Sections {{asym-msg2-proc}}{: format="counter"} and {{asym-msg3-proc}}{: format="counter"}.

The definition of Expand depends on the EDHOC hash algorithm of the selected cipher suite:

* if the EDHOC hash algorithm is SHA-2, then Expand( PRK, info, length ) = HKDF-Expand( PRK, info, length ) {{RFC5869}}
* if the EDHOC hash algorithm is SHAKE128, then Expand( PRK, info, length ) = KMAC128( PRK, info, L, "" )
* if the EDHOC hash algorithm is SHAKE256, then Expand( PRK, info, length ) = KMAC256( PRK, info, L, "" )

where L = 8*length, the output length in bits.

{{fig-edhoc-kdf}} lists derivations made with EDHOC-KDF during message processing, where

* hash_length - length of output size of the EDHOC hash algorithm of the selected cipher suite

* key_length - length of the encryption key of the EDHOC AEAD algorithm

* iv_length - length of the initialization vector of the EDHOC AEAD algorithm

Further details of the key derivation and how the output keying material is used is specified in {{asym}}.

~~~~~~~~~~~~~~~~~~~~~~~
KEYSTREAM_2   = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
SALT_3e2m     = EDHOC-KDF( PRK_2e,   1, TH_2,      hash_length )
MAC_2         = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
K_3           = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
IV_3          = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
SALT_4e3m     = EDHOC-KDF( PRK_3e2m, 5, TH_3,      hash_length )
MAC_3         = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
PRK_out       = EDHOC-KDF( PRK_4e3m, 7, TH_4,      hash_length )
K_4           = EDHOC-KDF( PRK_4e3m, 8, TH_4,      key_length )
IV_4          = EDHOC-KDF( PRK_4e3m, 9, TH_4,      iv_length )
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-edhoc-kdf title="Key derivations using EDHOC-KDF."}
{: artwork-align="center"}

### PRK_out {#prkout}

 The pseudorandom key PRK_out, derived as shown in {{fig-edhoc-kdf}}, is the only secret key shared between Initiator and Responder that needs to be stored after a successful EDHOC exchange, see {{m3}}. Keys for applications are derived from PRK_out, see {{exporter}}.

## Keys for EDHOC Applications

This section defines EDHOC-Exporter and EDHOC-KeyUpdate in terms of EDHOC-KDF and PRK_out.

### EDHOC-Exporter {#exporter}

Keying material for the application can be derived using the EDHOC-Exporter interface defined as:

~~~~~~~~~~~
   EDHOC-Exporter(label, context, length)
     = EDHOC-KDF(PRK_exporter, label, context, length)
~~~~~~~~~~~
where

* label is a registered uint from the EDHOC Exporter Label registry ({{exporter-label}})
* context is a bstr defined by the application
* length is a uint defined by the application
* PRK_exporter is derived from PRK_out:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
~~~~~~~~~~~~~~~~~~~~~~~

where hash_length denotes the output size in bytes of the EDHOC hash algorithm of the selected cipher suite.

PRK_exporter MUST be derived anew from PRK_out if EDHOC-KeyUpdate is used, see {{keyupdate}}.

The (label, context) pair used in EDHOC-Exporter must be unique, i.e., a (label, context) MUST NOT be used for two different purposes. However an application can re-derive the same key several times as long as it is done in a secure way. For example, in most encryption algorithms the same key can be reused with different nonces. The context can for example be the empty CBOR byte string.

Examples of use of the EDHOC-Exporter are given in {{transfer}}.


### EDHOC-KeyUpdate {#keyupdate}

To provide forward secrecy in an even more efficient way than re-running EDHOC, EDHOC provides the function EDHOC-KeyUpdate. When EDHOC-KeyUpdate is called, the old PRK_out is deleted and the new PRK_out is calculated as a "hash" of the old key using the Expand function as illustrated by the following pseudocode:

~~~~~~~~~~~
   EDHOC-KeyUpdate( context ):
      PRK_out = EDHOC-KDF( PRK_out, 11, context, hash_length )
~~~~~~~~~~~

where hash_length denotes the output size in bytes of the EDHOC hash algorithm of the selected cipher suite.

The EDHOC-KeyUpdate takes a context as input to enable binding of the updated PRK_out to some event that triggered the keyUpdate. The Initiator and the Responder need to agree on the context, which can, e.g., be a counter or a pseudorandom number such as a hash. The Initiator and the Responder also need to cache the old PRK_out until it has verfied that the other endpoint has the correct new PRK_out. {{I-D.ietf-core-oscore-key-update}} describes key update for OSCORE using EDHOC-KeyUpdate.

While this key update method provides forward secrecy it does not give as strong security properties as re-running EDHOC, see {{security}}.

# Message Formatting and Processing {#asym}

This section specifies formatting of the messages and processing steps. Error messages are specified in {{error}}. Annotated traces of EDHOC protocol runs are provided in {{I-D.ietf-lake-traces}}.

An EDHOC message is encoded as a sequence of CBOR data items (CBOR Sequence, {{RFC8742}}).
Additional optimizations are made to reduce message overhead.

While EDHOC uses the COSE_Key, COSE_Sign1, and COSE_Encrypt0 structures, only a subset of the parameters is included in the EDHOC messages, see {{COSE}}. The unprotected COSE header in COSE_Sign1, and COSE_Encrypt0 (not included in the EDHOC message) MAY contain parameters (e.g., 'alg').

## Message Processing Outline {#proc-outline}

This section outlines the message processing of EDHOC.

For each new/ongoing session, the endpoints are assumed to keep an associated protocol state containing identifiers, keying material, etc. used for subsequent processing of protocol related data. The protocol state is assumed to be associated to an application profile ({{applicability}}) which provides the context for how messages are transported, identified, and processed.

EDHOC messages SHALL be processed according to the current protocol state. The following steps are expected to be performed at reception of an EDHOC message:

1. Detect that an EDHOC message has been received, for example by means of port number, URI, or media type ({{applicability}}).

2. Retrieve the protocol state according to the message correlation provided by the transport, see {{transport}}. If there is no protocol state, in the case of message_1, a new protocol state is created. The Responder endpoint needs to make use of available Denial-of-Service mitigation ({{dos}}).

3. If the message received is an error message, then process it according to {{error}}, else process it as the expected next message according to the protocol state.

If the processing fails for some reason then, typically, an error message is sent, the protocol is discontinued, and the protocol state erased. Further details are provided in the following subsections and in {{error}}.

Different instances of the same message MUST NOT be processed in one session.  Note that processing will fail if the same message appears a second time for EDHOC processing in the same session because the state of the protocol has moved on and now expects something else. This assumes that message duplication due to re-transmissions is handled by the transport protocol, see {{transport}}. The case when the transport does not support message deduplication is addressed in {{duplication}}.


## EDHOC Message 1 {#m1}

### Formatting of Message 1 {#asym-msg1-form}

message_1 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  METHOD : int,
  SUITES_I : suites,
  G_X : bstr,
  C_I : bstr / -24..23,
  ? EAD_1 : ead,
)

suites = [ 2* int ] / int
~~~~~~~~~~~

where:

* METHOD - authentication method, see {{method}}.
* SUITES_I - array of cipher suites which the Initiator supports in order of preference, the first cipher suite in network byte order is the most preferred by I, the last is the one selected by I for this session. If the most preferred cipher suite is selected then SUITES_I contains only that cipher suite and is encoded as an int. The processing steps are detailed below and in {{wrong-selected}}.
* G_X - the ephemeral public key of the Initiator
* C_I - variable length connection identifier. Note that connection identifiers are byte strings but certain values are represented as integers in the message, see {{bstr-repr}}.
* EAD_1 - external authorization data, see {{AD}}.

### Initiator Processing of Message 1 {#init-proc-msg1}

The Initiator SHALL compose message_1 as follows:

* Construct SUITES_I complying with the definition in {{asym-msg1-form}}}, and furthermore:
   * The Initiator MUST select its most preferred cipher suite, conditioned on what it can assume to be supported by the Responder.
   * The selected cipher suite (i.e., the last cipher suite in SUITES_I) MAY be different between sessions, e.g., based on previous error messages (see next bullet), but all cipher suites which are more preferred by I than the selected cipher suite MUST be included in SUITES_I.
   * If the Initiator previously received from the Responder an error message with error code 2 containing SUITES_R (see {{wrong-selected}}) which indicates cipher suites supported by the Responder, then the Initiator SHOULD select its most preferred supported cipher suite among those (bearing in mind that error messages are not authenticated and may be forged).
   * The Initiator MUST NOT change the supported cipher suites and the order of preference in SUITES_I based on previous error messages.


* Generate an ephemeral ECDH key pair using the curve in the selected cipher suite and format it as a COSE_Key. Let G_X be the 'x' parameter of the COSE_Key.

* Choose a connection identifier C_I and store it for the length of the protocol.

* Encode message_1 as a sequence of CBOR encoded data items as specified in {{asym-msg1-form}}

### Responder Processing of Message 1 {#resp-proc-msg1}

The Responder SHALL process message_1 as follows:

* Decode message_1 (see {{CBOR}}).

* Verify that the selected cipher suite is supported and that no prior cipher suite in SUITES_I is supported.

* If EAD_1 is present then make it available to the application for EAD processing.

If any processing step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the session MUST be discontinued.

## EDHOC Message 2 {#m2}

### Formatting of Message 2 {#asym-msg2-form}

message_2 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
  C_R : bstr / -24..23,
)
~~~~~~~~~~~

where:

* G_Y_CIPHERTEXT_2 - the concatenation of G_Y (i.e., the ephemeral public key of the Responder) and CIPHERTEXT_2.
* C_R - variable length connection identifier. Note that connection identifiers are byte strings but certain values are represented as integers in the message, see {{bstr-repr}}.

### Responder Processing of Message 2 {#asym-msg2-proc}

The Responder SHALL compose message_2 as follows:

* Generate an ephemeral ECDH key pair using the curve in the selected cipher suite and format it as a COSE_Key. Let G_Y be the 'x' parameter of the COSE_Key.

* Choose a connection identifier C_R and store it for the length of the protocol.

* Compute the transcript hash TH_2 = H( G_Y, C_R, H(message_1) ) where H() is the EDHOC hash algorithm of the selected cipher suite. The transcript hash TH_2 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence. Note that H(message_1) can be computed and cached already in the processing of message_1.

* Compute MAC_2 as in {{expand}} with context_2 = << ID_CRED_R, TH_2, CRED_R, ? EAD_2 >>
   * If the Responder authenticates with a static Diffie-Hellman key (method equals 1 or 3), then mac_length_2 is the EDHOC MAC length of the selected cipher suite. If the Responder authenticates with a signature key (method equals 0 or 2), then mac_length_2 is equal to the output size of the EDHOC hash algorithm of the selected cipher suite.
    * ID_CRED_R - identifier to facilitate the retrieval of CRED_R, see {{id_cred}}
    * CRED_R - CBOR item containing the authentication credential of the Responder, see {{auth-cred}}
    * EAD_2 - external authorization data, see {{AD}}

* If the Responder authenticates with a static Diffie-Hellman key (method equals 1 or 3), then Signature_or_MAC_2 is MAC_2. If the Responder authenticates with a signature key (method equals 0 or 2), then Signature_or_MAC_2 is the 'signature' field of a COSE_Sign1 object, computed as specified in Section 4.4 of {{I-D.ietf-cose-rfc8152bis-struct}} using the signature algorithm of the selected cipher suite, the private authentication key of the Responder, and the following parameters as input (see {{COSE}} for an overview of COSE and {{CBOR}} for notation):

   * protected =  << ID_CRED_R >>

   * external_aad = << TH_2, CRED_R, ? EAD_2 >>

   * payload = MAC_2

* CIPHERTEXT_2 is calculated by using the Expand function as a binary additive stream cipher over the following plaintext:

   * PLAINTEXT_2 = ( ? PAD_2, ID_CRED_R / bstr / -24..23, Signature_or_MAC_2, ? EAD_2 )

      * If ID_CRED_R contains a single 'kid' parameter, i.e., ID_CRED_R = { 4 : kid_R }, then only the byte string kid_R is conveyed in the plaintext, represented as described in {{bstr-repr}}.

      * PAD_2 = 1* `true` (see {{CBOR}}) is padding that may be used to hide the length of the unpadded plaintext

   * Compute KEYSTREAM_2 as in {{expand}}, where plaintext_length is the length of PLAINTEXT_2.

   * CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2

* Encode message_2 as a sequence of CBOR encoded data items as specified in {{asym-msg2-form}}.

### Initiator Processing of Message 2

The Initiator SHALL process message_2 as follows:

* Decode message_2 (see {{CBOR}}).

* Retrieve the protocol state using the message correlation provided by the transport (e.g., the CoAP Token, the 5-tuple, or the prepended C_I, see {{coap}}).

* Decrypt CIPHERTEXT_2, see {{asym-msg2-proc}}, and, if present, discard the padding PAD_2.

* Make ID_CRED_R and (if present) EAD_2 available to the application for authentication- and EAD processing.

* Obtain the authentication credential (CRED_R) and the authentication key of R from the application (or by other means).

* Verify Signature_or_MAC_2 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg2-proc}}.

If any processing step fails, the Initiator MUST send an EDHOC error message back, formatted as defined in {{error}}, and the session MUST be discontinued.


## EDHOC Message 3 {#m3}

### Formatting of Message 3 {#asym-msg3-form}

message_3 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  CIPHERTEXT_3 : bstr,
)
~~~~~~~~~~~


### Initiator Processing of Message 3 {#asym-msg3-proc}

The Initiator SHALL compose message_3 as follows:

* Compute the transcript hash TH_3 = H(TH_2, PLAINTEXT_2) where H() is the EDHOC hash algorithm of the selected cipher suite. The transcript hash TH_3 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence. Note that H(TH_2, PLAINTEXT_2) can be computed and cached already in the processing of message_2.

* Compute MAC_3 as in {{expand}}, with context_3 = << ID_CRED_I, TH_3, CRED_I, ? EAD_3 >>
    * If the Initiator authenticates with a static Diffie-Hellman key (method equals 2 or 3), then mac_length_3 is the EDHOC MAC length of the selected cipher suite.  If the Initiator authenticates with a signature key (method equals 0 or 1), then mac_length_3 is equal to the output size of the EDHOC hash algorithm of the selected cipher suite.
    * ID_CRED_I - identifier to facilitate the retrieval of CRED_I, see {{id_cred}}
    * CRED_I - CBOR item containing the authentication credential of the Initiator, see {{auth-cred}}
    * EAD_3 - external authorization data, see {{AD}}


* If the Initiator authenticates with a static Diffie-Hellman key (method equals 2 or 3), then Signature_or_MAC_3 is MAC_3. If the Initiator authenticates with a signature key (method equals 0 or 1), then Signature_or_MAC_3 is the 'signature' field of a COSE_Sign1 object, computed as specified in Section 4.4 of {{I-D.ietf-cose-rfc8152bis-struct}} using the signature algorithm of the selected cipher suite, the private authentication key of the Initiator, and the following parameters as input (see {{COSE}}):

   * protected =  << ID_CRED_I >>

   * external_aad = << TH_3, CRED_I, ? EAD_3 >>

   * payload = MAC_3

* Compute a COSE_Encrypt0 object as defined in Sections 5.2 and 5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}, with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_3, the initialization vector IV_3 (if used by the AEAD algorithm), the plaintext PLAINTEXT_3, and the following parameters as input (see {{COSE}}):

   * protected = h''
   * external_aad = TH_3

   * K_3 and IV_3 are defined in {{expand}}

   * PLAINTEXT_3 = ( ? PAD_3, ID_CRED_I / bstr / -24..23, Signature_or_MAC_3, ? EAD_3 )

       * If ID_CRED_I contains a single 'kid' parameter, i.e., ID_CRED_I = { 4 : kid_I }, then only the byte string kid_I is conveyed in the plaintext, represented as described in {{bstr-repr}}.

       * PAD_3 = 1* `true` (see {{CBOR}}) is padding that may be used to hide the length of the unpadded plaintext

   CIPHERTEXT_3 is the 'ciphertext' of COSE_Encrypt0.

* Compute the transcript hash TH_4 = H(TH_3, PLAINTEXT_3) where H() is the EDHOC hash algorithm of the selected cipher suite. The transcript hash TH_4 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

* Calculate PRK_out as defined in {{fig-edhoc-kdf}}. The Initiator can now derive application keys using the EDHOC-Exporter interface, see {{exporter}}.

* Encode message_3 as a CBOR data item as specified in {{asym-msg3-form}}.

*  Make the connection identifiers (C_I, C_R) and the application algorithms in the selected cipher suite available to the application.

 The Initiator SHOULD NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message, from the Responder. This is similar to waiting for acknowledgement (ACK) in a transport protocol.


### Responder Processing of Message 3

The Responder SHALL process message_3 as follows:

* Decode message_3 (see {{CBOR}}).

* Retrieve the protocol state using the message correlation provided by the transport (e.g., the CoAP Token, the 5-tuple, or the prepended C_R, see {{coap}}).

* Decrypt and verify the COSE_Encrypt0 as defined in Sections 5.2 and 5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}, with the EDHOC AEAD algorithm in the selected cipher suite, and the parameters defined in {{asym-msg3-proc}}. Discard the padding PAD_3, if present.

* Make ID_CRED_I and (if present) EAD_3 available to the application for authentication- and EAD processing.

* Obtain the authentication credential (CRED_I) and the authentication key of I from the application (or by other means).

* Verify Signature_or_MAC_3 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg3-proc}}.

*  Make the connection identifiers (C_I, C_R) and the application algorithms in the selected cipher suite available to the application.

After verifying message_3, the Responder can compute PRK_out, see {{prkout}}, derive application keys using the EDHOC-Exporter interface, see {{exporter}}, persistently store the keying material, and send protected application data.

If any processing step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the session MUST be discontinued.


## EDHOC Message 4 {#m4}

This section specifies message_4 which is OPTIONAL to support. Key confirmation is normally provided by sending an application message from the Responder to the Initiator protected with a key derived with the EDHOC-Exporter, e.g., using OSCORE (see {{transfer}}). In deployments where no protected application message is sent from the Responder to the Initiator, message_4 MUST be supported and MUST be used. Two examples of such deployments:

1. When EDHOC is only used for authentication and no application data is sent.
2. When application data is only sent from the Initiator to the Responder.

Further considerations about when to use message_4 are provided in {{applicability}} and {{sec-prop}}.

### Formatting of Message 4 {#asym-msg4-form}

message_4 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_4 = (
  CIPHERTEXT_4 : bstr,
)
~~~~~~~~~~~

### Responder Processing of Message 4 {#asym-msg4-proc}

The Responder SHALL compose message_4 as follows:

* Compute a COSE_Encrypt0 as defined in Sections 5.2 and 5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}, with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_4, the initialization vector IV_4 (if used by the AEAD algorithm), the plaintext PLAINTEXT_4, and the following parameters as input (see {{COSE}}):

   * protected = h''
   * external_aad = TH_4

   * K_4 and IV_4 are defined in {{expand}}

    * PLAINTEXT_4 = ( ? PAD_4, ? EAD_4 )
      * PAD_4 = 1* `true` (see {{CBOR}}) is padding that may be used to hide the length of the unpadded plaintext.
      * EAD_4 - external authorization data, see {{AD}}.

  CIPHERTEXT_4 is the 'ciphertext' of COSE_Encrypt0.

* Encode message_4 as a CBOR data item as specified in {{asym-msg4-form}}.

### Initiator Processing of Message 4

The Initiator SHALL process message_4 as follows:

* Decode message_4 (see {{CBOR}}).

* Retrieve the protocol state using the message correlation provided by the transport (e.g., the CoAP Token, the 5-tuple, or the prepended C_I, see {{coap}}).

* Decrypt and verify the COSE_Encrypt0 as defined in Sections 5.2 and 5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}, with the EDHOC AEAD algorithm in the selected cipher suite, and the parameters defined in {{asym-msg4-proc}}. Discard the padding PAD_4, if present.

* Make (if present) EAD_4 available to the application for EAD processing.

If any processing step fails, the Initiator MUST send an EDHOC error message back, formatted as defined in {{error}}, and the session MUST be discontinued.

After verifying message_4, the Initiator is assured that the Responder has calculated the key PRK_out (key confirmation) and that no other party can derive the key.

# Error Handling {#error}

This section defines the format for error messages, and the processing associated to the currently defined error codes. Additional error codes may be registered, see {{error-code-reg}}.

There are many kinds of errors that can occur during EDHOC processing. As in CoAP, an error can be triggered by errors in the received message or internal errors in the receiving endpoint. Except for processing and formatting errors, it is up to the implementation when to send an error message. Sending error messages is essential for debugging but MAY be skipped if, for example, a session cannot be found or due to denial-of-service reasons, see {{dos}}. Errors messages in EDHOC are always fatal. After sending an error message, the sender MUST discontinue the protocol. The receiver SHOULD treat an error message as an indication that the other party likely has discontinued the protocol. But as the error message is not authenticated, a received error message might also have been sent by an attacker and the receiver MAY therefore try to continue the protocol.


An EDHOC error message can be sent by either endpoint as a reply to any non-error EDHOC message. How errors at the EDHOC layer are transported depends on lower layers, which need to enable error messages to be sent and processed as intended.


error SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
error = (
  ERR_CODE : int,
  ERR_INFO : any,
)
~~~~~~~~~~~
{: #fig-error-message title="EDHOC error message."}

where:

* ERR_CODE - error code encoded as an integer. The value 0 is used for success, all other values (negative or positive) indicate errors.
* ERR_INFO - error information. Content and encoding depend on error code.

The remainder of this section specifies the currently defined error codes, see {{fig-error-codes}}. Additional error codes and corresponding error information may be specified.

~~~~~~~~~~~
+----------+---------------+----------------------------------------+
| ERR_CODE | ERR_INFO Type | Description                            |
+==========+===============+========================================+
|        0 | any           | Success                                |
+----------+---------------+----------------------------------------+
|        1 | tstr          | Unspecified error                      |
+----------+---------------+----------------------------------------+
|        2 | suites        | Wrong selected cipher suite            |
+----------+---------------+----------------------------------------+
~~~~~~~~~~~
{: #fig-error-codes title="Error codes and error information included in the EDHOC error message."}



## Success

Error code 0 MAY be used internally in an application to indicate success, i.e., as a standard value in case of no error, e.g., in status reporting or log files. ERR_INFO can contain any type of CBOR item, the content is out of scope for this specification. Error code 0 MUST NOT be used as part of the EDHOC message exchange flow. If an endpoint receives an error message with error code 0, then it MUST discontinue the protocol and MUST NOT send an error message.

## Unspecified Error

Error code 1 is used for errors that do not have a specific error code defined. ERR_INFO MUST be a text string containing a human-readable diagnostic message written in English, for example "Method not supported". The diagnostic text message is mainly intended for software engineers that during debugging need to interpret it in the context of the EDHOC specification. The diagnostic message SHOULD be provided to the calling application where it SHOULD be logged.

## Wrong Selected Cipher Suite {#wrong-selected}

Error code 2 MUST only be used when replying to message_1 in case the cipher suite selected by the Initiator is not supported by the Responder, or if the Responder supports a cipher suite more preferred by the Initiator than the selected cipher suite, see {{resp-proc-msg1}}. ERR_INFO is in this case denoted SUITES_R and is of type suites, see {{asym-msg1-form}}. If the Responder does not support the selected cipher suite, then SUITES_R MUST include one or more supported cipher suites. If the Responder supports a cipher suite in SUITES_I other than the selected cipher suite (independently of if the selected cipher suite is supported or not) then SUITES_R MUST include the supported cipher suite in SUITES_I which is most preferred by the Initiator. SUITES_R MAY include a single cipher suite, i.e., be encoded as an int. If the Responder does not support any cipher suite in SUITES_I, then it SHOULD include all its supported cipher suites in SUITES_R.

In contrast to SUITES_I, the order of the cipher suites in SUITES_R has no significance.

### Cipher Suite Negotiation

After receiving SUITES_R, the Initiator can determine which cipher suite to select (if any) for the next EDHOC run with the Responder.

If the Initiator intends to contact the Responder in the future, the Initiator SHOULD remember which selected cipher suite to use until the next message_1 has been sent, otherwise the Initiator and Responder will likely run into an infinite loop where the Initiator selects its most preferred and the Responder sends an error with supported cipher suites. After a successful run of EDHOC, the Initiator MAY remember the selected cipher suite to use in future EDHOC sessions. Note that if the Initiator or Responder is updated with new cipher suite policies, any cached information may be outdated.

Note that the Initiator's list of supported cipher suites and order of preference is fixed (see {{asym-msg1-form}} and {{init-proc-msg1}}). Furthermore, the Responder SHALL only accept message_1 if the selected cipher suite is the first cipher suite in SUITES_I that the Responder supports (see {{resp-proc-msg1}}). Following this procedure ensures that the selected cipher suite is the most preferred (by the Initiator) cipher suite supported by both parties.

If the selected cipher suite is not the first cipher suite which the Responder supports in SUITES_I received in message_1, then the Responder MUST discontinue the protocol, see {{resp-proc-msg1}}. If SUITES_I in message_1 is manipulated, then the integrity verification of message_2 containing the transcript hash TH_2 will fail and the Initiator will discontinue the protocol.

### Examples {#ex-neg}

Assume that the Initiator supports the five cipher suites 5, 6, 7, 8, and 9 in decreasing order of preference. Figures {{fig-error1}}{: format="counter"} and {{fig-error2}}{: format="counter"} show examples of how the Initiator can format SUITES_I and how SUITES_R is used by Responders to give the Initiator information about the cipher suites that the Responder supports.

In the first example ({{fig-error1}}), the Responder supports cipher suite 6 but not the initially selected cipher suite 5.

~~~~~~~~~~~
Initiator                                                   Responder
|              METHOD, SUITES_I = 5, G_X, C_I, EAD_1                |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                   ERR_CODE = 2, SUITES_R = 6                      |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|             METHOD, SUITES_I = [5, 6], G_X, C_I, EAD_1            |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error1 title="Example of an Initiator supporting suites 5, 6, 7, 8, and 9 in decreasing order of preference, and a Responder supporting suite 6 but not suite 5. The Responder rejects the first message_1 with an error indicating support for suite 6. The Initiator also supports suite 6, and therefore selects suite 6 in the second message_1. The initiator prepends in SUITES_I the selected suite 6 with the more preferred suites, in this case suite 5, to mitigate a potential attack on the cipher suite negotiation."}
{: artwork-align="center"}

In the second example ({{fig-error2}}), the Responder supports cipher suites 8 and 9 but not the more preferred (by the Initiator) cipher suites 5, 6 or 7. To illustrate the negotiation mechanics we let the Initiator first make a guess that the Responder supports suite 6 but not suite 5. Since the Responder supports neither 5 nor 6, it responds with SUITES_R containing the supported suites, after which the Initiator selects its most preferred supported suite.  (If the Responder had supported suite 5, it would have included it in SUITES_R of the response, and it would in that case have become the selected suite in the second message_1.)

~~~~~~~~~~~
Initiator                                                   Responder
|            METHOD, SUITES_I = [5, 6], G_X, C_I, EAD_1             |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                  ERR_CODE = 2, SUITES_R = [9, 8]                  |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|           METHOD, SUITES_I = [5, 6, 7, 8], G_X, C_I, EAD_1        |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error2 title="Example of an Initiator supporting suites 5, 6, 7, 8, and 9 in decreasing order of preference, and a Responder supporting suites 8 and 9 but not 5, 6 or 7. The Responder rejects the first message_1 with an error indicating support for suites 8 and 9 (in any order). The Initiator also supports suites 8 and 9, and prefers suite 8, so therefore selects suite 8 in the second message_1. The initiator prepends in SUITES_I the selected suite 8 with the more preferred suites in order of preference, in this case suites 5, 6 and 7, to mitigate a potential attack on the cipher suite negotiation."}
{: artwork-align="center"}

# Compliance Requirements {#mti}

In the absence of an application profile specifying otherwise:

An implementation MAY support only Initiator or only Responder.

An implementation MAY support only a single method. None of the methods are mandatory-to-implement.

Implementations MUST support 'kid' parameters. None of the other COSE header parameters are mandatory-to-implement.

An implementation MAY support only a single credential type (CCS, CWT, X.509, C509). None of the credential types are mandatory-to-implement.

Implementations MUST support the EDHOC-Exporter. Implementations SHOULD support EDHOC-KeyUpdate.

Implementations MAY support message_4. Error codes (ERR_CODE) 1 and 2 MUST be supported.

Implementations MAY support EAD.

Implementations MAY support padding of plaintext when sending messages. Implementations MUST support padding of plaintext when receiving messages, i.e., MUST be able to parse padded messages.

Implementations MUST support cipher suite 2 and 3. Cipher suites 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256) and 3 (AES-CCM-16-128-128, SHA-256, 16, P-256, ES256, AES-CCM-16-64-128, SHA-256) only differ in size of the MAC length, so supporting one or both of these is no essential difference. Implementations only need to implement the algorithms needed for their supported methods.

# Security Considerations {#security}

## Security Properties {#sec-prop}

EDHOC inherits its security properties from the theoretical SIGMA-I protocol {{SIGMA}}. Using the terminology from {{SIGMA}}, EDHOC provides forward secrecy, mutual authentication with aliveness, consistency, and peer awareness. As described in {{SIGMA}}, peer awareness is provided to the Responder, but not to the Initiator.

As described in {{SIGMA}}, different levels of identity protection are provided to the Initiator and the Responder. EDHOC provides identity protection of the Initiator against active attacks and identity protection of the Responder against passive attacks. An active attacker can get the credential identifier of the Responder by eavesdropping on the destination address used for transporting message_1 and send its own message_1 to the same address. The roles should be assigned to protect the most sensitive identity/identifier, typically that which is not possible to infer from routing information in the lower layers.

Compared to {{SIGMA}}, EDHOC adds an explicit method type and expands the message authentication coverage to additional elements such as algorithms, external authorization data, and previous plaintext message content. This protects against an attacker replaying messages or injecting messages from another session.

EDHOC also adds selection of connection identifiers and downgrade protected negotiation of cryptographic parameters, i.e., an attacker cannot affect the negotiated parameters. A single session of EDHOC does not include negotiation of cipher suites, but it enables the Responder to verify that the selected cipher suite is the most preferred cipher suite by the Initiator which is supported by both the Initiator and the Responder.

As required by {{RFC7258}}, IETF protocols need to mitigate pervasive monitoring when possible. EDHOC therefore only supports methods with ephemeral Diffie-Hellman and provides a KeyUpdate function for lightweight application protocol rekeying with forward secrecy, in the sense that compromise of the private authentication keys does not compromise past session keys, and compromise of a session key does not compromise past session keys.

While the KeyUpdate method can be used to meet cryptographic limits and provide partial protection against key leakage, it provides significantly weaker security properties than re-running EDHOC with ephemeral Diffie-Hellman. Even with frequent use of KeyUpdate, compromise of one session key compromises all future session keys, and an attacker therefore only needs to perform static key exfiltration {{RFC7624}}. Frequently re-running EDHOC with ephemeral Diffie-Hellman forces attackers to perform dynamic key exfiltration instead of static key exfiltration {{RFC7624}}. In the dynamic case, the attacker must have continuous interactions with the collaborator, which is more complicated and has a higher risk profile than the static case.

To limit the effect of breaches, it is important to limit the use of symmetrical group keys for bootstrapping. EDHOC therefore strives to make the additional cost of using raw public keys and self-signed certificates as small as possible. Raw public keys and self-signed certificates are not a replacement for a public key infrastructure but SHOULD be used instead of symmetrical group keys for bootstrapping.

Compromise of the long-term keys (private signature or static DH keys) does not compromise the security of completed EDHOC exchanges. Compromising the private authentication keys of one party lets an active attacker impersonate that compromised party in EDHOC exchanges with other parties but does not let the attacker impersonate other parties in EDHOC exchanges with the compromised party. Compromise of the long-term keys does not enable a passive attacker to compromise future session keys. Compromise of the HDKF input parameters (ECDH shared secret) leads to compromise of all session keys derived from that compromised shared secret. Compromise of one session key does not compromise other session keys. Compromise of PRK_out leads to compromise of all keying material derived with the EDHOC-Exporter since the last invocation (if any) of the EDHOC-KeyUpdate function.

Based on the cryptographic algorithms requirements {{sec_algs}}, EDHOC provides a minimum of 64-bit security against online brute force attacks and a minimum of 128-bit security against offline brute force attacks. To break 64-bit security against online brute force an attacker would on average have to send 4.3 billion messages per second for 68 years, which is infeasible in constrained IoT radio technologies. A forgery against a 64-bit MAC in EDHOC breaks the security of all future application data, while a forgery against a 64-bit MAC in the subsequent application protocol (e.g., OSCORE {{RFC8613}}) typically only breaks the security of the data in the forged packet.

After sending message_3, the Initiator is assured that no other party than the Responder can compute the key PRK_out. While the Initiator can securely send protected application data, the Initiator SHOULD NOT persistently store the keying material PRK_out until the Initiator has verified an OSCORE message or message_4 from the Responder. After verifying message_3, the Responder is assured that an honest Initiator has computed the key PRK_out. The Responder can securely derive and store the keying material PRK_out, and send protected application data.

External authorization data sent in message_1 (EAD_1) or message_2 (EAD_2) should be considered unprotected by EDHOC, see {{unprot-data}}. EAD_2 is encrypted but the Responder has not yet authenticated the Initiator and the encryption does not provide confidentiality against active attacks.

External authorization data sent in message_3 (EAD_3) or message_4 (EAD_4) is protected between Initiator and Responder by the protocol, but note that EAD fields may be used by the application before the message verification is completed, see {{AD}}. Designing a secure mechanism that uses EAD is not necessarily straightforward. This document only provides the EAD transport mechanism, but the problem of agreeing on the surrounding context and the meaning of the information passed to and from the application remains. Any new uses of EAD should be subject to careful review.

Key compromise impersonation (KCI): In EDHOC authenticated with signature keys, EDHOC provides KCI protection against an attacker having access to the long-term key or the ephemeral secret key. With static Diffie-Hellman key authentication, KCI protection would be provided against an attacker having access to the long-term Diffie-Hellman key, but not to an attacker having access to the ephemeral secret key. Note that the term KCI has typically been used for compromise of long-term keys, and that an attacker with access to the ephemeral secret key can only attack that specific session.

Repudiation: If an endpoint authenticates with a signature, the other endpoint can prove that the endpoint performed a run of the protocol by presenting the data being signed as well as the signature itself. With static Diffie-Hellman key authentication, the authenticating endpoint can deny having participated in the protocol.

Two earlier versions of EDHOC have been formally analyzed {{Norrman20}} {{Bruni18}} and the specification has been updated based on the analysis.

## Cryptographic Considerations {#crypto}
The SIGMA protocol requires that the encryption of message_3 provides confidentiality against active attackers and EDHOC message_4 relies on the use of
authenticated encryption. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism.

To reduce message overhead EDHOC does not use explicit nonces and instead relies on the ephemeral public keys to provide randomness to each session. A good amount of randomness is important for the key generation, to provide liveness, and to protect against interleaving attacks. For this reason, the ephemeral keys MUST NOT be used in more than one EDHOC message, and both parties SHALL generate fresh random ephemeral key pairs. Note that an ephemeral key may be used to calculate several ECDH shared secrets. When static Diffie-Hellman authentication is used the same ephemeral key is used in both ephemeral-ephemeral and ephemeral-static ECDH.

As discussed in {{SIGMA}}, the encryption of message_2 does only need to protect against passive attacker as active attackers can always get the Responder's identity by sending their own message_1. EDHOC uses the Expand function (typically HKDF-Expand) as a binary additive stream cipher which is proven secure as long as the expand function is a PRF.  HKDF-Expand is not often used as a stream cipher as it is slow on long messages, and most applications require both IND-CCA confidentiality as well as integrity protection. For the encryption of message_2, any speed difference is negligible, IND-CCA does not increase security, and integrity is provided by the inner MAC (and signature depending on method).

Requirements for how to securely generate, validate, and process the ephemeral public keys depend on the elliptic curve. For X25519 and X448, the requirements are defined in {{RFC7748}}. For secp256r1, secp384r1, and secp521r1, the requirements are defined in Section 5 of {{SP-800-56A}}. For secp256r1, secp384r1, and secp521r1, at least partial public-key validation MUST be done.

As noted in Section 12 of {{I-D.ietf-cose-rfc8152bis-struct}} the use of a single key for multiple algorithms is strongly discouraged unless proven secure by a dedicated cryptographic analysis. In particular this recommendation applies to using the same private key for static Diffie-Hellman authentication and digital signature authentication. A preliminary conjecture is that a minor change to EDHOC may be sufficient to fit the analysis of secure shared signature and ECDH key usage in {{Degabriele11}} and {{Thormarker21}}.

So-called selfie attacks are mitigated as long as the Initiator does not have its own identity in the set of Responder identities it is allowed to communicate with. In trust on first use (TOFU) use cases the Initiator should verify that the Responder's identity is not equal to its own. Any future EHDOC methods using e.g., pre-shared keys might need to mitigate this in other ways.

## Cipher Suites and Cryptographic Algorithms {#sec_algs}

When using private cipher suite or registering new cipher suites, the choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. The Initiator and the Responder should enforce a minimum security level.

The output size of the EDHOC hash algorithm MUST be at least 256-bits, i.e., the hash algorithms SHA-1 and SHA-256/64 (SHA-256 truncated to 64-bits) SHALL NOT be supported for use in EDHOC except for certificate identification with x5t and c5t. For security considerations of SHA-1, see {{RFC6194}}. As EDHOC integrity protects the whole authentication credential, the choice of hash algorithm in x5t and c5t does not affect security and it is RECOMMENDED to use the same hash algorithm as in the cipher suite but with as much truncation as possible, i.e., when the EDHOC hash algorithm is SHA-256 it is RECOMMENDED to use SHA-256/64 in x5t and c5t. The EDHOC MAC length MUST be at least 8 bytes and the tag length of the EDHOC AEAD algorithm MUST be at least 64-bits. Note that secp256k1 is only defined for use with ECDSA and not for ECDH. Note that some COSE algorithms are marked as not recommended in the COSE IANA registry.

## Post-Quantum Considerations {#pqc}

As of the publication of this specification, it is unclear when or even if a quantum computer of sufficient size and power to exploit public key cryptography will exist. Deployments that need to consider risks decades into the future should transition to Post-Quantum Cryptography (PQC) in the not-too-distant future. Many other systems should take a slower wait-and-see approach where PQC is phased in when the quantum threat is more imminent. Current PQC algorithms have limitations compared to Elliptic Curve Cryptography (ECC) and the data sizes would be problematic in many constrained IoT systems.

Symmetric algorithms used in EDHOC such as SHA-256 and AES-CCM-16-64-128 are practically secure against even large quantum computers. EDHOC supports all signature algorithms defined by COSE, including PQC signature algorithms such as HSS-LMS. EDHOC is currently only specified for use with key exchange algorithms of type ECDH curves, but any Key Encapsulation Method (KEM), including PQC KEMs, can be used in method 0. While the key exchange in method 0 is specified with terms of the Diffie-Hellman protocol, the key exchange adheres to a KEM interface: G_X is then the public key of the Initiator, G_Y is the encapsulation, and G_XY is the shared secret. Use of PQC KEMs to replace static DH authentication would likely require a specification updating EDHOC with new methods.

## Unprotected Data and Privacy {#unprot-data}

The Initiator and the Responder must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to EAD_1, ID_CRED_R, EAD_2, and error messages. Using the same EAD_1 in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. Another consideration is that the list of supported cipher suites may potentially be used to identify the application. The Initiator and the Responder must also make sure that unauthenticated data does not trigger any harmful actions. In particular, this applies to EAD_1 and error messages.

An attacker observing network traffic may use connection identifiers sent in clear in EDHOC or the subsequent application protocol to correlate packets sent on different paths or at different times. The attacker may use this information for traffic flow analysis or to track an endpoint. Application protocols using connection identifiers from EDHOC SHOULD provide mechanisms to update the connection identifier and MAY provide mechanisms to issue several simultaneously active connection identifiers. See {{RFC9000}} for a non-constrained example of such mechanisms. Connection identifiers SHOULD be unpredictable. Using the same identifier several times is not a problem as long as it is chosen randomly. Connection identity privacy mechanisms are only useful when there are not fixed identifiers such as IP address or MAC address in the lower layers.

## Updated Internet Threat Model Considerations {#internet-threat}

Since the publication of {{RFC3552}} there has been an increased awareness of the need to protect against endpoints that are compromised, malicious, or whose interests simply do not align with the interests of users {{I-D.arkko-arch-internet-threat-model-guidance}}. {{RFC7624}} describes an updated threat model for Internet confidentiality, see {{sec-prop}}. {{I-D.arkko-arch-internet-threat-model-guidance}} further expands the threat model. Implementations and users SHOULD consider these threat models. In particular, even data sent protected to the other endpoint such as ID_CRED and EAD can be used for tracking, see Section 2.7 of {{I-D.arkko-arch-internet-threat-model-guidance}}.

The fields ID_CRED_I, ID_CRED_R, EAD_2, EAD_3, and EAD_4 have variable length and information regarding the length may leak to an attacker. An passive attacker may e.g., be able to differentiating endpoints using identifiers of different length. To mitigate this information leakage an implementation may ensure that the fields have fixed length or use padding. An implementation may e.g., only use fix length identifiers like 'kid' of length 1. Alternatively padding may be used to hide the true length of e.g., certificates by value in 'x5chain' or 'c5c'.

## Denial-of-Service {#dos}

EDHOC itself does not provide countermeasures against Denial-of-Service attacks. In particular, by sending a number of new or replayed message_1 an attacker may cause the Responder to allocate state, perform cryptographic operations, and amplify messages. To mitigate such attacks, an implementation SHOULD rely on lower layer mechanisms. For instance, when EDHOC is transferred as an exchange of CoAP messages, the CoAP server can use the Echo option defined in {{RFC9175}} which forces the CoAP client to demonstrate reachability at its apparent network address.

An attacker can also send faked message_2, message_3, message_4, or error in an attempt to trick the receiving party to send an error message and discontinue the session. EDHOC implementations MAY evaluate if a received message is likely to have been forged by an attacker and ignore it without sending an error message or discontinuing the session.

## Implementation Considerations {#impl-cons}

The availability of a secure random number generator is essential for the security of EDHOC. If no true random number generator is available, a random seed must be provided from an external source and used with a cryptographically secure pseudorandom number generator. As each pseudorandom number must only be used once, an implementation needs to get a unique input to the pseudorandom number generator after reboot, or continuously store state in nonvolatile memory. Appendix B.1.1 in {{RFC8613}} describes issues and solution approaches for writing to nonvolatile memory. Intentionally or unintentionally weak or predictable pseudorandom number generators can be abused or exploited for malicious purposes. {{RFC8937}} describes a way for security protocol implementations to augment their (pseudo)random number generators using a long-term private key and a deterministic signature function. This improves randomness from broken or otherwise subverted random number generators. The same idea can be used with other secrets and functions such as a Diffie-Hellman function or a symmetric secret and a PRF like HMAC or KMAC. It is RECOMMENDED to not trust a single source of randomness and to not put unaugmented random numbers on the wire.

Implementations might consider deriving secret and non-secret randomness from different PNRG/PRF/KDF instances to limit the damage if the PNRG/PRF/KDF turns out to be fundamentally broken. NIST generally forbids deriving secret and non-secret randomness from the same KDF instance, but this decision has been criticized by Krawczyk {{HKDFpaper}} and doing so is common practice. In addition to IVs, other examples are the challenge in EAP-TTLS, the RAND in 3GPP AKAs, and the Session-Id in EAP-TLS 1.3. Note that part of KEYSTREAM_2 is also non-secret randomness as it is known or predictable to an attacker. As explained by Krawczyk, if any attack is mitigated by the NIST requirement it would mean that the KDF is fully broken and would have to be replaced anyway.

For many constrained IoT devices it is problematic to support several crypto primitives. Existing devices can be expected to support either ECDSA or EdDSA. If ECDSA is supported, "deterministic ECDSA" as specified in {{RFC6979}} MAY be used. Pure deterministic elliptic-curve signatures such as deterministic ECDSA and EdDSA have gained popularity over randomized ECDSA as their security do not depend on a source of high-quality randomness. Recent research has however found that implementations of these signature algorithms may be vulnerable to certain side-channel and fault injection attacks due to their determinism. See e.g., Section 1 of {{I-D.mattsson-cfrg-det-sigs-with-noise}} for a list of attack papers. As suggested in Section 2.1.1 of {{I-D.ietf-cose-rfc8152bis-algs}} this can be addressed by combining randomness and determinism.

Appendix D of {{I-D.ietf-lwig-curve-representations}} describes how Montgomery curves such as X25519 and X448 and (twisted) Edwards curves as curves such as Ed25519 and Ed448 can mapped to and from short-Weierstrass form for implementation on platforms that accelerate elliptic curve group operations in short-Weierstrass form.

All private keys, symmetric keys, and IVs MUST be secret. Implementations should provide countermeasures to side-channel attacks such as timing attacks. Intermediate computed values such as ephemeral ECDH keys and ECDH shared secrets MUST be deleted after key derivation is completed.

The Initiator and the Responder are responsible for verifying the integrity and validity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported. The choice of revocation mechanism is left to the application. For example, in case of X.509 certificates, Certificate Revocation Lists {{RFC5280}} or OCSP {{RFC6960}} may be used. Verification of validity may require the use of a Real-Time Clock (RTC). The private authentication keys MUST be kept secret, only the Responder SHALL have access to the Responder's private authentication key and only the Initiator SHALL have access to the Initiator's private authentication key.

The Initiator and the Responder are allowed to select its connection identifiers C_I and C_R, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent application protocol (e.g., OSCORE {{RFC8613}}). The choice of connection identifier is not security critical in EDHOC but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong connection identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieve the wrong security context (which also terminates the protocol as the message cannot be verified).

If two nodes unintentionally initiate two simultaneous EDHOC message exchanges with each other even if they only want to complete a single EDHOC message exchange, they MAY terminate the exchange with the lexicographically smallest G_X. Note that in cases where several EDHOC exchanges with different parameter sets (method, COSE headers, etc.) are used, an attacker can affect which of the parameter sets that will be used by blocking some of the parameter sets.

If supported by the device, it is RECOMMENDED that at least the long-term private keys are stored in a Trusted Execution Environment (TEE) and that sensitive operations using these keys are performed inside the TEE.  To achieve even higher security it is RECOMMENDED that additional operations such as ephemeral key generation, all computations of shared secrets, and storage of the PRK keys can be done inside the TEE. The use of a TEE aims at preventing code within that environment to be tampered with, and preventing data used by such code to be read or tampered with by code outside that environment.


Note that HKDF-Expand has a relatively small maximum output length of 255 * hash_length, where hash_length is the output size in bytes of the EDHOC hash algorithm of the selected cipher suite. This means that when when SHA-256 is used as hash algorithm, message_2 cannot be longer than 8160 bytes.


The sequence of transcript hashes in EHDOC (TH_2, TH_3, TH_4) do not make use of a so called running hash, this is a design choice as running hashes are often not supported on constrained platforms.

When parsing a received EDHOC message, implementations MUST terminate the protocol if the message does not comply with the CDDL for that message. It is RECOMMENDED to terminate the protocol if the received EDHOC message is not deterministic CBOR.


# IANA Considerations {#iana}

## EDHOC Exporter Label Registry {#exporter-label}

IANA has created a new registry titled "EDHOC Exporter Label" under the new group name "Ephemeral Diffie-Hellman Over COSE (EDHOC)". The registration procedure is "Expert Review". The columns of the registry are Label and Description. Label is a uint. Description is a text string. The initial contents of the registry are:

<!-- TBD Labels for private use? -->

~~~~~~~~~~~~~~~~~~~~~~~
Label: 0
Description: Derived OSCORE Master Secret
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Label: 1
Description: Derived OSCORE Master Salt
~~~~~~~~~~~~~~~~~~~~~~~


## EDHOC Cipher Suites Registry {#suites-registry}

IANA has created a new registry titled "EDHOC Cipher Suites" under the new group name "Ephemeral Diffie-Hellman Over COSE (EDHOC)". The registration procedure is "Expert Review". The columns of the registry are Value, Array and Description, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~~~~~~~~~~~~~
Value: -24
Algorithms: N/A
Desc: Reserved for Private Use
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -23
Algorithms: N/A
Desc: Reserved for Private Use
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -22
Algorithms: N/A
Desc: Reserved for Private Use
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -21
Algorithms: N/A
Desc: Reserved for Private Use
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 0
Array: 10, -16, 8, 4, -8, 10, -16
Desc: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA,
      AES-CCM-16-64-128, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 1
Array: 30, -16, 16, 4, -8, 10, -16
Desc: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA,
      AES-CCM-16-64-128, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 2
Array: 10, -16, 8, 1, -7, 10, -16
Desc: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256,
      AES-CCM-16-64-128, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 3
Array: 30, -16, 16, 1, -7, 10, -16
Desc: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256,
      AES-CCM-16-64-128, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 4
Array: 24, -16, 16, 4, -8, 24, -16
Desc: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA,
      ChaCha20/Poly1305, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 5
Array: 24, -16, 16, 1, -7, 24, -16
Desc: ChaCha20/Poly1305, SHA-256, 16, P-256, ES256,
      ChaCha20/Poly1305, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 6
Array: 1, -16, 16, 4, -7, 1, -16
Desc: A128GCM, SHA-256, 16, X25519, ES256,
      A128GCM, SHA-256
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 24
Array: 3, -43, 16, 2, -35, 3, -43
Desc: A256GCM, SHA-384, 16, P-384, ES384,
      A256GCM, SHA-384
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 25
Array: 24, -45, 16, 5, -8, 24, -45
Desc: ChaCha20/Poly1305, SHAKE256, 16, X448, EdDSA,
      ChaCha20/Poly1305, SHAKE256
~~~~~~~~~~~~~~~~~~~~~~~

## EDHOC Method Type Registry {#method-types}

IANA has created a new registry entitled "EDHOC Method Type" under the new group name "Ephemeral Diffie-Hellman Over COSE (EDHOC)". The registration procedure is "Specification Required". The columns of the registry are Value, Initiator Authentication Key, and Responder Authentication Key, where Value is an integer and the other columns are text strings describing the authentication keys. The initial contents of the registry are shown in {{fig-method-types}}.

## EDHOC Error Codes Registry {#error-code-reg}

IANA has created a new registry entitled "EDHOC Error Codes" under the new group name "Ephemeral Diffie-Hellman Over COSE (EDHOC)". The registration procedure is "Expert Review". The columns of the registry are ERR_CODE, ERR_INFO Type and Description, where ERR_CODE is an integer, ERR_INFO is a CDDL defined type, and Description is a text string. The initial contents of the registry are shown in {{fig-error-codes}}.

## EDHOC External Authorization Data Registry {#iana-ead}

IANA has created a new registry entitled "EDHOC External Authorization Data" under the new group name "Ephemeral Diffie-Hellman Over COSE (EDHOC)". The registration procedure is "Specification Required". The columns of the registry are Label, Message, Description, and Reference, where Label is an integer and the other columns are text strings.

## COSE Header Parameters Registry {#cwt-header-param}

IANA has registered the following entries in the "COSE Header Parameters" registry under the group name "CBOR Object Signing and Encryption (COSE)". The value of the 'kcwt' header parameter is a COSE Web Token (CWT) {{RFC8392}}, and the value of the 'kccs' header parameter is a CWT Claims Set (CCS), see {{term}}. The CWT/CCS must contain a COSE_Key in a 'cnf' claim {{RFC8747}}. The Value Registry for this item is empty and omitted from the table below.

~~~~~~~~~~~
+-----------+-------+----------------+---------------------------+
| Name      | Label | Value Type     | Description               |
+===========+=======+================+===========================+
| kcwt      | TBD1  | COSE_Messages  | A CBOR Web Token (CWT)    |
|           |       |                | containing a COSE_Key in  |
|           |       |                | a 'cnf' claim             |
+-----------+-------+----------------+---------------------------+
| kccs      | TBD2  | map / #6(map)  | A CWT Claims Set (CCS)    |
|           |       |                | containing a COSE_Key in  |
|           |       |                | a 'cnf' claim             |
+-----------+-------+----------------+---------------------------+
~~~~~~~~~~~


## The Well-Known URI Registry {#well-known}

IANA has added the well-known URI "edhoc" to the "Well-Known URIs" registry under the group name "Well-Known URIs".

- URI suffix: edhoc

- Change controller: IETF

- Specification document(s): \[\[this document\]\]

- Related information: None

## Media Types Registry {#media-type}

IANA has added the media types "application/edhoc+cbor-seq" and "application/cid-edhoc+cbor-seq" to the "Media Types" registry.

### application/edhoc+cbor-seq Media Type Registration

- Type name: application

- Subtype name: edhoc+cbor-seq

- Required parameters: N/A

- Optional parameters: N/A

- Encoding considerations: binary

- Security considerations: See Section 7 of this document.

- Interoperability considerations: N/A

- Published specification: \[\[this document\]\] (this document)

- Applications that use this media type: To be identified

- Fragment identifier considerations: N/A

- Additional information:

  * Magic number(s): N/A

  * File extension(s): N/A

  * Macintosh file type code(s): N/A

- Person & email address to contact for further information: See "Authors' Addresses" section.

- Intended usage: COMMON

- Restrictions on usage: N/A

- Author: See "Authors' Addresses" section.

- Change Controller: IESG

### application/cid-edhoc+cbor-seq Media Type Registration

- Type name: application

- Subtype name: cid-edhoc+cbor-seq

- Required parameters: N/A

- Optional parameters: N/A

- Encoding considerations: binary

- Security considerations: See Section 7 of this document.

- Interoperability considerations: N/A

- Published specification: \[\[this document\]\] (this document)

- Applications that use this media type: To be identified

- Fragment identifier considerations: N/A

- Additional information:

  * Magic number(s): N/A

  * File extension(s): N/A

  * Macintosh file type code(s): N/A

- Person & email address to contact for further information: See "Authors' Addresses" section.

- Intended usage: COMMON

- Restrictions on usage: N/A

- Author: See "Authors' Addresses" section.

- Change Controller: IESG

## CoAP Content-Formats Registry {#content-format}

IANA has added the media types "application/edhoc+cbor-seq" and "application/cid-edhoc+cbor-seq" to the "CoAP Content-Formats" registry under the group name "Constrained RESTful Environments (CoRE) Parameters".

~~~~~~~~~~~
+--------------------------------+----------+------+-------------------+
| Media Type                     | Encoding | ID   | Reference         |
+--------------------------------+----------+------+-------------------+
| application/edhoc+cbor-seq     | -        | TBD5 | [[this document]] |
| application/cid-edhoc+cbor-seq | -        | TBD6 | [[this document]] |
+--------------------------------+----------+------+-------------------+
~~~~~~~~~~~
{: #fig-format-ids title="CoAP Content-Format IDs"}

## Resource Type (rt=) Link Target Attribute Values Registry {#rt}

IANA has added the resource type "core.edhoc" to the "Resource Type (rt=) Link Target Attribute Values" registry under the group name "Constrained RESTful Environments (CoRE) Parameters".

-  Value: "core.edhoc"

-  Description: EDHOC resource.

-  Reference: \[\[this document\]\]


## Expert Review Instructions

The IANA Registries established in this document are defined as "Expert Review". This section gives some general guidelines for what the experts should be looking for, but they are being designated as experts for a reason so they should be given substantial latitude.

Expert reviewers should take into consideration the following points:

* Clarity and correctness of registrations. Experts are expected to check the clarity of purpose and use of the requested entries. Expert needs to make sure the values of algorithms are taken from the right registry, when that is required. Expert should consider requesting an opinion on the correctness of registered parameters from relevant IETF working groups. Encodings that do not meet these objective of clarity and completeness should not be registered.
* Experts should take into account the expected usage of fields when approving point assignment. The length of the encoded value should be weighed against how many code points of that length are left, the size of device it will be used on, and the number of code points left that encode to that size.
* Specifications are recommended. When specifications are not provided, the description provided needs to have sufficient information to verify the points above.

--- back


# Use with OSCORE and Transfer over CoAP {#transfer}

This appendix describes how to derive an OSCORE security context when OSCORE is used with EDHOC, and how to transfer EDHOC messages over CoAP.

## Deriving the OSCORE Security Context {#oscore-ctx-derivation}

This section specifies how to use EDHOC output to derive the OSCORE security context.

After successful processing of EDHOC message_3, Client and Server derive Security Context parameters for OSCORE as follows (see Section 3.2 of {{RFC8613}}):

* The Master Secret and Master Salt are derived by using the EDHOC-Exporter interface, see {{exporter}}.

  The EDHOC Exporter Labels for deriving the OSCORE Master Secret and the OSCORE Master Salt, are the uints 0 and 1, respectively.

  The context parameter is h'' (0x40), the empty CBOR byte string.

  By default, oscore_key_length is the key length (in bytes) of the application AEAD Algorithm of the selected cipher suite for the EDHOC session. Also by default, oscore_salt_length has value 8. The Initiator and Responder MAY agree out-of-band on a longer oscore_key_length than the default and on a different oscore_salt_length.

~~~~~~~~~~~~~~~~~~~~~~~
   Master Secret = EDHOC-Exporter( 0, h'', oscore_key_length )
   Master Salt   = EDHOC-Exporter( 1, h'', oscore_salt_length )
~~~~~~~~~~~~~~~~~~~~~~~

* The AEAD Algorithm is the application AEAD algorithm of the selected cipher suite for the EDHOC session.

* The HKDF Algorithm is the one based on the application hash algorithm of the selected cipher suite for the EDHOC session. For example, if SHA-256 is the application hash algorithm of the selected cipher suite, HKDF SHA-256 is used as HKDF Algorithm in the OSCORE Security Context.

* In case the Client is Initiator and the Server is Responder, the Client's OSCORE Sender ID and the Server's OSCORE Sender ID are determined from the EDHOC connection identifiers C_R and C_I for the EDHOC session, respectively, by applying the conversion in {{ci-oscore}}. The reverse applies in case the Client is the Responder and the Server is the Initiator.

Client and Server use the parameters above to establish an OSCORE Security Context, as per Section 3.2.1 of {{RFC8613}}.

From then on, Client and Server retrieve the OSCORE protocol state using the Recipient ID, and optionally other transport information such as the 5-tuple.

## Transferring EDHOC over CoAP {#coap}

This section specifies one instance for how EDHOC can be transferred as an exchange of CoAP {{RFC7252}} messages. CoAP provides a reliable transport that can preserve packet ordering and handle message duplication. CoAP can also perform fragmentation and protect against denial-of-service attacks. The underlying CoAP transport should be used in reliable mode, in particular when fragmentation is used, to avoid, e.g.,  situations with hanging endpoints waiting for each other.

By default, the CoAP client is the Initiator and the CoAP server is the Responder, but the roles SHOULD be chosen to protect the most sensitive identity, see {{security}}. Client applications can use the resource type "core.edhoc" to discover a server's EDHOC resource, i.e., where to send a request for executing the EDHOC protocol, see {{rt}}. According to this specification, EDHOC is transferred in POST requests and 2.04 (Changed) responses to the Uri-Path: "/.well-known/edhoc", see {{well-known}}. An application may define its own path that can be discovered, e.g., using a resource directory {{RFC9176}}.

By default, the message flow is as follows:
EDHOC message_1 is sent in the payload of a POST request from the client to the
server's resource for EDHOC. EDHOC message_2 or the EDHOC error message is
sent from the server to the client in the payload of the response, in the former case
with response code 2.04 (Changed), in the latter
   with response code as specified in {{edhoc-oscore-over-coap}}.
   EDHOC message_3 or the EDHOC error message is sent from
   the client to the server's resource in the payload of a POST request.
   If EDHOC message_4 is used, or in case of an error message, it is sent from the server to the client in the payload of the response, with response codes analogously to message_2. In case of an error message in response to message_4, it is sent analogously to errors in response to message_2.

In order for the server to correlate a message received from a client to a message previously sent in the same EDHOC session over CoAP, messages sent by the client are prepended with the CBOR serialization of the connection identifier which the server has chosen. This applies independently of if the CoAP server is Responder or Initiator.

* For the default case when the server is Responder, message_3 is sent from the client prepended with the identifier C_R. In this case message_1 is also sent by the client, and to indicate that this is a new EDHOC session it is prepended with a dummy identifier, the CBOR simple value `true` (0xf5), since the server has not selected C_R yet. See {{fig-coap1}}.

* In the case when the server is Initiator, message_2 (and, if present, message_4) is sent from the client prepended with the identifier C_I. See {{fig-coap2}}.

The prepended identifiers are encoded in CBOR and thus self-delimiting. The integer representation of identifiers described in {{bstr-repr}} is used, when applicable. They are sent in front of the actual EDHOC message to keep track of messages in an EDHOC session, and only the part of the body following the identifier is used for EDHOC processing. In particular, the connection identifiers within the EDHOC messages are not impacted by the prepended identifiers.

The application/edhoc+cbor-seq media type does not apply to these messages;
their media type is application/cid-edhoc+cbor-seq.

An example of a successful EDHOC exchange using CoAP is shown in {{fig-coap1}}. In this case the CoAP Token enables correlation on the Initiator side, and the prepended C_R enables correlation on the Responder (server) side.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/cid-edhoc+cbor-seq
  |          | Payload: true, EDHOC message_1
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc+cbor-seq
  |          | Payload: EDHOC message_2
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/cid-edhoc+cbor-seq
  |          | Payload: C_R, EDHOC message_3
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc+cbor-seq
  |          | Payload: EDHOC message_4
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap1 title="Example of transferring EDHOC in CoAP when the Initiator is CoAP client. The optional message_4 is included in this example, without which that message needs no payload."}
{: artwork-align="center"}

The exchange in {{fig-coap1}} protects the client identity against active attackers and the server identity against passive attackers.

An alternative exchange that protects the server identity against active attackers and the client identity against passive attackers is shown in {{fig-coap2}}. In this case the CoAP Token enables the Responder to correlate message_2 and message_3, and the prepended C_I enables correlation on the Initiator (server) side. If EDHOC message_4 is used, C_I is prepended, and it is transported with CoAP in the payload of a POST request with a 2.04 (Changed) response.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc+cbor-seq
  |          | Payload: EDHOC message_1
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/cid-edhoc+cbor-seq
  |          | Payload: C_I, EDHOC message_2
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc+cbor-seq
  |          | Payload: EDHOC message_3
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap2 title="Example of transferring EDHOC in CoAP when the Initiator is CoAP server."}
{: artwork-align="center"}

To protect against denial-of-service attacks, the CoAP server MAY respond to the first POST request with a 4.01 (Unauthorized) containing an Echo option {{RFC9175}}. This forces the Initiator to demonstrate its reachability at its apparent network address. If message fragmentation is needed, the EDHOC messages may be fragmented using the CoAP Block-Wise Transfer mechanism {{RFC7959}}.

EDHOC does not restrict how error messages are transported with CoAP, as long as the appropriate error message can to be transported in response to a message that failed (see {{error}}). EDHOC error messages transported with CoAP are carried in the payload.

### Transferring EDHOC and OSCORE over CoAP {#edhoc-oscore-over-coap}

When using EDHOC over CoAP for establishing an OSCORE Security Context, EDHOC error messages sent as CoAP responses MUST be sent in the payload of error responses, i.e., they MUST specify a CoAP error response code. In particular, it is RECOMMENDED that such error responses have response code either 4.00 (Bad Request) in case of client error (e.g., due to a malformed EDHOC message), or 5.00 (Internal Server Error) in case of server error (e.g., due to failure in deriving EDHOC keying material). The Content-Format of the error response MUST be set to application/edhoc+cbor-seq, see {{content-format}}.

A method for combining EDHOC and OSCORE protocols in two round-trips is specified in {{I-D.ietf-core-oscore-edhoc}}. That specification also contains conversion from OSCORE Sender/Recipient IDs to EDHOC connection identifiers, web-linking and target attributes for discovering of EDHOC resources.


# Compact Representation {#comrep}

As described in Section 4.2 of {{RFC6090}} the x-coordinate of an elliptic curve public key is a suitable representative for the entire point whenever scalar multiplication is used as a one-way function. One example is ECDH with compact output, where only the x-coordinate of the computed value is used as the shared secret.

This section defines a format for compact representation based on the Elliptic-Curve-Point-to-Octet-String Conversion defined in Section 2.3.3 of {{SECG}}.
In EDHOC, compact representation is used for the ephemeral public keys (G_X and G_Y), see {{cose_key}}. Using the notation from {{SECG}}, the output is an octet string of length ceil( (log2 q) / 8 ). See {{SECG}} for a definition of q, M, X, xp, and ~yp. The steps in Section 2.3.3 of {{SECG}} are replaced by:

  1. Convert the field element xp to an octet string X of length ceil( (log2 q) / 8 ) octets using the conversion routine specified in Section 2.3.5 of {{SECG}}.

  2. Output M = X

The encoding of the point at infinity is not supported. Compact representation does not change any requirements on validation. If a y-coordinate is required for validation or compatibility with APIs the value ~yp SHALL be set to zero. For such use, the compact representation can be transformed into the SECG point compressed format by prepending it with the single byte 0x02 (i.e., M = 0x02 \|\| X).

Using compact representation have some security benefits. An implementation does not need to check that the point is not the point at infinity (the identity element). Similarly, as not even the sign of the y-coordinate is encoded, compact representation trivially avoids so called "benign malleability" attacks where an attacker changes the sign, see {{SECG}}.

# Use of CBOR, CDDL, and COSE in EDHOC {#CBORandCOSE}

This Appendix is intended to simplify for implementors not familiar with CBOR {{RFC8949}}, CDDL {{RFC8610}}, COSE {{I-D.ietf-cose-rfc8152bis-struct}}, and HKDF {{RFC5869}}.

## CBOR and CDDL  {#CBOR}

The Concise Binary Object Representation (CBOR) {{RFC8949}} is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g., encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values, byte strings (bstr), and text strings (tstr), CBOR also supports arrays \[\]  of data items, maps {} of pairs of data items, and sequences {{RFC8742}} of data items. Some examples are given below.

The EDHOC specification sometimes use CDDL names in CBOR diagnostic notation as in e.g., << ID_CRED_R, ? EAD_2 >>. This means that EAD_2 is optional and that ID_CRED_R and EAD_2 should be substituted with their values before evaluation. I.e., if ID_CRED_R = { 4 : h'' } and EAD_2 is omitted then << ID_CRED_R, ? EAD_2 >> = << { 4 : h'' } >>, which encodes to 0x43a10440. We also make use of the occurrance symbol "\*", like in e.g.,  2* int, meaning two or more CBOR integers.

For a complete specification and more examples, see {{RFC8949}} and {{RFC8610}}. We recommend implementors to get used to CBOR by using the CBOR playground {{CborMe}}.

~~~~~~~~~~~~~~~~~~~~~~~
Diagnostic          Encoded              Type
------------------------------------------------------------------
1                   0x01                 unsigned integer
24                  0x1818               unsigned integer
-24                 0x37                 negative integer
-25                 0x3818               negative integer
true                0xf5                 simple value
h''                 0x40                 byte string
h'12cd'             0x4212cd             byte string
'12cd'              0x4431326364         byte string
"12cd"              0x6431326364         text string
{ 4 : h'cd' }       0xa10441cd           map
<< 1, 2, true >>    0x430102f5           byte string
[ 1, 2, true ]      0x830102f5           array
( 1, 2, true )      0x0102f5             sequence
1, 2, true          0x0102f5             sequence
------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}

## CDDL Definitions

This sections compiles the CDDL definitions for ease of reference.

~~~~~~~~~~~ CDDL
suites = [ 2* int ] / int

ead = 1* (
  ead_label : int,
  ead_value : bstr,
)

message_1 = (
  METHOD : int,
  SUITES_I : suites,
  G_X : bstr,
  C_I : bstr / -24..23,
  ? EAD_1 : ead,
)

message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
  C_R : bstr / -24..23,
)

message_3 = (
  CIPHERTEXT_3 : bstr,
)

message_4 = (
  CIPHERTEXT_4 : bstr,
)

error = (
  ERR_CODE : int,
  ERR_INFO : any,
)

info = (
  label : tstr,
  context : bstr,
  length : uint,
)
~~~~~~~~~~~

## COSE {#COSE}

CBOR Object Signing and Encryption (COSE) {{I-D.ietf-cose-rfc8152bis-struct}} describes how to create and process signatures, message authentication codes, and encryption using CBOR. COSE builds on JOSE, but is adapted to allow more efficient processing in constrained devices. EDHOC makes use of COSE_Key, COSE_Encrypt0, and COSE_Sign1 objects in the message processing:

* ECDH ephemeral public keys of type EC2 or OKP in message_1 and message_2 consist of the COSE_Key parameter named 'x', see Section 7.1 and 7.2 of {{I-D.ietf-cose-rfc8152bis-algs}}

* The ciphertexts in message_3 and message_4 consist of a subset of the single recipient encrypted data object COSE_Encrypt0, which is described in Sections 5.2-5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}. The ciphertext is computed over the plaintext and associated data, using an encryption key and an initialization vector. The associated data is an Enc_structure consisting of protected headers and externally supplied data (external_aad). COSE constructs the input to the AEAD {{RFC5116}} for message_i (i = 3 or 4, see {{m3}} and {{m4}}, respectively) as follows:

   * Secret key K = K_i
   * Nonce N = IV_i
   * Plaintext P for message_i
   * Associated Data A = \[ "Encrypt0", h'', TH_i \]

* Signatures in message_2 of method 0 and 2, and in message_3 of method 0 and 1, consist of a subset of the single signer data object COSE_Sign1, which is described in Sections 4.2-4.4 of {{I-D.ietf-cose-rfc8152bis-struct}}. The signature is computed over a Sig_structure containing payload, protected headers and externally supplied data (external_aad) using a private signature key and verified using the corresponding public signature key. For COSE_Sign1, the message to be signed is:

       [ "Signature1", protected, external_aad, payload ]

    where protected, external_aad and payload are specified in {{m2}} and {{m3}}.

Different header parameters to identify X.509 or C509 certificates by reference are defined in {{I-D.ietf-cose-x509}} and {{I-D.ietf-cose-cbor-encoded-cert}}:

* by a hash value with the 'x5t' or 'c5t' parameters, respectively:

   * ID_CRED_x = { 34 : COSE_CertHash }, for x = I or R,

   * ID_CRED_x = { TBD3 : COSE_CertHash }, for x = I or R;

* or by a URI with the 'x5u' or 'c5u' parameters, respectively:

   * ID_CRED_x = { 35 : uri }, for x = I or R,

   * ID_CRED_x = { TBD4 : uri }, for x = I or R.

When ID_CRED_x does not contain the actual credential, it may be very short, e.g., if the endpoints have agreed to use a key identifier parameter 'kid':

* ID_CRED_x = { 4 : key_id_x }, where key_id_x : kid, for x = I or R.

Note that a COSE header map can contain several header parameters, for example { x5u, x5t } or { kid, kid_context }.

ID_CRED_x MAY also identify the credential by value. For example, a certificate chain can be transported in ID_CRED_x with COSE header parameter c5c or x5chain, defined in {{I-D.ietf-cose-cbor-encoded-cert}} and {{I-D.ietf-cose-x509}} and credentials of type CWT and CCS can be transported with the COSE header parameters registered in {{cwt-header-param}}.


# Authentication Related Verifications {#auth-validation}

EDHOC performs certain authentication related operations, see {{auth-key-id}}, but in general it is necessary to make additional verifications beyond EDHOC message processing. What verifications are needed depend on the deployment, in particular the trust model and the security policies, but most commonly it can be expressed in terms of verifications of credential content.

 EDHOC assumes the existence of mechanisms (certification authority or other trusted third party, pre-provisioning, etc.) for generating and distributing authentication credentials and other credentials, as well as the existence of trust anchors (CA certificates, trusted public keys, etc.). For example, a public key certificate or CWT may rely on a trusted third party whose public key is pre-provisioned, whereas a CCS or a self-signed certificate/CWT may be used when trust in the public key can be achieved by other means, or in the case of trust-on-first-use, see {{tofu}}.

In this section we provide some examples of such verifications. These verifications are the responsibility of the application but may be implemented as part of an EDHOC library.


## Validating the Authentication Credential {#validating-auth-credential}

The authentication credential may contain, in addition to the authentication key, other parameters that needs to be verified. For example:

* In X.509 and C509 certificates, signature keys typically have key usage "digitalSignature" and Diffie-Hellman public keys typically have key usage "keyAgreement" {{RFC3279}}{{RFC8410}}.

* In X.509 and C509 certificates validity is expressed using Not After and Not Before. In CWT and CCS, the “exp” and “nbf” claims have similar meanings.



## Identities {#identities}

The application must decide on allowing a connection or not depending on the intended endpoint, and in particular whether it is a specific identity or a set of identities. To prevent misbinding attacks, the identity of the endpoint is included in a MAC verified through the protocol. More details and examples are provided in this section.

Policies for what connections to allow are typically set based on the identity of the other endpoint, and endpoints typically only allow connections from a specific identity or a small restricted set of identities. For example, in the case of a device connecting to a network, the network may only allow connections from devices which authenticate with certificates having a particular range of serial numbers and signed by a particular CA. Conversely, a device may only be allowed to connect to a network which authenticates with a particular public key.

* When a Public Key Infrastructure (PKI) is used with certificates, the identity is the subject whose unique name, e.g., a domain name, a Network Access Identifier (NAI), or an Extended Unique Identifier (EUI), is included in the endpoint's certificate.

* Similarly, when a PKI is used with CWTs, the identity is the subject identified by the relevant claim(s), such as 'sub' (subject).

* When PKI is not used (e.g., CCS, self-signed certificate/CWT) the identity is typically directly associated to the authentication key of the other party. For example, if identities can be expressed in the form of unique subject names assigned to public keys, then a binding to identity is achieved by including both public key and associated subject name in the authentication credential: CRED_I or CRED_R may be a self-signed certificate/CWT or CCS containing the authentication key and the subject name, see {{auth-cred}}. Each endpoint thus needs to know the specific authentication key/unique associated subject name, or set of public authentication keys/unique associated subject names, which it is allowed to communicate with.

To prevent misbinding attacks in systems where an attacker can register public keys without proving knowledge of the private key, SIGMA {{SIGMA}} enforces a MAC to be calculated over the "identity". EDHOC follows SIGMA by calculating a MAC over the whole authentication credential, which in case of an X.509 or C509 certificate includes the "subject" and "subjectAltName" fields, and in the case of CWT or CCS includes the "sub" claim.

(While the SIGMA paper only focuses on the identity, the same principle is true for other information such as policies associated to the public key.)

## Certification Path and Trust Anchors {#cert-path}

When a Public Key Infrastructure (PKI) is used with certificates, the trust anchor is a Certification Authority (CA) certificate. Each party needs at least one CA public key certificate, or just the CA public key. The certification path contains proof that the subject of the certificate owns the public key in the certificate. Only validated public-key certificates are to be accepted.

Similarly, when a PKI is used with CWTs, each party needs to have at least one trusted third party public key as trust anchor to verify the end entity CWTs. The trusted third party public key can, e.g., be stored in a self-signed CWT or in a CCS.

The signature of the authentication credential needs to be verified with the public key of the issuer. X.509 and C509 certificates includes the “Issuer” field. In CWT and CCS, the “iss” claim has a similar meaning. The public key is either a trust anchor or the public key in another valid and trusted credential in a certification path from trust anchor to authentication credential.

Similar verifications as made with the authentication credential (see {{validating-auth-credential}}) are also needed for the other credentials in the certification path.

When PKI is not used (CCS, self-signed certificate/CWT), the trust anchor is the authentication key of the other party, in which case there is no certification path.


## Revocation Status {#revocation}

The application may need to verify that the credentials are not revoked, see {{impl-cons}}. Some use cases may be served by short-lived credentials, for example, where the validity of the credential is on par with the interval between revocation checks. But, in general, credential lifetime and revocation checking are complementary measures to control credential status. Revocation information may be transported as External Authentication Data (EAD), see {{ead-appendix}}.


## Trust-on-first-use {#tofu}

TBD


# Use of External Authorization Data {#ead-appendix}

In order to reduce the number of messages and round trips, or to simplify processing, external security applications may be integrated into EDHOC by transporting external authorization related data (EAD) in the messages.

The EAD format is specified in {{AD}}, this section contains examples and further details of how EAD may be used with an appropriate accompanying specification.

* One example is third party assisted authorization, requested with EAD_1, and an authorization artifact (“voucher”, cf. {{RFC8366}}) returned in EAD_2, see {{I-D.selander-ace-ake-authz}}.

* Another example is remote attestation, requested in EAD_2, and an Entity Attestation Token (EAT, {{I-D.ietf-rats-eat}}) returned in EAD_3.

* A third example is certificate enrolment, where a Certificate Signing Request (CSR, {{RFC2986}}) is included EAD_3, and the issued public key certificate (X.509 {{RFC5280}}, C509 {{I-D.ietf-cose-cbor-encoded-cert}}) or a reference thereof is returned in EAD_4.

External authorization data should be considered unprotected by EDHOC, and the protection of EAD is the responsibility of the security application (third party authorization, remote attestation, certificate enrolment, etc.). The security properties of the EAD fields (after EDHOC processing) are discussed in {{sec-prop}}.

The content of the EAD field may be used in the EDHOC processing of the message in which they are contained. For example, authentication related information like assertions and revocation information, transported in EAD fields may provide input about trust anchors or validity of credentials relevant to the authentication processing. The EAD fields (like ID_CRED fields) are therefore made available to the application before the message is verified, see details of message processing in {{asym}}. In the first example above, a voucher in EAD_2 made available to the application can enable the Initiator to verify the identity or public key of the Responder before verifying the signature. An application allowing EAD fields containing authentication information thus may need to handle authentication related verifications associated with EAD processing.

Conversely, the security application may need to wait for EDHOC message verification to complete. In the third example above, the validation of a CSR carried in EAD_3 is not started by the Responder before EDHOC has successfully verified message_3 and proven the possession of the private key of the Initiator.

The security application may reuse EDHOC protocol fields which therefore need to be available to the application. For example, the security application may use the same crypto algorithms as in the EDHOC session and therefore needs access to the selected cipher suite (or the whole SUITES_I). The application may use the ephemeral public keys G_X and G_Y, as ephemeral keys or as nonces, see {{I-D.selander-ace-ake-authz}}.

The processing of (ead_label, ead_value) by the security application needs to be described in the specification where the ead_label is registered, see {{iana-ead}}, including the ead_value for each message and actions in case of errors. An application may support multiple security applications that make use of EAD, which may result in multiple (ead_label, ead_value) pairs in one EAD field, see {{AD}}. Any dependencies on security applications with previously registered EAD fields needs to be documented, and the processing needs to consider their simultaneous use.

Since data carried in EAD may not be protected, or be processed by the application before the EDHOC message is verified, special considerations need to be made such that it does not violate security and privacy requirements of the service which uses this data, see {{unprot-data}}. The content in an EAD field may impact the security properties provided by EDHOC. Security applications making use of the EAD fields must perform the necessary security analysis.


# Application Profile Example {#appl-temp}

This appendix contains a rudimentary example of an application profile, see {{applicability}}.

For use of EDHOC with application X the following assumptions are made:

1. Transfer in CoAP as specified in {{coap}} with requests expected by the CoAP server (= Responder) at /app1-edh, no Content-Format needed.
2. METHOD = 1 (I uses signature key, R uses static DH key.)
3. CRED_I is an IEEE 802.1AR IDevID encoded as a C509 certificate of type 0 {{I-D.ietf-cose-cbor-encoded-cert}}.
    * R acquires CRED_I out-of-band, indicated in EAD_1.
    * ID_CRED_I = {4: h''} is a 'kid' with value empty CBOR byte string.
4. CRED_R is a CCS of type OKP as specified in {{auth-cred}}.
   * The CBOR map has parameters 1 (kty), -1 (crv), and -2 (x-coordinate).
   * ID_CRED_R is {TBD2 : CCS}.   Editor's note: TBD2 is the COSE header parameter value of 'kccs', see {{cwt-header-param}}
5. External authorization data is defined and processed as specified in {{I-D.selander-ace-ake-authz}}.
6. EUI-64 is used as the identity of the endpoint (see example in {{auth-cred}}).
7. No use of message_4: the application sends protected messages from R to I.


# EDHOC Message Deduplication {#duplication}

EDHOC by default assumes that message duplication is handled by the transport, in this section exemplified with CoAP.

Deduplication of CoAP messages is described in Section 4.5 of {{RFC7252}}. This handles the case when the same Confirmable (CON) message is received multiple times due to missing acknowledgement on CoAP messaging layer. The recommended processing in {{RFC7252}} is that the duplicate message is acknowledged (ACK), but the received message is only processed once by the CoAP stack.

Message deduplication is resource demanding and therefore not supported in all CoAP implementations. Since EDHOC is targeting constrained environments, it is desirable that EDHOC can optionally support transport layers which do not handle message duplication. Special care is needed to avoid issues with duplicate messages, see {{proc-outline}}.

The guiding principle here is similar to the deduplication processing on CoAP messaging layer: a received duplicate EDHOC message SHALL NOT result in another instance of the next EDHOC message. The result MAY be that a duplicate next EDHOC message is sent, provided it is still relevant with respect to the current protocol state. In any case, the received message MUST NOT be processed more than once in the same EDHOC session. This is called "EDHOC message deduplication".

An EDHOC implementation MAY store the previously sent EDHOC message to be able to resend it.

In principle, if the EDHOC implementation would deterministically regenerate the identical EDHOC message previously sent, it would be possible to instead store the protocol state to be able to recreate and resend the previously sent EDHOC message. However, even if the protocol state is fixed, the message generation may introduce differences which compromises security. For example, in the generation of message_3, if I is performing a (non-deterministic) ECDSA signature (say, method 0 or 1, cipher suite 2 or 3) then PLAINTEXT_3 is randomized, but K_3 and IV_3 are the same, leading to a key and nonce reuse.

The EDHOC implementation MUST NOT store previous protocol state and regenerate an EDHOC message if there is a risk that the same key and IV are used for two (or more) distinct messages.

The previous message or protocol state MUST NOT be kept longer than what is required for retransmission, for example, in the case of CoAP transport, no longer than the EXCHANGE_LIFETIME (see Section 4.8.2 of {{RFC7252}}).

# Transports Not Natively Providing Correlation

Protocols that do not natively provide full correlation between a series of messages can send the C_I and C_R identifiers along as needed.

The transport over CoAP ({{coap}}) can serve as a blueprint for other server-client protocols:
The client prepends the C_x which the server selected (or, for message_1, the CBOR simple value `true` which is not a valid C_x) to any request message it sends.
The server does not send any such indicator, as responses are matched to request by the client-server protocol design.

Protocols that do not provide any correlation at all can prescribe prepending of the peer's chosen C_x to all messages.

<!--
Protocols that can provide all the necessary correlation but do not have any short-lived component to it
may need ... no, they don't need anything special: after an error, the next thing is a message 1 again.
-->

# Large message_2

By design of encryption of message_2, if the EDHOC hash algorithm is SHA-2 then HKDF-Expand is used which limits the size of plaintext that can be encrypted to 255 * hash_length, where hash_length is the length of the output of the EDHOC hash algorithm given by the cipher suite. For example, with SHA-256 as EDHOC hash algorithm the length of the hash output is 32 bytes and the maximum length of PLAINTEXT_2 is 255 * 32 = 8160 bytes.

While message_2 is expected to be much smaller than 8 kB for the intended use cases, it seems nevertheless prudent to provide alternative solutions for the event that this should turn out to be a limitation.

One simple solution is to use a cipher suite with a different hash function. In particular, the use of KMAC removes all practical limitations in this respect.

Another solution is make use of multiple invocations of HKDF-Expand, as specified in the remainder of this section:

Split PLAINTEXT_2 in parts P(i) of size equal to M = 255 \* hash_length, except the last part P(last) which has size \<= M.

~~~~~~~~~~~
PLAINTEXT_2 = P(0) | P(1) | ... | P(last)
~~~~~~~~~~~

where \| indicates concatenation. Define a matching keystream

~~~~~~~~~~~
KEYSTREAM_2 = OKM(0) | OKM(1)  | ... | OKM(last)
~~~~~~~~~~~

where

~~~~~~~~~~~
OKM(i) = EDHOC-KDF( PRK_2e, -i, TH_2, length(P(i)) )
~~~~~~~~~~~

Note that if PLAINTEXT_2 \<= M then P(0) = PLAINTEXT_2 and the definition of KEYSTREAM_2 = OKM(0) coincides with {{fig-edhoc-kdf}}.

An application profile may specify if it supports this method to handle large message_2.

Editor's note: This variant requires the type of KDF label to be changed from uint to int.


# Change Log

RFC Editor: Please remove this appendix.


* From -13 to -14
  * Merge of section 1.1 and 1.2
  * Connection and key identifiers restricted to be byte strings
  * Representation of byte strings as one-byte CBOR ints (-24..23)
  * Simplified mapping between EDHOC and OSCORE identifiers
  * Rewrite of 3.5
     * Clarification of authentication related operations performed by EDHOC
     * Authentication related verifications, including old section 3.5.1, moved to new appendix D
  * Rewrite of 3.8
     * Move content about use of EAD to new appendix E
     * ead_value changed to bstr
  * EDHOC-KDF updated
     * transcript_hash argument removed
     * TH included in context argument
     * label argument is now type uint, all labels replaced
  * Key schedule updated
     * New salts derived to avoid reuse of same key with expand and extract
     * PRK_4x3m renamed PRK_4e3m
     * K_4 and IV_4 derived from PRK_4e3m
     * New PRK: PRK_out derived from PRK_4e3m and TH_4
     * Clarified main output of EDHOC is the shared secret PRK_out
     * Exporter defined by EDHOC-KDF and new PRK PRK_exporter derived from PRK_out
     * Key update defined by Expand instead of Extract
  * All applications of EDHOC-KDF in one place
  * Update of processing
    * EAD and ID_CRED passed to application when available
    * identity verification and credential retrieval omitted in protocol description
    * Transcript hash defined by plaintext messages instead of ciphertext
    * Changed order of input to TH_2
    * Removed general G_X checking against selfie-attacks
  * Support for padding of plaintext
  * Updated compliance requirements
  * Updated security considerations
    * Updated and more clear requirements on MAC length
    * Clarification of key confirmation
    * Forbid use of same key for signature and static DH
  * Updated appendix on message deduplication
  * Clarifications of
     * connection identifiers
     * cipher suites, including negotiation
     * EAD
     * Error messages
  * Updated media types
  * Applicability template renamed application profile
  * Editorials

* From -12 to -13
   * no changes

* From -12:
  * Shortened labels to derive OSCORE key and salt
  * ead_value changed to bstr
  * Removed general G_X checking against selfie-attacks
  * Updated and more clear requirements on MAC length
  * Clarifications from Kathleen, Stephen, Marco, Sean, Stefan,
  * Authentication Related Verifications moved to appendix
  * Updated MTI section and cipher suite
  * Updated security considerations

* From -11 to -12:
  * Clarified applicability to KEMs
  * Clarified use of COSE header parameters
  * Updates on MTI
  * Updated security considerations
  * New section on PQC
  * Removed duplicate definition of cipher suites
  * Explanations of use of COSE moved to Appendix C.3
  * Updated internal references

* From -10 to -11:
  * Restructured section on authentication parameters
  * Changed UCCS to CCS
  * Changed names and description of COSE header parameters for CWT/CCS
  * Changed several of the KDF and Exporter labels
  * Removed edhoc_aead_id from info (already in transcript_hash)
  * Added MTI section
  * EAD: changed CDDL names and added value type to registry
  * Updated Figures 1, 2, and 3
  * Some correction and clarifications
  * Added core.edhoc to CoRE Resource Type registry

* From -09 to -10:
   * SUITES_I simplified to only contain the selected and more preferred suites
   * Info is a CBOR sequence and context is a bstr
   * Added kid to UCCS example
   * Separate header parameters for CWT and UCCS
   * CWT Confirmation Method kid extended to bstr / int

* From -08 to -09:
   * G_Y and CIPHERTEXT_2 are now included in one CBOR bstr
   * MAC_2 and MAC_3 are now generated with EDHOC-KDF
   * Info field “context” is now general and explicit in EDHOC-KDF
   * Restructured Section 4, Key Derivation
   * Added EDHOC MAC length to cipher suite for use with static DH
   * More details on the use of CWT and UCCS
   * Restructured and clarified Section 3.5, Authentication Parameters
   * Replaced 'kid2' with extension of 'kid'
   * EAD encoding now supports multiple ead types in one message
   * Clarified EAD type
   * Updated message sizes
   * Replaced “perfect forward secrecy” with “forward secrecy”
   * Updated security considerations
   * Replaced prepended 'null' with 'true' in the CoAP transport of message_1
   * Updated CDDL definitions
   * Expanded on the use of COSE


* From -07 to -08:
   * Prepended C_x moved from the EDHOC protocol itself to the transport mapping
   * METHOD_CORR renamed to METHOD, corr removed
   * Removed bstr_identifier and use bstr / int instead; C_x can now be int without any implied bstr semantics
   * Defined COSE header parameter 'kid2' with value type bstr / int for use with ID_CRED_x
   * Updated message sizes
   * New cipher suites with AES-GCM and ChaCha20 / Poly1305
   * Changed from one- to two-byte identifier of CNSA compliant suite
   * Separate sections on transport and connection id with further sub-structure
   * Moved back key derivation for OSCORE from draft-ietf-core-oscore-edhoc
   * OSCORE and CoAP specific processing moved to new appendix
   * Message 4 section moved to message processing section


* From -06 to -07:
   * Changed transcript hash definition for TH_2 and TH_3
   * Removed "EDHOC signature algorithm curve" from cipher suite
   * New IANA registry "EDHOC Exporter Label"
   * New application defined parameter "context" in EDHOC-Exporter
   * Changed normative language for failure from MUST to SHOULD send error
   * Made error codes non-negative and 0 for success
   * Added detail on success error code
   * Aligned terminology "protocol instance" ->  "session"
   * New appendix on compact EC point representation
   * Added detail on use of ephemeral public keys
   * Moved key derivation for OSCORE to draft-ietf-core-oscore-edhoc
   * Additional security considerations
   * Renamed "Auxililary Data" as "External Authorization Data"
   * Added encrypted EAD_4 to message_4

* From -05 to -06:
   * New section 5.2 "Message Processing Outline"
   * Optional inital byte C_1 = null in message_1
   * New format of error messages, table of error codes, IANA registry
   * Change of recommendation transport of error in CoAP
   * Merge of content in 3.7 and appendix C into new section 3.7 "Applicability Statement"
   * Requiring use of deterministic CBOR
   * New section on message deduplication
   * New appendix containin all CDDL definitions
   * New appendix with change log
   * Removed section "Other Documents Referencing EDHOC"
   * Clarifications based on review comments


* From -04 to -05:
   * EDHOC-Rekey-FS -> EDHOC-KeyUpdate
   * Clarification of cipher suite negotiation
   * Updated security considerations
   * Updated test vectors
   * Updated applicability statement template


* From -03 to -04:
   * Restructure of section 1
   * Added references to C509 Certificates
   * Change in CIPHERTEXT_2 -> plaintext XOR KEYSTREAM_2 (test vector not updated)
   * "K_2e", "IV_2e" -> KEYSTREAM_2
   * Specified optional message 4
   * EDHOC-Exporter-FS -> EDHOC-Rekey-FS
   * Less constrained devices SHOULD implement both suite 0 and 2
   * Clarification of error message
   * Added exporter interface test vector

* From -02 to -03:
   * Rearrangements of section 3 and beginning of section 4
   * Key derivation new section 4
   * Cipher suites 4 and 5 added
   * EDHOC-EXPORTER-FS - generate a new PRK_4x3m from an old one
   * Change in CIPHERTEXT_2 -> COSE_Encrypt0 without tag (no change to test vector)
   * Clarification of error message
   * New appendix C applicability statement


* From -01 to -02:
   * New section 1.2 Use of EDHOC
   * Clarification of identities
   * New section 4.3 clarifying bstr_identifier
   * Updated security considerations
   * Updated text on cipher suite negotiation and key confirmation
   * Test vector for static DH

* From -00 to -01:
   * Removed PSK method
   * Removed references to certificate by value



# Acknowledgments
{: numbered="no"}

The authors want to thank
{{{Christian Amsüss}}},
{{{Alessandro Bruni}}},
{{{Karthikeyan Bhargavan}}},
{{{Carsten Bormann}}},
{{{Timothy Claeys}}},
{{{Martin Disch}}},
{{{Stephen Farrell}}},
{{{Loïc Ferreira}}},
{{{Theis Grønbech Petersen}}},
{{{Felix Günther}}},
{{{Dan Harkins}}},
{{{Klaus Hartke}}},
{{{Russ Housley}}},
{{{Stefan Hristozov}}},
{{{Marc Ilunga}}},
{{{Charlie Jacomme}}},
{{{Elise Klein}}},
{{{Steve Kremer}}},
{{{Alexandros Krontiris}}},
{{{Ilari Liusvaara}}},
{{{Kathleen Moriarty}}},
{{{David Navarro}}},
{{{Karl Norrman}}},
{{{Salvador Pérez}}},
{{{Maïwenn Racouchot}}},
{{{Eric Rescorla}}},
{{{Michael Richardson}}},
{{{Thorvald Sahl Jørgensen}}},
{{{Jim Schaad}}},
{{{Carsten Schürmann}}},
{{{Ludwig Seitz}}},
{{{Stanislav Smyshlyaev}}},
{{{Valery Smyslov}}},
{{{Peter van der Stok}}},
{{{Rene Struik}}},
{{{Vaishnavi Sundararajan}}},
{{{Erik Thormarker}}},
{{{Marco Tiloca}}},
{{{Sean Turner}}},
{{{Michel Veillette}}},
and
{{{Mališa Vučinić}}}
for reviewing and commenting on intermediate versions of the draft. We are especially indebted to {{{Jim Schaad}}} for his continuous reviewing and implementation of different versions of the draft.

Work on this document has in part been supported by the H2020 project SIFIS-Home (grant agreement 952652).

--- fluff
