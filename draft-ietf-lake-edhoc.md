---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-ietf-lake-edhoc-latest

ipr: trust200902
cat: std

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Preuß Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        email: francesca.palombini@ericsson.com

        
normative:

  RFC2119:
  RFC5116:
  RFC5869:
  RFC6090:
  RFC6979:
  RFC7252:
  RFC7748:
  RFC8949:
  RFC7959:
  RFC8152:
  RFC8174:
  RFC8376:
  RFC8610:
  RFC8613:
  RFC8724:
  RFC8742:
  I-D.ietf-cose-x509:
  I-D.ietf-core-echo-request-tag:
  I-D.ietf-lake-reqs:

informative:

  RFC7228:
  RFC7258:
  RFC7296:
  RFC8446:
  RFC8937:
  I-D.ietf-6tisch-dtsecurity-zerotouch-join:
  I-D.ietf-core-resource-directory:
  I-D.ietf-lwig-security-protocol-comparison:
  I-D.ietf-tls-dtls13:
  I-D.selander-ace-ake-authz:
  I-D.palombini-core-oscore-edhoc:
  I-D.mattsson-cose-cbor-cert-compress:
  I-D.mattsson-cfrg-det-sigs-with-noise:

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
 
  SIGMA:
    target: http://webee.technion.ac.il/~hugo/sigma-pdf.pdf
    title: SIGMA - The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols (Long version)
    author:
      -
        ins: H. Krawczyk
    date: June 2003
    
  CNSA:
    target: https://apps.nsa.gov/iaarchive/programs/iad-initiatives/cnsa-suite.cfm
    title: Commercial National Security Algorithm Suite
    author:
      -
        ins: (Placeholder)
    date: August 2015
    
  LoRa1:
    target: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6021899/pdf/sensors-18-01833.pdf
    title: Enhancing LoRaWAN Security through a Lightweight and Authenticated Key Management Approach
    author:
      -
        ins: R. Sanchez-Iborra
      -
        ins: J. Sánchez-Gómez
      -
        ins: S. Pérez
      -
        ins: P.J. Fernández
      -
        ins: J. Santa
      -
        ins: J.L. Hernández-Ramos
      -
        ins: A.F. Skarmeta
    date: June 2018

  LoRa2:
    target: https://ants.inf.um.es/~josesanta/doc/GIoTS1.pdf
    title: Internet Access for LoRaWAN Devices Considering Security Issues
    author:
      -
        ins: R. Sanchez-Iborra
      -
        ins: J. Sánchez-Gómez
      -
        ins: S. Pérez
      -
        ins: P.J. Fernández
      -
        ins: J. Santa
      -
        ins: J.L. Hernández-Ramos
      -
        ins: A.F. Skarmeta
    date: June 2018

  Kron18:
    target: https://www.nada.kth.se/~ann/exjobb/alexandros_krontiris.pdf
    title: Evaluation of Certificate Enrollment over Application Layer Security
    author:
      -
        ins: A. Krontiris
    date: May 2018

  SSR18:
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

  Perez18:
    target: http://www.anastacia-h2020.eu/publications/Architecture_of_security_association_establishment_based_on_bootstrapping_technologies_for_enabling_critical_IoT_infrastructures.pdf
    title: Architecture of security association establishment based on bootstrapping technologies for enabling critical IoT K
    author:
      -
        ins: S. Pérez
      -
        ins: D. Garcia-Carrillo
      -
        ins: R. Marín-López
      -
        ins: J. Hernández-Ramos
      -
        ins: R. Marín-Pérez
      -
        ins: A. Skarmeta
    date: October 2018
    
  CborMe:
    target: http://cbor.me/
    title: CBOR Playground
    author:
      -
        ins: C. Bormann
    date: May 2018

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a very compact and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys. EDHOC provides mutual authentication, perfect forward secrecy, and identity protection. EDHOC is intended for usage in constrained scenarios and a main use case is to establish an OSCORE security context. By reusing COSE for cryptography, CBOR for encoding, and CoAP for transport, the additional code size can be kept very low.

--- middle

# Introduction

## Motivation 

Many Internet of Things (IoT) deployments require technologies which are highly performant in constrained environments {{RFC7228}}. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and power. The connectivity for these settings may also exhibit constraints such as unreliable and lossy channels, highly restricted bandwidth, and dynamic topology. The IETF has acknowledged this problem by standardizing a range of lightweight protocols and enablers designed for the IoT, including the Constrained Application Protocol (CoAP, {{RFC7252}}), Concise Binary Object Representation (CBOR, {{RFC8949}}), and Static Context Header Compression (SCHC, {{RFC8724}}).

The need for special protocols targeting constrained IoT deployments extends also to the security domain {{I-D.ietf-lake-reqs}}. Important characteristics in constrained environments are the number of round trips and protocol message sizes, which if kept low can contribute to good performance by enabling transport over a small number of radio frames, reducing latency due to fragmentation or duty cycles, etc. Another important criteria is code size, which may be prohibitive for certain deployments due to device capabilities or network load during firmware update. Some IoT deployments also need to support a variety of underlying transport technologies, potentially even with a single connection.

Some security solutions for such settings exist already. CBOR Object Signing and Encryption (COSE) {{RFC8152}} specifies basic application-layer security services efficiently encoded in CBOR. Another example is Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} which is a lightweight communication security extension to CoAP using CBOR and COSE. In order to establish good quality cryptographic keys for security protocols such as COSE and OSCORE, the two endpoints may run an authenticated key exchange protocol, from which shared secret key material can be derived. Such a key exchange protocol should also be lightweight; to prevent bad performance in case of repeated use, e.g., due to device rebooting or frequent rekeying for security reasons; or to avoid latencies in a network formation setting with many devices authenticating at the same time.

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a lightweight authenticated key exchange protocol providing good security properties including perfect forward secrecy, identity protection, and cipher suite negotation. Authentication can be based on raw public keys (RPK) or public key certificates, and requires the application to provide input on how to verify that endpoints are trusted. This specificaton focuses on referencing instead of transporting credentials to reduce message overhead.

EDHOC makes use of known protocol constructions, such as SIGMA {{SIGMA}} and Extract-and-Expand {{RFC5869}}. COSE also provides crypto agility and enables the use of future algorithms targeting IoT.

## Use of EDHOC

EDHOC is designed for highly constrained settings making it especially suitable for low-power wide area networks {{RFC8376}} such as Cellular IoT, 6TiSCH, and LoRaWAN. A main objective for EDHOC is to be a lightweight AKE for OSCORE, i.e. to provide authentication and session key establishment for IoT use cases such as those built on CoAP {{RFC7252}}. CoAP is a specialized web transfer protocol for use with constrained nodes and networks, providing a request/response interaction model between application endpoints. As such, EDHOC is targeting a large variety of use cases involving 'things' with embedded microcontrollers, sensors, and actuators.

A typical setting is when one of the endpoints is constrained or in a constrained network, and the other endpoint is a node on the Internet (such as a mobile phone) or at the edge of the constrained network (such as a gateway). Thing-to-thing interactions over constrained networks are also relevant since both endpoints would then benefit from the lightweight properties of the protocol. EDHOC could e.g. be run when a device/device(s) connect(s) for the first time, or to establish fresh keys which are not revealed by a later compromise of the long-term keys. Further security properties are described in {{sec-prop}}.

EDHOC builds on the same lightweight primitives as OSCORE: CBOR for encoding, COSE for cryptography, and CoAP for transport. By reusing existing libraries the additional code size can be kept very low. EDHOC is not bound to a particular transport, but it is recommended to transfer EDHOC messages in CoAP payloads.

## Message Size Examples

Compared to the DTLS 1.3 handshake {{I-D.ietf-tls-dtls13}} with ECDHE and connection ID, the number of bytes in EDHOC + CoAP can be less than 1/6 when RPK authentication is used, see {{I-D.ietf-lwig-security-protocol-comparison}}. {{fig-sizes}} shows two examples of message sizes for EDHOC with different kinds of authentication keys and different COSE header parameters for identification: static Diffie-Hellman keys identified by 'kid' {{RFC8152}}, and X.509 signature certificates identified by a hash value using 'x5t' {{I-D.ietf-cose-x509}}. 

~~~~~~~~~~~~~~~~~~~~~~~
=================================
                    kid       x5t                     
---------------------------------
message_1            37        37                     
message_2            46       117       
message_3            20        91        
---------------------------------
Total               103       245      
=================================
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-sizes title="Example of message sizes in bytes." artwork-align="center"}

## Document Structure

The remainder of the document is organized as follows: {{background}} outlines EDHOC authenticated with digital signatures, {{overview}} describes the protocol elements of EDHOC, including message flow, and formatting of the ephemeral public keys, {{key-der}} describes the key derivation, {{asym}} specifies EDHOC with authentication based on signature keys or static Diffie-Hellman keys, {{error}} specifies the EDHOC error message, and {{transfer}} describes how EDHOC can be transferred in CoAP and used to establish an OSCORE security context.


## Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

Readers are expected to be familiar with the terms and concepts described in CBOR {{RFC8949}}, CBOR Sequences {{RFC8742}}, COSE {{RFC8152}}, and CDDL {{RFC8610}}. The Concise Data Definition Language (CDDL) is used to express CBOR data structures {{RFC8949}}. Examples of CBOR and CDDL are provided in {{CBOR}}.

The single output from authenticated encryption (including the authentication tag) is called 'ciphertext', following {{RFC5116}}.


# EDHOC Outline {#background}

EDHOC specifies different authentication methods of the Diffie-Hellman key exchange: digital signatures and static Diffie-Hellman keys. This section outlines the digital signature based method. Further details of protocol elements and other authentication methods are provided in the remainder of this document.

SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 {{RFC7296}} and (D)TLS 1.3 {{RFC8446}}, EDHOC authenticated with digital signatures is built on a variant of the SIGMA protocol which provide identity protection of the initiator (SIGMA-I), and like IKEv2 {{RFC7296}}, EDHOC implements the SIGMA-I variant as MAC-then-Sign. The SIGMA-I protocol using an authenticated encryption algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Initiator                                               Responder
   |                          G_X                            |
   +-------------------------------------------------------->|
   |                                                         |
   |  G_Y, AEAD( K_2; ID_CRED_R, Sig(R; CRED_R, G_X, G_Y) )  |
   |<--------------------------------------------------------+
   |                                                         |
   |     AEAD( K_3; ID_CRED_I, Sig(I; CRED_I, G_Y, G_X) )    |
   +-------------------------------------------------------->|
   |                                                         |
~~~~~~~~~~~
{: #fig-sigma title="Authenticated encryption variant of the SIGMA-I protocol."}
{: artwork-align="center"}

The parties exchanging messages are called Initiator (I) and Responder (R). They exchange ephemeral public keys, compute the shared secret, and derive symmetric application keys. 

* G_X and G_Y are the ECDH ephemeral public keys of I and R, respectively.

* CRED_I and CRED_R are the credentials containing the public authentication keys of I and R, respectively.

* ID_CRED_I and ID_CRED_R are data enabling the recipient party to retrieve the credential of I and R, respectively.

* Sig(I; . ) and S(R; . ) denote signatures made with the private authentication key of I and R, respectively.

* AEAD(K; . ) denotes authenticated encryption with additional data using a key K derived from the shared secret.

In order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit connection identifiers C_I, C_R chosen by I and R, respectively, enabling the recipient to find the protocol state.

* Transcript hashes (hashes of message data) TH_2, TH_3, TH_4 used for key derivation and as additional authenticated data.

* Computationally independent keys derived from the ECDH shared secret and used for authenticated encryption of different messages.

* An optional fouth flight giving explicit key confirmation to I in deployments where no application data is send from R to I.

* A key material exporter and a key update function enabling frequent forward secrecy.

* Verification of a common preferred cipher suite:

   * The Initiator lists supported cipher suites in order of preference
   
   * The Responder verifies that the selected cipher suite is the first supported cipher suite

* Method types and error handling.

* Transport of opaque auxiliary data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR, COSE, and CoAP libraries.

To simplify for implementors, the use of CBOR and COSE in EDHOC is summarized in {{CBORandCOSE}} and test vectors including CBOR diagnostic notation are given in {{vectors}}.

# Protocol Elements {#overview}

## General 

An EDHOC message flow consists of three mandatory messages (message_1, message_2, message_3) between Initiator and Responder, an optional forth message (message_4), plus an EDHOC error message. EDHOC messages are CBOR Sequences {{RFC8742}}, see {{fig-flow}}. The protocol elements in the figure are introduced in the following sections. Message formatting and processing is specified in {{asym}} and {{error}}. An implementation may support only Initiator or only Responder. 

Application data is protected using the agreed application algorithms (AEAD, hash) in the selected cipher suite (see {{cs}}) and the application can make use of the established connection identifiers C_I and C_R (see {{corr}}). EDHOC may be used with the media type application/edhoc defined in {{iana}}.

The Initiator can derive symmetric application keys after creating EDHOC message_3, see {{exporter}}. Application protected data can therefore be sent in parallel or toghether with EDHOC message_3.

~~~~~~~~~~~
Initiator                                                   Responder
|               METHOD_CORR, SUITES_I, G_X, C_I, AD_1               |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|      C_I, G_Y, C_R, Enc(ID_CRED_R, Signature_or_MAC_2, AD_2)      |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|       C_R, AEAD(K_3ae; ID_CRED_I, Signature_or_MAC_3, AD_3)       |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-flow title="EDHOC Message Flow"}
{: artwork-align="center"}


## Method and Correlation

The data item METHOD_CORR in message_1 (see {{asym-msg1-form}}), is an integer specifying the method and the correlation properties of the transport, which are described in this section.

### Method {#method}

EDHOC supports authentication with signature or static Diffie-Hellman keys, as defined in the four authentication methods: 0, 1, 2, and 3, see {{fig-method-types}}. (Method 0 corresponds to the case outlined in {{background}} where both Initiator and Responder authenticate with signature keys.)

An implementation may support only a single method. The Initiator and the Responder need to have agreed on a single method to be used for EDHOC, see {{applicability}}.

~~~~~~~~~~~
+-------+-------------------+-------------------+-------------------+
| Value | Initiator         | Responder         | Reference         |
+-------+-------------------+-------------------+-------------------+
|     0 | Signature Key     | Signature Key     | [[this document]] |
|     1 | Signature Key     | Static DH Key     | [[this document]] |
|     2 | Static DH Key     | Signature Key     | [[this document]] |
|     3 | Static DH Key     | Static DH Key     | [[this document]] |
+-------+-------------------+-------------------+-------------------+
~~~~~~~~~~~
{: #fig-method-types title="Method Types"}
{: artwork-align="center"}

### Connection Identifiers {#ci}

EDHOC includes connection identifiers (C_I, C_R) to correlate messages. The connection identifiers C_I and C_R do not have any cryptographic purpose in EDHOC. They contain information facilitating retrieval of the protocol state and may therefore be very short. One byte connection identifiers are realistic in many scenarios as most constrained devices only have a few connections. In cases where a node only has one connection, the identifiers may even be the empty byte string. 

The connection identifier MAY be used with an application protocol (e.g. OSCORE) for which EDHOC establishes keys, in which case the connection identifiers SHALL adhere to the requirements for that protocol. Each party choses a connection identifier it desires the other party to use in outgoing messages. (For OSCORE this results in the endpoint selecting its Recipient ID, see Section 3.1 of {{RFC8613}}).

### Transport {#transport}

Cryptographically, EDHOC does not put requirements on the lower layers. EDHOC is not bound to a particular transport layer, and can be used in environments without IP. The transport is responsible to handle message loss, reordering, message duplication, fragmentation, and denial of service protection, where necessary.

The Initiator and the Responder need to have agreed on a transport to be used for EDHOC, see {{applicability}}. It is recommended to transport EDHOC in CoAP payloads, see {{transfer}}.

### Message Correlation {#corr}

If the transport provides a mechanism for correlating messages, some of the connection identifiers may be omitted. There are four cases:

   * corr = 0, the transport does not provide a correlation mechanism.

   * corr = 1, the transport provides a correlation mechanism that enables the Responder to correlate message_2 and message_1.

   * corr = 2, the transport provides a correlation mechanism that enables the Initiator to correlate message_3 and message_2.

   * corr = 3, the transport provides a correlation mechanism that enables both parties to correlate all three messages.

For example, if the key exchange is transported over CoAP, the CoAP Token can be used to correlate messages, see {{coap}}.


## Authentication Parameters {#auth-key-id}

### Authentication Keys

The authentication key MUST be a signature key or static Diffie-Hellman key. The Initiator and the Responder
 MAY use different types of authentication keys, e.g. one uses a signature key and the other uses a static Diffie-Hellman key. When using a signature key, the authentication is provided by a signature. When using a static Diffie-Hellman key the authentication is provided by a Message Authentication Code (MAC) computed from an ephemeral-static ECDH shared secret which enables significant reductions in message sizes. The MAC is implemented with an AEAD algorithm. When using static Diffie-Hellman keys the Initiator's and Responder's private authentication keys are called I and R, respectively, and the public authentication keys are called G_I and G_R, respectively.

* Only the Responder SHALL have access to the Responder's private authentication key.

* Only the Initiator SHALL have access to the Initiator's private authentication key.


### Identities

EDHOC assumes the existence of mechanisms (certification authority, trusted third party, manual distribution, etc.) for specifying and distributing authentication keys and identities. Policies are set based on the identity of the other party, and parties typically only allow connections from a specific identity or a small restricted set of identities. For example, in the case of a device connecting to a network, the network may only allow connections from devices which authenticate with certificates having a particular range of serial numbers in the subject field and signed by a particular CA. On the other side, the device may only be allowed to connect to a network which authenticate with a particular public key (information of which may be provisioned, e.g., out of band or in the Auxiliary Data, see {{AD}}).
 
The EDHOC implementation must be able to receive and enforce information from the application about what is the intended peer endpoint, and in particular whether it is a specific identity or a set of identities.

* When a Public Key Infrastructure (PKI) is used, the trust anchor is a Certification Authority (CA) certificate, and the identity is the subject whose unique name (e.g. a domain name, NAI, or EUI) is included in the endpoint's certificate. Before running EDHOC each party needs at least one CA public key certificate, or just the public key, and a specific identity or set of identities it is allowed to communicate with. Only validated public-key certificates with an allowed subject name, as specified by the application, are to be accepted. EDHOC provides proof that the other party possesses the private authentication key corresponding to the public authentication key in its certificate. The certification path provides proof that the subject of the certificate owns the public key in the certificate.

* When public keys are used but not with a PKI (RPK, self-signed certificate), the trust anchor is the public authentication key of the other party. In this case, the identity is typically directly associated to the public authentication key of the other party. For example, the name of the subject may be a canonical representation of the public key. Alternatively, if identities can be expressed in the form of unique subject names assigned to public keys, then a binding to identity can be achieved by including both public key and associated subject name in the protocol message computation: CRED_I or CRED_R may be a self-signed certificate or COSE_Key containing the public authentication key and the subject name, see {{auth-cred}}. Before running EDHOC, each endpoint needs a specific public authentication key/unique associated subject name, or a set of public authentication keys/unique associated subject names, which it is allowed to communicate with. EDHOC provides proof that the other party possesses the private authentication key corresponding to the public authentication key.



### Authentication Credentials {#auth-cred}

The authentication credentials, CRED_I and CRED_R, contain the public authentication key of the Initiator and the Responder, respectively.
The Initiator and the Responder MAY use different types of credentials, e.g. one uses an RPK and the other uses a public key certificate.

The credentials CRED_I and CRED_R are signed or MAC:ed (depending on method) by the Initiator and the Responder, respectively, see {{m3}} and {{m2}}.

When the credential is a certificate, CRED_x is an end-entity certificate (i.e. not the certificate chain) encoded as a CBOR bstr.
In X.509 certificates, signature keys typically have key usage "digitalSignature" and Diffie-Hellman keys typically have key usage "keyAgreement"

When the credential is a COSE_Key, CRED_x is a CBOR map only containing specific fields from the COSE_Key:

* For COSE_Keys of type OKP the CBOR map SHALL only include the parameters 1 (kty), -1 (crv), and -2 (x-coordinate).
* For COSE_Keys of type EC2 the CBOR map SHALL only include the parameters 1 (kty), -1 (crv), -2 (x-coordinate), and -3 (y-coordinate).

To prevent misbinding attacks in systems where an attacker can register public keys without proving knowledge of the private key, SIGMA {{SIGMA}} enforces a MAC to be calculated over the "Identity", which in case of a X.509 certificate would be the 'subject' and 'subjectAltName' fields. EDHOC follows SIGMA by calculating a MAC over the whole certificate. While SIGMA paper only focuses on the identity, the same principle is true for any information such as policies connected to the public key.

If the parties have agreed on an identity besides the public key, the identity is included in the CBOR map with the label "subject name", otherwise the subject name is the empty text string.
The parameters SHALL be encoded in decreasing order with int labels first and text string labels last.
An example of CRED_x when the RPK contains an X25519 static Diffie-Hellman key and the parties have agreed on an EUI-64 identity is shown below:

~~~~~~~~~~~
CRED_x = {
  1:  1,
 -1:  4,
 -2:  h'b1a3e89460e88d3a8d54211dc95f0b90
        3ff205eb71912d6db8f4af980d2db83a',
 "subject name" : "42-50-31-FF-EF-37-32-39"
}
~~~~~~~~~~~

### Identification of Credentials {#id_cred}

ID_CRED_I and ID_CRED_R are identifiers of the public authentication keys of the Initiator and the Responder, respectively. 
ID_CRED_I and ID_CRED_R do not have any cryptographic purpose in EDHOC.

* ID_CRED_R is intended to facilitate for the Initiator to retrieve the Responder's public authentication key.

* ID_CRED_I is intended to facilitate for the Responder to retrieve the Initiator's public authentication key.

The identifiers ID_CRED_I and ID_CRED_R are COSE header_maps, i.e. CBOR maps containing COSE Common Header Parameters, see Section 3.1 of {{RFC8152}}).
In the following we give some examples of COSE header_maps.

Raw public keys are most optimally stored as COSE_Key objects and identified with a 'kid' parameter:

* ID_CRED_x = { 4 : kid_x }, where kid_x : bstr, for x = I or R.

Public key certificates can be identified in different ways. Header parameters for identifying CBOR certificates and X.509 certificates are defined in {{I-D.mattsson-cose-cbor-cert-compress}} and {{I-D.ietf-cose-x509}}, for example:

* by a hash value with the 'c5t' or 'x5t' parameters;

   * ID_CRED_x = { 34 : COSE_CertHash }, for x = I or R,

   * ID_CRED_x = { TDB3 : COSE_CertHash }, for x = I or R,

* by a URI with the 'c5u' or 'x5u' parameters;

   * ID_CRED_x = { 35 : uri }, for x = I or R,

   * ID_CRED_x = { TBD4 : uri }, for x = I or R,

ID_CRED_x MAY contain the actual credential used for authentication, CRED_x.
For example, in case of a DER encoded X.509 certificate chain when CRED_x is a COSE_X509  then this may be the value of ID_CRED_x with COSE header parameter x5chain, see Section 2 of {{I-D.ietf-cose-x509}}. This is typically how certificates are transported within EDHOC.

It is RECOMMENDED that ID_CRED_x uniquely identify the public authentication key as the recipient may otherwise have to try several keys.
ID_CRED_I and ID_CRED_R are transported in the 'ciphertext', see {{m3}} and {{m2}}.

When ID_CRED_x does not contain the actual credential it may be very short.
One byte credential identifiers are realistic in many scenarios as most constrained devices only have a few keys. In cases where a node only has one key, the identifier may even be the empty byte string.

## Cipher Suites {#cs}

An EDHOC cipher suite consists of an ordered set of COSE code points from the "COSE Algorithms" and "COSE Elliptic Curves" registries: 

* EDHOC AEAD algorithm
* EDHOC hash algorithm
* EDHOC ECDH curve
* EDHOC signature algorithm 
* EDHOC signature algorithm curve
* Application AEAD algorithm 
* Application hash algorithm 

Each cipher suite is identified with a pre-defined int label.

EDHOC can be used with all algorithms and curves defined for COSE. Implementation can either use one of the pre-defined cipher suites ({{suites-registry}}) or use any combination of COSE algorithms to define their own private cipher suite. Private cipher suites can be identified with any of the four values -24, -23, -22, -21.

The following cipher suites are for constrained IoT where message overhead is a very important factor:

~~~~~~~~~~~
   0. ( 10, -16, 4, -8, 6, 10, -16 )
      (AES-CCM-16-64-128, SHA-256, X25519, EdDSA, Ed25519,
       AES-CCM-16-64-128, SHA-256)

   1. ( 30, -16, 4, -8, 6, 10, -16 )
      (AES-CCM-16-128-128, SHA-256, X25519, EdDSA, Ed25519,
       AES-CCM-16-64-128, SHA-256)

   2. ( 10, -16, 1, -7, 1, 10, -16 )
      (AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256,
       AES-CCM-16-64-128, SHA-256)

   3. ( 30, -16, 1, -7, 1, 10, -16 )
      (AES-CCM-16-128-128, SHA-256, P-256, ES256, P-256,
       AES-CCM-16-64-128, SHA-256)
~~~~~~~~~~~

The following cipher suite is for general non-constrained applications. It uses very high performance algorithms that also are widely supported:

~~~~~~~~~~~
   4. ( 1, -16, 4, -7, 1, 1, -16 )
      (A128GCM, SHA-256, X25519, ES256, P-256,
       A128GCM, SHA-256)
~~~~~~~~~~~

The following cipher suite is for high security application such as government use and financial applications. It is compatible with the CNSA suite {{CNSA}}.

~~~~~~~~~~~
   5. ( 3, -43, 2, -35, 2, 3, -43 )
      (A256GCM, SHA-384, P-384, ES384, P-384,
       A256GCM, SHA-384)
~~~~~~~~~~~

The different methods use the same cipher suites, but some algorithms are not used in some methods. The EDHOC signature algorithm and the EDHOC signature algorithm curve are not used in methods without signature authentication.

The Initiator needs to have a list of cipher suites it supports in order of preference. The Responder needs to have a list of cipher suites it supports. SUITES_I is a CBOR array containing cipher suites that the Initiator supports. SUITES_I is formatted and processed as detailed in {{asym-msg1-form}} to secure the cipher suite negotation.


## Ephemeral Public Keys {#cose_key}

The ECDH ephemeral public keys are formatted as a COSE_Key of type EC2 or OKP according to Sections 13.1 and 13.2 of {{RFC8152}}, but only the 'x' parameter is included G_X and G_Y. For Elliptic Curve Keys of type EC2, compact representation as per {{RFC6090}} MAY be used also in the COSE_Key. If the COSE implementation requires an 'y' parameter, any of the possible values of the y-coordinate can be used, see Appendix C of {{RFC6090}}. COSE {{RFC8152}} always use compact output for Elliptic Curve Keys of type EC2.


## Auxiliary Data {#AD}

In order to reduce round trips and number of messages, and in some cases also streamline processing, certain security applications may be integrated into EDHOC by transporting auxiliary data together with the messages. One example is the transport of third-party authorization information protected outside of EDHOC {{I-D.selander-ace-ake-authz}}. Another example is the embedding of a certificate enrolment request or a newly issued certificate.

EDHOC allows opaque auxiliary data (AD) to be sent in the EDHOC messages. Unprotected Auxiliary Data (AD_1, AD_2) may be sent in message_1 and message_2, respectively. Protected Auxiliary Data (AD_3) may be sent in message_3.

Since data carried in AD_1 and AD_2 may not be protected, and the content of AD_3 is available to both the Initiator and the Responder, special considerations need to be made such that the availability of the data a) does not violate security and privacy requirements of the service which uses this data, and b) does not violate the security properties of EDHOC.


## Communication of Protocol Features

EDHOC allows the communication or negotiation of various protocol features during the execution of the protocol.

* The Initiator proposes a cipher suite (see {{cs}}), and the Responder either accepts or rejects, and may make a counter proposal. 

* The Initiator decides on the correlation parameter corr (see {{corr}}). This is typically given by the transport which the Initiator and the Responder have agreed on beforehand. The Responder either accepts or rejects.

* The Initiator decides on the method parameter, see {{fig-method-types}}. The Responder either accepts or rejects.

* The Initiator and the Responder decide on the representation of the identifier of their respective credentials, ID_CRED_I and ID_CRED_R. The decision is reflected by the label used in the CBOR map, see for example {{id_cred}}.

Editor's note: This section needs to be aligned with {{applicability}}.


# Key Derivation {#key-der}

EDHOC uses Extract-and-Expand {{RFC5869}} with the EDHOC hash algorithm in the selected cipher suite to derive keys. Extract is used to derive fixed-length uniformly pseudorandom keys (PRK) from ECDH shared secrets. Expand is used to derive additional output keying material (OKM) from the PRKs. The PRKs are derived using Extract.

~~~~~~~~~~~~~~~~~~~~~~~
   PRK = Extract( salt, IKM )
~~~~~~~~~~~~~~~~~~~~~~~

If the EDHOC hash algorithm is SHA-2, then Extract( salt, IKM ) = HKDF-Extract( salt, IKM ) {{RFC5869}}. If the EDHOC hash algorithm is SHAKE128, then Extract( salt, IKM ) = KMAC128( salt, IKM, 256, "" ). If the EDHOC hash algorithm is SHAKE256, then Extract( salt, IKM ) = KMAC256( salt, IKM, 512, "" ).

PRK_2e is used to derive a keystream to encrypt message_2. PRK_3e2m is used to derive keys and IVs to produce a MAC in message_2 and to encrypt message_3. PRK_4x3m is used to derive keys and IVs to produce a MAC in message_3 and to derive application specific data.

PRK_2e is derived with the following input:

* The salt SHALL be the empty byte string. Note that {{RFC5869}} specifies that if the salt is not provided, it is set to a string of zeros (see Section 2.2 of {{RFC5869}}). For implementation purposes, not providing the salt is the same as setting the salt to the empty byte string. 

* The input keying material (IKM) SHALL be the ECDH shared secret G_XY (calculated from G_X and Y or G_Y and X) as defined in Section 12.4.1 of {{RFC8152}}.

Example: Assuming the use of SHA-256 the extract phase of HKDF produces PRK_2e as follows:

~~~~~~~~~~~~~~~~~~~~~~~
   PRK_2e = HMAC-SHA-256( salt, G_XY )
~~~~~~~~~~~~~~~~~~~~~~~

where salt = 0x (the empty byte string).

The pseudorandom keys PRK_3e2m and PRK_4x3m are defined as follow:

* If the Responder authenticates with a static Diffie-Hellman key, then PRK_3e2m = Extract( PRK_2e, G_RX ), where G_RX is the ECDH shared secret calculated from G_R and X, or G_X and R, else PRK_3e2m = PRK_2e.

* If the Initiator authenticates with a static Diffie-Hellman key, then PRK_4x3m = Extract( PRK_3e2m, G_IY ), where G_IY is the ECDH shared secret calculated from G_I and Y, or G_Y and I, else PRK_4x3m = PRK_3e2m.

Example: Assuming the use of curve25519, the ECDH shared secrets G_XY, G_RX, and G_IY are the outputs of the X25519 function {{RFC7748}}:

~~~~~~~~~~~~~~~~~~~~~~~
   G_XY = X25519( Y, G_X ) = X25519( X, G_Y )
~~~~~~~~~~~~~~~~~~~~~~~

The keys and IVs used in EDHOC are derived from PRK using Expand {{RFC5869}} where the EDHOC-KDF is instantiated with the EDHOC AEAD algorithm in the selected cipher suite.

~~~~~~~~~~~~~~~~~~~~~~~
   OKM = EDHOC-KDF( PRK, transcript_hash, label, length )
       = Expand( PRK, info, length )
~~~~~~~~~~~~~~~~~~~~~~~

where info is the CBOR encoding of

~~~~~~~~~~~~~~~~~~~~~~~
info = [
   edhoc_aead_id : int / tstr,
   transcript_hash : bstr,
   label : tstr,
   length : uint
]
~~~~~~~~~~~~~~~~~~~~~~~

where

  + edhoc_aead_id is an int or tstr containing the algorithm identifier of the EDHOC AEAD algorithm in the selected cipher suite encoded as defined in {{RFC8152}}. Note that a single fixed edhoc_aead_id is used in all invocations of EDHOC-KDF, including the derivation of KEYSTREAM_2 and invocations of the EDHOC-Exporter.
  
  + transcript_hash is a bstr set to one of the transcript hashes TH_2, TH_3, or TH_4 as defined in Sections {{asym-msg2-form}}{: format="counter"}, {{asym-msg3-form}}{: format="counter"}, and {{exporter}}{: format="counter"}.

  + label is a tstr set to the name of the derived key or IV, i.e. "K_2m", "IV_2m", "KEYSTREAM_2", "K_3m", "IV_3m", "K_3ae", or "IV_3ae".

  + length is the length of output keying material (OKM) in bytes

If the EDHOC hash algorithm is SHA-2, then Expand( PRK, info, length ) = HKDF-Expand( PRK, info, length ) {{RFC5869}}. If the EDHOC hash algorithm is SHAKE128, then Expand( PRK, info, length ) = KMAC128( PRK, info, L, "" ). If the EDHOC hash algorithm is SHAKE256, then Expand( PRK, info, length ) = KMAC256( PRK, info, L, "" ).

KEYSTREAM_2 are derived using the transcript hash TH_2 and the pseudorandom key PRK_2e. K_2m and IV_2m are derived using the transcript hash TH_2 and the pseudorandom key PRK_3e2m. K_3ae and IV_3ae are derived using the transcript hash TH_3 and the pseudorandom key PRK_3e2m. K_3m and IV_3m are derived using the transcript hash TH_3 and the pseudorandom key PRK_4x3m. IVs are only used if the EDHOC AEAD algorithm uses IVs.

## EDHOC-Exporter Interface {#exporter}

Application keys and other application specific data can be derived using the EDHOC-Exporter interface defined as:

~~~~~~~~~~~
   EDHOC-Exporter(label, length)
     = EDHOC-KDF(PRK_4x3m, TH_4, label, length) 
~~~~~~~~~~~

where label is a tstr defined by the application and length is a uint defined by the application. The label SHALL be different for each different exporter value. The transcript hash TH_4 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

~~~~~~~~~~~
   TH_4 = H( TH_3, CIPHERTEXT_3 )
~~~~~~~~~~~

where H() is the hash function in the selected cipher suite. Example use of the EDHOC-Exporter is given in Sections {{oscore}}{: format="counter"}.

To provide forward secrecy in an even more efficient way than re-running EDHOC, EDHOC provides the function EDHOC-KeyUpdate. When EDHOC-KeyUpdate is called the old PRK_4x3m is deleted and the new PRk_4x3m is calculated as a "hash" of the old key using the Extract function as illustrated by the following pseudocode:

~~~~~~~~~~~
   EDHOC-KeyUpdate( nonce ):
      PRK_4x3m = Extract( nonce, PRK_4x3m )
~~~~~~~~~~~

# Message Formatting and Processing {#asym}

This section specifies formatting of the messages and processing steps. Error messages are specified in {{error}}. 

An EDHOC message is encoded as a sequence of CBOR data (CBOR Sequence, {{RFC8742}}).
Additional optimizations are made to reduce message overhead.

While EDHOC uses the COSE_Key, COSE_Sign1, and COSE_Encrypt0 structures, only a subset of the parameters is included in the EDHOC messages. The unprotected COSE header in COSE_Sign1, and COSE_Encrypt0 (not included in the EDHOC message) MAY contain parameters (e.g. 'alg'). 

## Encoding of bstr_identifier {#bstr_id}

Byte strings are encoded in CBOR as two or more bytes, whereas integers in the interval -24 to 23 are encoded in CBOR as one byte.

bstr_identifier is a special encoding of byte strings, used throughout the protocol to enable the encoding of the shortest byte strings as integers that only require one byte of CBOR encoding.

The bstr_identifier encoding is defined as follows: Byte strings in the interval h'00' to h'2f' are encoded as the corresponding integer minus 24, which are all represented by one byte CBOR ints. Other byte strings are encoded as CBOR byte strings.

For example, the byte string h'59e9' encoded as a bstr_identifier is equal to h'59e9', while the byte string h'2a' is encoded as the integer 18.

The CDDL definition of the bstr_identifier is given below:

~~~~~~~~~~~ CDDL
bstr_identifier = bstr / int
~~~~~~~~~~~

Note that, despite what could be interpreted by the CDDL definition only, bstr_identifier once decoded are always byte strings.

## EDHOC Message 1

### Formatting of Message 1 {#asym-msg1-form}

message_1 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  METHOD_CORR : int,
  SUITES_I : [ selected : suite, supported : 2* suite ] / suite,
  G_X : bstr,
  C_I : bstr_identifier,  
  ? AD_1 : bstr,
)

suite = int
~~~~~~~~~~~

where:

* METHOD_CORR = 4 * method + corr, where method = 0, 1, 2, or 3 (see {{fig-method-types}}) and the correlation parameter corr is chosen based on the transport and determines which connection identifiers that are omitted (see {{corr}}).
* SUITES_I - cipher suites which the Initiator supports in order of (decreasing) preference. The list of supported cipher suites can be truncated at the end, as is detailed in the processing steps below. One of the supported cipher suites is selected. The selected suite is the first suite in the SUITES_I CBOR array. If a single supported cipher suite is conveyed then that cipher suite is selected and the selected cipher suite is encoded as an int instead of an array.
* G_X - the ephemeral public key of the Initiator
* C_I - variable length connection identifier, encoded as a bstr_identifier (see {{bstr_id}}).
* AD_1 - bstr containing unprotected opaque auxiliary data
* 
### Initiator Processing of Message 1 {#init-proc-msg1}

The Initiator SHALL compose message_1 as follows:

* The supported cipher suites and the order of preference MUST NOT be changed based on previous error messages. However, the list SUITES_I sent to the Responder MAY be truncated such that cipher suites which are the least preferred are omitted. The amount of truncation MAY be changed between sessions, e.g. based on previous error messages (see next bullet), but all cipher suites which are more preferred than the least preferred cipher suite in the list MUST be included in the list.

* Determine the cipher suite to use with the Responder in message_1. If the Initiator previously received from the Responder an error message to a message_1 with diagnostic payload identifying a cipher suite that the Initiator supports, then the Initiator SHALL use that cipher suite. Otherwise the first supported (i.e. the most preferred) cipher suite in SUITES_I MUST be used.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite and format it as a COSE_Key. Let G_X be the 'x' parameter of the COSE_Key.
   
* Choose a connection identifier C_I and store it for the length of the protocol.

* Encode message_1 as a sequence of CBOR encoded data items as specified in {{asym-msg1-form}}

### Responder Processing of Message 1 {#resp-proc-msg1}

The Responder SHALL process message_1 as follows:

* Decode message_1 (see {{CBOR}}).

* Verify that the selected cipher suite is supported and that no prior cipher suite in SUITES_I is supported.

* Pass AD_1 to the security application.

If any verification step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued. If the Responder does not support the selected cipher suite, then SUITES_R MUST include one or more supported cipher suites. If the Responder does not support the selected cipher suite, but supports another cipher suite in SUITES_I, then SUITES_R MUST include the first supported cipher suite in SUITES_I.

## EDHOC Message 2 {#m2}

### Formatting of Message 2 {#asym-msg2-form}

message_2 and data_2 SHALL be CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_2 = (
  ? C_I : bstr_identifier,
  G_Y : bstr,
  C_R : bstr_identifier,
)
~~~~~~~~~~~

where:

* G_Y - the ephemeral public key of the Responder
* C_R - variable length connection identifier, encoded as a bstr_identifier (see {{bstr_id}}).

### Responder Processing of Message 2 {#asym-msg2-proc}

The Responder SHALL compose message_2 as follows:

* If corr (METHOD_CORR mod 4) equals 1 or 3, C_I is omitted, otherwise C_I is not omitted.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite and format it as a COSE_Key. Let G_Y be the 'x' parameter of the COSE_Key.

* Choose a connection identifier C_R and store it for the length of the protocol.

* Compute the transcript hash TH_2 = H(message_1, data_2) where H() is the hash function in the selected cipher suite. The transcript hash TH_2 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

* Compute an inner COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_2m, IV_2m, and the following parameters:

   * protected =  << ID_CRED_R >>

      * ID_CRED_R - identifier to facilitate retrieval of CRED_R, see {{id_cred}}

   * external_aad = << TH_2, CRED_R, ? AD_2 >>

      * CRED_R - bstr containing the credential of the Responder, see {{id_cred}}. 

      * AD_2 = bstr containing opaque unprotected auxiliary data

   * plaintext = h''

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = EDHOC-KDF( PRK_3e2m, TH_2, "K_2m", length ) 
   * Nonce N = EDHOC-KDF( PRK_3e2m, TH_2, "IV_2m", length )
   * Plaintext P = 0x (the empty string)
   * Associated data A =

     \[ "Encrypt0", << ID_CRED_R >>, << TH_2, CRED_R, ? AD_2 >> \]

   MAC_2 is the 'ciphertext' of the inner COSE_Encrypt0.

* If the Responder authenticates with a static Diffie-Hellman key (method equals 1 or 3), then Signature_or_MAC_2 is MAC_2. If the Responder authenticates with a signature key (method equals 0 or 2), then Signature_or_MAC_2 is the 'signature' of a COSE_Sign1 object as defined in Section 4.4 of {{RFC8152}} using the signature algorithm in the selected cipher suite, the private authentication key of the Responder, and the following parameters:

   * protected =  << ID_CRED_R >>

   * external_aad = << TH_2, CRED_R, ? AD_2 >>

   * payload = MAC_2

   COSE constructs the input to the Signature Algorithm as:

   * The key is the private authentication key of the Responder.

   * The message M to be signed =

     \[ "Signature1", << ID_CRED_R >>, << TH_2, CRED_R, ? AD_2 >>, MAC_2 \]

* CIPHERTEXT_2 is encrypted by using the Expand function as a binary additive stream cipher.

   * plaintext = ( ID_CRED_R / bstr_identifier, Signature_or_MAC_2, ? AD_2 )

      * Note that if ID_CRED_R contains a single 'kid' parameter, i.e., ID_CRED_R = { 4 : kid_R }, only the byte string kid_R is conveyed in the plaintext encoded as a bstr_identifier, see {{id_cred}} and {{bstr_id}}.

   * CIPHERTEXT_2 = plaintext XOR KEYSTREAM_2

* Encode message_2 as a sequence of CBOR encoded data items as specified in {{asym-msg2-form}}.

### Initiator Processing of Message 2

The Initiator SHALL process message_2 as follows:

* Decode message_2 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_I and/or other external information such as the CoAP Token and the 5-tuple.

* Decrypt CIPHERTEXT_2, see {{asym-msg2-proc}}.

* Verify that the identity of the Responder is an allowed identity for this connection, see {{auth-key-id}}.

* Verify Signature_or_MAC_2 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg2-proc}}.

* Pass AD_2 to the security application.

If any verification step fails, the Initiator MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

## EDHOC Message 3 {#m3}

### Formatting of Message 3 {#asym-msg3-form}

message_3 and data_3 SHALL be CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_3 = (
  ? C_R : bstr_identifier,
)
~~~~~~~~~~~

### Initiator Processing of Message 3 {#asym-msg3-proc}

The Initiator  SHALL compose message_3 as follows:

* If corr (METHOD_CORR mod 4) equals 2 or 3, C_R is omitted, otherwise C_R is not omitted.

* Compute the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3) where H() is the hash function in the the selected cipher suite. The transcript hash TH_3 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

* Compute an inner COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3m, IV_3m, and the following parameters:

   * protected =  << ID_CRED_I >>

      * ID_CRED_I - identifier to facilitate retrieval of CRED_I, see {{id_cred}}

   * external_aad = << TH_3, CRED_I, ? AD_3 >>

      * CRED_I - bstr containing the credential of the Initiator, see {{id_cred}}. 

      * AD_3 = bstr containing opaque protected auxiliary data

   * plaintext = h''

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = EDHOC-KDF( PRK_4x3m, TH_3, "K_3m", length ) 
   * Nonce N = EDHOC-KDF( PRK_4x3m, TH_3, "IV_3m", length )
   * Plaintext P = 0x (the empty string)
   * Associated data A =

     \[ "Encrypt0", << ID_CRED_I >>, << TH_3, CRED_I, ? AD_3 >> \]

   MAC_3 is the 'ciphertext' of the inner COSE_Encrypt0.

* If the Initiator authenticates with a static Diffie-Hellman key (method equals 2 or 3), then Signature_or_MAC_3 is MAC_3. If the Initiator authenticates with a signature key (method equals 0 or 1), then Signature_or_MAC_3 is the 'signature' of a COSE_Sign1 object as defined in Section 4.4 of {{RFC8152}} using the signature algorithm in the selected cipher suite, the private authentication key of the Initiator, and the following parameters:

   * protected =  << ID_CRED_I >>

   * external_aad = << TH_3, CRED_I, ? AD_3 >>

   * payload = MAC_3

   COSE constructs the input to the Signature Algorithm as:

   * The key is the private authentication key of the Initiator.

   * The message M to be signed =

     \[ "Signature1", << ID_CRED_I >>, << TH_3, CRED_I, ? AD_3 >>, MAC_3 \]

* Compute an outer COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3ae, IV_3ae, and the following parameters. The protected header SHALL be empty.

   * external_aad = TH_3

   * plaintext = ( ID_CRED_I / bstr_identifier, Signature_or_MAC_3, ? AD_3 )

      * Note that if ID_CRED_I contains a single 'kid' parameter, i.e., ID_CRED_I = { 4 : kid_I }, only the byte string kid_I is conveyed in the plaintext encoded as a bstr_identifier, see {{id_cred}} and {{bstr_id}}.

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = EDHOC-KDF( PRK_3e2m, TH_3, "K_3ae", length ) 
   * Nonce N = EDHOC-KDF( PRK_3e2m, TH_3, "IV_3ae", length )
   * Plaintext P = ( ID_CRED_I / bstr_identifier, Signature_or_MAC_3, ? AD_3 )
   * Associated data A = \[ "Encrypt0", h'', TH_3 \]

   CIPHERTEXT_3 is the 'ciphertext' of the outer COSE_Encrypt0.

* Encode message_3 as a sequence of CBOR encoded data items as specified in {{asym-msg3-form}}.

Pass the connection identifiers (C_I, C_R) and the application algorithms in the selected cipher suite to the application. The application can now derive application keys using the EDHOC-Exporter interface.

After sending message_3, the Initiator is assured that no other party than the Responder can compute the key PRK_4x3m (implicit key authentication). The Initiator does however not know that the Responder has actually computed the key PRK_4x3m. While the Initiator can securely send protected application data, the Initiator SHOULD NOT permanently store the keying material PRK_4x3m and TH_4 until the Initiator is assured that the Responder has actually computed the key PRK_4x3m (explicit key confirmation). Explicit key confirmation is e.g. assured when the Initiator has verified an OSCORE message or message_4 from the Responder.

### Responder Processing of Message 3

The Responder SHALL process message_3 as follows:

* Decode message_3 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_R and/or other external information such as the CoAP Token and the 5-tuple.

* Decrypt and verify the outer COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3ae, and IV_3ae.

* Verify that the identity of the Initiator is an allowed identity for this connection, see {{auth-key-id}}.

* Verify Signature_or_MAC_3 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg3-proc}}.

*  Pass AD_3, the connection identifiers (C_I, C_R), and the application algorithms in the selected cipher suite to the security application. The application can now derive application keys using the EDHOC-Exporter interface.

If any verification step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

After verifying message_3, the Responder is assured that the Initiator has calculated the key PRK_4x3m (explicit key confirmation) and that no other party than the Responder can compute the key. The Responder can securely send protected application data and store the keying material PRK_4x3m and TH_4.

# Error Handling {#error}

## EDHOC Error Message

This section defines a message format for the EDHOC error message. 

An EDHOC error message can be sent by either endpoint as a reply to any non-error EDHOC message.

How errors at the EDHOC layer are transported depends on lower layers, which need to enable error messages to be sent and processed as intended.
EDHOC errors sent as normal successful messages (e.g. CoAP POST and 2.04 Changed) can avoid issues created by usage of cross protocol proxies (e.g. UDP to TCP).
However, for the combined EDHOC-in-OSCORE case {{I-D.palombini-core-oscore-edhoc}}, an error message response following a combined EDHOC message_3/OSCORE request needs to be sent with a CoAP error code.

All error messages in EDHOC are fatal. After sending an error message, the sender MUST discontinue the protocol. The receiver SHOULD treat an error message as an indication that the other party likely has discontinued the protocol. But as the error message is not authenticated, a received error messages might also have been sent by an attacker and the receiver MAY therefore try to continue the protocol. 

error SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
error = (
  ? C_x : bstr_identifier,
  DIAG_MSG : tstr,
  ? SUITES_R : [ supported : 2* suite ] / suite,
)
~~~~~~~~~~~

where:

* C_x - (optional) variable length connection identifier, encoded as a bstr_identifier (see {{bstr_id}}). If error is sent by the Responder and corr (METHOD_CORR mod 4) equals 0 or 2 then C_x is set to C_I, else if error is sent by the Initiator and corr (METHOD_CORR mod 4) equals 0 or 1 then C_x is set to C_R, else C_x is omitted.
* DIAG_MSG - text string containing the diagnostic message in English. MUST NOT be the empty string unless the error message contains SUITES_R.
* SUITES_R - (optional) cipher suites from SUITES_I or the EDHOC cipher suites registry that the Responder supports. SUITES_R MUST only be included in replies to message_1. If a single supported cipher suite is conveyed then the supported cipher suite is encoded as an int instead of an array.

After receiving SUITES_R, the Initiator can determine which selected cipher suite to use for the next EDHOC run with the Responder. If the Initiator intends to contact the Responder in the future, the Initiator SHOULD remember which selected cipher suite to use until the next message_1 has been sent, otherwise the Initiator and Responder will likely run into an infinite loop. After a successful run of EDHOC, the Initiator MAY remember the selected cipher suite to use in future EDHOC runs. Note that if the Initiator or Responder is updated with new cipher suite policies, any cached information may be outdated.

Error messages without SUITES_R MUST contain a human-readable diagnostic message DIAG_MSG written in English, explaning the error situation. The diagnostic text message is mainly intended for software engineers that during debugging need to interpret it in the context of the EDHOC specification. The diagnostic message SHOULD be be provided to the calling application where they SHOULD be logged. Error messages with SUITES_R MAY use the empty string as the diagnostic message. The DIAG_MSG text string is mandatory and characteristic for error messages, which enables the receiver to distinguish between a normal message and an error message.


### Example Use of EDHOC Error Message with SUITES_R

Assume that the Initiator supports the five cipher suites 5, 6, 7, 8, and 9 in decreasing order of preference. Figures {{fig-error1}}{: format="counter"} and {{fig-error2}}{: format="counter"} show examples of how the Initiator can truncate SUITES_I and how SUITES_R is used by Responders to give the Initiator information about the cipher suites that the Responder supports.

In the first example ({{fig-error1}}), the Responder supports cipher suite 6 but not the initially selected cipher suite 5.

~~~~~~~~~~~
Initiator                                                   Responder
|            METHOD_CORR, SUITES_I = 5, G_X, C_I, AD_1              |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                    C_I, DIAG_MSG, SUITES_R = 6                    |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|         METHOD_CORR, SUITES_I = [6, 5, 6], G_X, C_I, AD_1         |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error1 title="Example of Responder supporting suite 6 but not suite 5."}
{: artwork-align="center"}

In the second example ({{fig-error2}}), the Responder supports cipher suites 8 and 9 but not the more preferred (by the Initiator) cipher suites 5, 6 or 7. To illustrate the negotiation mechanics we let the Initiator make a guess that the Responder supports suite 6 but not suite 5. Since the Responder supports neither 5 nor 6, it responds with an error and SUITES_R, after which the Initiator can select a better suite. The order of cipher suites in SUITES_R does not matter. (If the Responder had supported suite 5, it would include it in SUITES_R of the response, and it would in that case be the selected suite in the second message_1.) 

~~~~~~~~~~~
Initiator                                                   Responder
|        METHOD_CORR, SUITES_I = [6, 5, 6], G_X, C_I, AD_1          |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                  C_I, DIAG_MSG, SUITES_R = [9, 8]                 |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|       METHOD_CORR, SUITES_I = [8, 5, 6, 7, 8], G_X, C_I, AD_1     |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error2 title="Example of Responder supporting suites 8 and 9 but not 5, 6 or 7."}
{: artwork-align="center"}


Note that the Initiator's list of supported cipher suites and order of preference is fixed (see {{asym-msg1-form}} and {{init-proc-msg1}}). Furthermore, the Responder shall only accept message_1 if the selected cipher suite is the first cipher suite in SUITES_I that the Responder supports (see {{resp-proc-msg1}}). Following this procedure ensures that the selected cipher suite is the most preferred (by the Initiator) cipher suite supported by both parties.

If the selected cipher suite is not the first cipher suite which the Responder supports in SUITES_I received in message_1, then Responder MUST discontinue the protocol, see {{resp-proc-msg1}}. If SUITES_I in message_1 is manipulated then the integrity verification of message_2 containing the transcript hash TH_2 = H( message_1, data_2 ) will fail and the Initiator will discontinue the protocol.

# Transferring EDHOC and Deriving an OSCORE Context {#transfer}

## EDHOC Message 4 {#m4}

This section specifies message_4 which is OPTIONAL to support. Key confirmation is normally provided by sending an application message from the Responder to the Initiator protected with a key derived with the EDHOC-Exporter, e.g., using OSCORE (see {{oscore}}). In deployments where no protected application message is sent from the Responder to the Initiator, the Responder MUST send message_4. Two examples of such deployments:

1. When EDHOC is only used for authentication and no application data is sent.
2. When application data is only sent from the Initiator to the Responder.

Further considerations are provided in {{applicability}}.

### Formatting of Message 4 {#asym-msg4-form}

message_4 and data_4 SHALL be CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_4 = (
  data_4,
  MAC_4 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_4 = (
  ? C_I : bstr_identifier,
)
~~~~~~~~~~~

### Responder Processing of Message 4 {#asym-msg4-proc}

The Responder SHALL compose message_4 as follows:

* If corr (METHOD_CORR mod 4) equals 1 or 3, C_I is omitted, otherwise C_I is not omitted.

* Compute an inner COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, and the following parameters:

   * protected = h''

   * external_aad = << TH_4 >>

   * plaintext = h''

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = EDHOC-Exporter( "EDHOC_message_4_Key", length ) 
   * Nonce N = EDHOC-Exporter( "EDHOC_message_4_Nonce", length )
   * Plaintext P = 0x (the empty string)
   * Associated data A =

     \[ "Encrypt0", h'', << TH_4 >> \]

   MAC_4 is the 'ciphertext' of the COSE_Encrypt0.

* Encode message_4 as a sequence of CBOR encoded data items as specified in {{asym-msg4-form}}.

### Initiator Processing of Message 4

The Initiator SHALL process message_4 as follows:

* Decode message_4 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_I and/or other external information such as the CoAP Token and the 5-tuple.

* Verify MAC_4 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, and the parameters defined in {{asym-msg4-proc}}. 

If any verification step fails the Initiator MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.


## Transferring EDHOC in CoAP {#coap}

It is recommended to transport EDHOC as an exchange of CoAP {{RFC7252}} messages. CoAP is a reliable transport that can preserve packet ordering and handle message duplication. CoAP can also perform fragmentation and protect against denial of service attacks. It is recommended to carry the EDHOC messages in Confirmable messages, especially if fragmentation is used.

By default, the CoAP client is the Initiator and the CoAP server is the Responder, but the roles SHOULD be chosen to protect the most sensitive identity, see {{security}}. By default, EDHOC is transferred in POST requests and 2.04 (Changed) responses to the Uri-Path: "/.well-known/edhoc", but an application may define its own path that can be discovered e.g. using resource directory {{I-D.ietf-core-resource-directory}}.

By default, the message flow is as follows: EDHOC message_1 is sent in the payload of a POST request from the client to the server's resource for EDHOC. EDHOC message_2 or the EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response. EDHOC message_3 or the EDHOC error message is sent from the client to the server's resource in the payload of a POST request. If needed, an EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response. Alternatively, if EDHOC message_4 is used, it is sent from the server to the client in the payload of a 2.04 (Changed) response analogously to message_2.

An example of a successful EDHOC exchange using CoAP is shown in {{fig-coap1}}. In this case the CoAP Token enables the Initiator to correlate message_1 and message_2 so the correlation parameter corr = 1.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_1
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_2
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_3
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | 
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap1 title="Transferring EDHOC in CoAP when the Initiator is CoAP Client"}
{: artwork-align="center"}

The exchange in {{fig-coap1}} protects the client identity against active attackers and the server identity against passive attackers. An alternative exchange that protects the server identity against active attackers and the client identity against passive attackers is shown in {{fig-coap2}}. In this case the CoAP Token enables the Responder to correlate message_2 and message_3 so the correlation parameter corr = 2. If EDHOC message_4 is used, it is transported with CoAP in the payload of a POST request with a 2.04 (Changed) response.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_1
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_2
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_3
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap2 title="Transferring EDHOC in CoAP when the Initiator is CoAP Server"}
{: artwork-align="center"}

To protect against denial-of-service attacks, the CoAP server MAY respond to the first POST request with a 4.01 (Unauthorized) containing an Echo option {{I-D.ietf-core-echo-request-tag}}. This forces the initiator to demonstrate its reachability at its apparent network address. If message fragmentation is needed, the EDHOC messages may be fragmented using the CoAP Block-Wise Transfer mechanism {{RFC7959}}.

### Deriving an OSCORE Context from EDHOC {#oscore}

When EDHOC is used to derive parameters for OSCORE {{RFC8613}}, the parties  make sure that the EDHOC connection identifiers are unique, i.e. C_R MUST NOT be equal to C_I. The CoAP client and server MUST be able to retrieve the OSCORE protocol state using its chosen connection identifier and optionally other information such as the 5-tuple. In case that the CoAP client is the Initiator and the CoAP server is the Responder:

* The client's OSCORE Sender ID is C_R and the server's OSCORE Sender ID is C_I, as defined in this document

* The AEAD Algorithm and the hash algorithm are the application AEAD and hash algorithms in the selected cipher suite.

* The Master Secret and Master Salt are derived as follows. By default key_length is the key length (in bytes) of the application AEAD Algorithm and salt_length is 8 bytes. The Intiator and Responder MAY agree out-of-band on a longer key_length than the default and a different salt_length. 

~~~~~~~~~~~~~~~~~~~~~~~
   Master Secret = EDHOC-Exporter( "OSCORE Master Secret", key_length )
   Master Salt   = EDHOC-Exporter( "OSCORE Master Salt", salt_length )
~~~~~~~~~~~~~~~~~~~~~~~

# Security Considerations {#security}

## Security Properties {#sec-prop}

EDHOC inherits its security properties from the theoretical SIGMA-I protocol {{SIGMA}}. Using the terminology from {{SIGMA}}, EDHOC provides perfect forward secrecy, mutual authentication with aliveness, consistency, peer awareness. As described in {{SIGMA}}, peer awareness is provided to the Responder, but not to the Initiator.

EDHOC protects the credential identifier of the Initiator against active attacks and the credential identifier of the Responder against passive attacks. The roles should be assigned to protect the most sensitive identity/identifier, typically that which is not possible to infer from routing information in the lower layers. 

Compared to {{SIGMA}}, EDHOC adds an explicit method type and expands the message authentication coverage to additional elements such as algorithms, auxiliary data, and previous messages. This protects against an attacker replaying messages or injecting messages from another session.

EDHOC also adds negotiation of connection identifiers and downgrade protected negotiation of cryptographic parameters, i.e. an attacker cannot affect the negotiated parameters. A single session of EDHOC does not include negotiation of cipher suites, but it enables the Responder to verify that the selected cipher suite is the most preferred cipher suite by the Initiator which is supported by both the Initiator and the Responder.

As required by {{RFC7258}}, IETF protocols need to mitigate pervasive monitoring when possible. One way to mitigate pervasive monitoring is to use a key exchange that provides perfect forward secrecy. EDHOC therefore only supports methods with perfect forward secrecy. To limit the effect of breaches, it is important to limit the use of symmetrical group keys for bootstrapping. EDHOC therefore strives to make the additional cost of using raw public keys and self-signed certificates as small as possible. Raw public keys and self-signed certificates are not a replacement for a public key infrastructure, but SHOULD be used instead of symmetrical group keys for bootstrapping.

Compromise of the long-term keys (private signature or static DH keys) does not compromise the security of completed EDHOC exchanges. Compromising the private authentication keys of one party lets an active attacker impersonate that compromised party in EDHOC exchanges with other parties, but does not let the attacker impersonate other parties in EDHOC exchanges with the compromised party. Compromise of the long-term keys does not enable a passive attacker to compromise future session keys. Compromise of the HDKF input parameters (ECDH shared secret) leads to compromise of all session keys derived from that compromised shared secret. Compromise of one session key does not compromise other session keys. Compromise of PRK_4x3m leads to compromise of all exported keying material derived after the last invocation of the EDHOC-KeyUpdate function.

EDHOC provides a minimum of 64-bit security against online brute force attacks and a minimum of 128-bit security against offline brute force attacks. This is in line with IPsec, TLS, and COSE. To break 64-bit security against online brute force an attacker would on average have to send 4.3 billion messages per second for 68 years, which is very infeasable in contrained IoT radio technologies.

After sending message_3, the Initiator is assured that no other party than the Responder can compute the key PRK_4x3m (implicit key authentication). The Initiator does however not know that the Responder has actually computed the key PRK_4x3m. While the Initiator can securely send protected application data, the Initiator SHOULD NOT permanently store the keying material PRK_4x3m and TH_4 until the Initiator is assured that the Responder has actually computed the key PRK_4x3m (explicit key confirmation). Explicit key confirmation is e.g. assured when the Initiator has verified an OSCORE message or message_4 from the Responder. After verifying message_3, the Responder is assured that the Initiator has calculated the key PRK_4x3m (explicit key confirmation) and that no other party than the Responder can compute the key. The Responder can securely send protected application data and store the keying material PRK_4x3m and TH_4.

Key compromise impersonation (KCI): In EDHOC authenticated with signature keys, EDHOC provides KCI protection against an attacker having access to the long term key or the ephemeral secret key. With static Diffie-Hellman key authentication, KCI protection would be provided against an attacker having access to the long-term Diffie-Hellman key, but not to an attacker having access to the ephemeral secret key. Note that the term KCI has typically been used for compromise of long-term keys, and that an attacker with access to the ephemeral secret key can only attack that specific protocol run.

Repudiation: In EDHOC authenticated with signature keys, the Initiator could theoretically prove that the Responder performed a run of the protocol by presenting the private ephemeral key, and vice versa. Note that storing the private ephemeral keys violates the protocol requirements. With static Diffie-Hellman key authentication, both parties can always deny having participated in the protocol.

## Cryptographic Considerations
The security of the SIGMA protocol requires the MAC to be bound to the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism. EDHOC implements SIGMA-I using a MAC-then-Sign approach.

To reduce message overhead EDHOC does not use explicit nonces and instead rely on the ephemeral public keys to provide randomness to each session. A good amount of randomness is important for the key generation, to provide liveness, and to protect against interleaving attacks. For this reason, the ephemeral keys MUST NOT be reused, and both parties SHALL generate fresh random ephemeral key pairs.

As discussed the {{SIGMA}}, the encryption of message_2 does only need to protect against passive attacker as active attackers can always get the Responders identity by sending their own message_1. EDHOC uses the Expand function (typically HKDF-Expand) as a binary additive stream cipher. HKDF-Expand provides better confidentiality than AES-CTR but is not often used as it is slow on long messages, and most applications require both IND-CCA confidentiality as well as integrity protection. For the encryption of message_2, any speed difference is negligible, IND-CCA does not increase security, and integrity is provided by the inner MAC (and signature depending on method).

The data rates in many IoT deployments are very limited. Given that the application keys are protected as well as the long-term authentication keys they can often be used for years or even decades before the cryptographic limits are reached. If the application keys established through EDHOC need to be renewed, the communicating parties can derive application keys with other labels or run EDHOC again.

## Cipher Suites and Cryptographic Algorithms

For many constrained IoT devices it is problematic to support more than one cipher suite. Existing devices can be expected to support either ECDSA or EdDSA. To enable as much interoperability as we can reasonably achieve, less constrained devices SHOULD implement both cipher suite 0 (AES-CCM-16-64-128, SHA-256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256) and cipher suite 2 (AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256). Constrained endpoints SHOULD implement cipher suite 0 or cipher suite 2. Implementations only need to implement the algorithms needed for their supported methods. 

When using private cipher suite or registering new cipher suites, the choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. The Initiator and the Responder should enforce a minimum security level.

The hash algorithms SHA-1 and SHA-256/64 (256-bit Hash truncated to 64-bits) SHALL NOT be be supported for use in EDHOC except for certificate identification with x5u and c5u. Note that secp256k1 is only defined for use with ECDSA and not for ECDH.

## Unprotected Data

The Initiator and the Responder must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to AD_1, ID_CRED_R, AD_2, and ERR_MSG. Using the same AD_1 in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. Another consideration is that the list of supported cipher suites may potentially be used to identify the application.

The Initiator and the Responder must also make sure that unauthenticated data does not trigger any harmful actions. In particular, this applies to AD_1 and ERR_MSG.

## Denial-of-Service

EDHOC itself does not provide countermeasures against Denial-of-Service attacks. By sending a number of new or replayed message_1 an attacker may cause the Responder to allocate state, perform cryptographic operations, and amplify messages. To mitigate such attacks, an implementation SHOULD rely on lower layer mechanisms such as the Echo option in CoAP {{I-D.ietf-core-echo-request-tag}} that forces the initiator to demonstrate reachability at its apparent network address.

## Implementation Considerations

The availability of a secure random number generator is essential for the security of EDHOC. If no true random number generator is available, a truly random seed MUST be provided from an external source and used with a cryptographically secure pseudorandom number generator. As each pseudorandom number must only be used once, an implementation need to get a new truly random seed after reboot, or continuously store state in nonvolatile memory, see ({{RFC8613}}, Appendix B.1.1) for issues and solution approaches for writing to nonvolatile memory. Intentionally or unintentionally weak or predictable pseudorandom number generators can be abused or exploited for malicious purposes. {{RFC8937}} describes a way for security protocol implementations to augment their (pseudo)random number generators using a long-term private keys and a deterministic signature function. This improves randomness from broken or otherwise subverted random number generators. The same idea can be used with other secrets and functions such as a Diffie-Hellman function or a symmetric secret and a PRF like HMAC or KMAC. It is RECOMMENDED to not trust a single source of randomness and to not put unaugmented random numbers on the wire.

If ECDSA is supported, "deterministic ECDSA" as specified in {{RFC6979}} MAY be used. Pure deterministic elliptic-curve signatures such as deterministic ECDSA and EdDSA have gained popularity over randomized ECDSA as their security do not depend on a source of high-quality randomness. Recent research has however found that implementations of these signature algorithms may be vulnerable to certain side-channel and
fault injection attacks due to their determinism. See e.g. Section 1 of {{draft-mattsson-cfrg-det-sigs-with-noise}} for a list of attack papers. As suggested in Section 2.1.1 of {{RFC8152}} this can be adressed by combining randomness and determinism.

The referenced processing instructions in {{SP-800-56A}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed. The ECDH shared secrets, keys, and IVs MUST be secret. Implementations should provide countermeasures to side-channel attacks such as timing attacks. Depending on the selected curve, the parties should perform various validations of each other's public keys, see e.g. Section 5 of {{SP-800-56A}}.

The Initiator and the Responder are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported. The private authentication keys MUST be kept secret.

The Initiator and the Responder are allowed to select the connection identifiers C_I and C_R, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent application protocol (e.g. OSCORE {{RFC8613}}). The choice of connection identifier is not security critical in EDHOC but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong connection identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieve the wrong security context (which also terminates the protocol as the message cannot be verified).

The Responder MUST finish the verification step of message_3 before passing AD_3 to the application.

If two nodes unintentionally initiate two simultaneous EDHOC message exchanges with each other even if they only want to complete a single EDHOC message exchange, they MAY terminate the exchange with the lexicographically smallest G_X. If the two G_X values are equal, the received message_1 MUST be discarded to mitigate reflection attacks. Note that in the case of two simultaneous EDHOC exchanges where the nodes only complete one and where the nodes have different preferred cipher suites, an attacker can affect which of the two nodes’ preferred cipher suites will be used by blocking the other exchange.

If supported by the device, it is RECOMMENDED that at least the long-term private keys is stored in a Trusted Execution Environment (TEE) and that sensitive operations using these keys are performed inside the TEE. To achieve even higher security it is RECOMMENDED that additional operations such as ephemeral key generation, all computations of shared secrets, and storage of the PRK keys can be done inside the TEE. The TEE can also be used to protect the EDHOC and application protocol (e.g. OSCORE) implementation using some form of "secure boot", memory protection etc. Typically an adversary with physical access to a device can be assumed to gain access to all information outside of the TEE, but none of the information inside the TEE.

## Other Documents Referencing EDHOC

EDHOC has been analyzed in several other documents. A formal verification of EDHOC was done in {{SSR18}}, an analysis of EDHOC for certificate enrollment was done in {{Kron18}}, the use of EDHOC in LoRaWAN is analyzed in {{LoRa1}} and {{LoRa2}}, the use of EDHOC in IoT bootstrapping is analyzed in {{Perez18}}, and the use of EDHOC in 6TiSCH is described in {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}. 

# IANA Considerations {#iana}

## EDHOC Cipher Suites Registry {#suites-registry}

IANA has created a new registry titled "EDHOC Cipher Suites" under the new heading "EDHOC". The registration procedure is "Expert Review". The columns of the registry are Value, Array, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~~~~~~~~~~~~~
Value: -24
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -23
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -22
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -21
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 0
Array: 10, 5, 4, -8, 6, 10, 5
Desc: AES-CCM-16-64-128, SHA-256, X25519, EdDSA, Ed25519,
      AES-CCM-16-64-128, SHA-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 1
Array: 30, 5, 4, -8, 6, 10, 5
Desc: AES-CCM-16-128-128, SHA-256, X25519, EdDSA, Ed25519,
      AES-CCM-16-64-128, SHA-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 2
Array: 10, 5, 1, -7, 1, 10, 5
Desc: AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256,
      AES-CCM-16-64-128, SHA-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 3
Array: 30, 5, 1, -7, 1, 10, 5
Desc: AES-CCM-16-128-128, SHA-256, P-256, ES256, P-256,
      AES-CCM-16-64-128, SHA-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 4
Array: 1, -16, 4, -7, 1, 1, -16
Desc: A128GCM, SHA-256, X25519, ES256, P-256,
      A128GCM, SHA-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 5
Array: 3, -43, 2, -35, 2, 3, -43 
Desc: A256GCM, SHA-384, P-384, ES384, P-384,
      A256GCM, SHA-384
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~


## EDHOC Method Type Registry {#method-types}

IANA has created a new registry titled "EDHOC Method Type" under the new heading "EDHOC". The registration procedure is "Expert Review". The columns of the registry are Value, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry is shown in {{fig-method-types}}.


## The Well-Known URI Registry

IANA has added the well-known URI 'edhoc' to the Well-Known URIs registry.

- URI suffix: edhoc

- Change controller: IETF

- Specification document(s): \[\[this document\]\]

- Related information: None

## Media Types Registry

IANA has added the media type 'application/edhoc' to the Media Types registry.

- Type name: application

- Subtype name: edhoc

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

## CoAP Content-Formats Registry

IANA has added the media type 'application/edhoc' to the CoAP Content-Formats registry.

-  Media Type: application/edhoc

-  Encoding:

-  ID: TBD42

-  Reference: \[\[this document\]\]

## Expert Review Instructions

The IANA Registries established in this document is defined as "Expert Review". This section gives some general guidelines for what the experts should be looking for, but they are being designated as experts for a reason so they should be given substantial latitude.

Expert reviewers should take into consideration the following points:

* Clarity and correctness of registrations. Experts are expected to check the clarity of purpose and use of the requested entries. Expert needs to make sure the values of algorithms are taken from the right registry, when that's required. Expert should consider requesting an opinion on the correctness of registered parameters from relevant IETF working groups. Encodings that do not meet these objective of clarity and completeness should not be registered.
* Experts should take into account the expected usage of fields when approving point assignment. The length of the encoded value should be weighed against how many code points of that length are left, the size of device it will be used on, and the number of code points left that encode to that size.
* Specifications are recommended. When specifications are not provided, the description provided needs to have sufficient information to verify the points above.

--- back

# Use of CBOR, CDDL and COSE in EDHOC {#CBORandCOSE}

This Appendix is intended to simplify for implementors not familiar with CBOR {{RFC8949}}, CDDL {{RFC8610}}, COSE {{RFC8152}}, and HKDF {{RFC5869}}.

## CBOR and CDDL  {#CBOR}

The Concise Binary Object Representation (CBOR) {{RFC8949}} is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values (e.g. null), byte strings (bstr), and text strings (tstr), CBOR also supports arrays \[\]  of data items, maps {} of pairs of data items, and sequences {{RFC8742}} of data items. Some examples are given below. For a complete specification and more examples, see {{RFC8949}} and {{RFC8610}}. We recommend implementors to get used to CBOR by using the CBOR playground {{CborMe}}. 

~~~~~~~~~~~~~~~~~~~~~~~
Diagnostic          Encoded              Type
------------------------------------------------------------------
1                   0x01                 unsigned integer    
24                  0x1818               unsigned integer
-24                 0x37                 negative integer
-25                 0x3818               negative integer 
null                0xf6                 simple value 
h'12cd'             0x4212cd             byte string
'12cd'              0x4431326364         byte string
"12cd"              0x6431326364         text string
{ 4 : h'cd' }       0xa10441cd           map                 
<< 1, 2, null >>    0x430102f6           byte string
[ 1, 2, null ]      0x830102f6           array      
( 1, 2, null )      0x0102f6             sequence
1, 2, null          0x0102f6             sequence
------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}

## COSE {#COSE}

CBOR Object Signing and Encryption (COSE) {{RFC8152}} describes how to create and process signatures, message authentication codes, and encryption using CBOR. COSE builds on JOSE, but is adapted to allow more efficient processing in constrained devices. EDHOC makes use of COSE_Key, COSE_Encrypt0, and COSE_Sign1 objects.

# Test Vectors {#vectors}

This appendix provides detailed test vectors based on v-02 of this specification, to ease implementation and ensure interoperability. In addition to hexadecimal, all CBOR data items and sequences are given in CBOR diagnostic notation. The test vectors use the default mapping to CoAP where the Initiator acts as CoAP client (this means that corr = 1). 

A more extensive test vector suite covering more combinations of authentication method used between Initiator and Responder and related code to generate them can be found at https://github.com/lake-wg/edhoc/tree/master/test-vectors .

## Test Vectors for EDHOC Authenticated with Signature Keys (x5t)

<!-- Test vector index (int) 22900 -->

EDHOC with signature authentication and X.509 certificates is used. In this test vector, the hash value 'x5t' is used to identify the certificate.

~~~~~~~~~~~~~~~~~~~~~~~
method (Signature Authentication)
0
~~~~~~~~~~~~~~~~~~~~~~~

CoAP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

From there, METHOD_CORR has the following value:

~~~~~~~~~~~~~~~~~~~~~~~
METHOD_CORR (4 * method + corr) (int)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

There is only one supported cipher suite indicated by the Initiator. 

~~~~~~~~~~~~~~~~~~~~~~~
Supported Cipher Suites (1 byte)
00
~~~~~~~~~~~~~~~~~~~~~~~

The cipher suite selected by the Initiator is the most preferred:

~~~~~~~~~~~~~~~~~~~~~~~
Selected Cipher Suite (int)
0
~~~~~~~~~~~~~~~~~~~~~~~

Cipher suite 0 is supported by both the Initiator and the Responder, see {{cipher-suites}}.

### Message_1

The Initiator generates its ephemeral key pair.

~~~~~~~~~~~~~~~~~~~~~~~
X (Initiator's ephemeral private key) (32 bytes)
8f 78 1a 09 53 72 f8 5b 6d 9f 61 09 ae 42 26 11 73 4d 7d bf a0 06 9a 2d 
f2 93 5b b2 e0 53 bf 35
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_X (Initiator's ephemeral public key) (32 bytes)
89 8f f7 9a 02 06 7a 16 ea 1e cc b9 0f a5 22 46 f5 aa 4d d6 ec 07 6b ba 
02 59 d9 04 b7 ec 8b 0c
~~~~~~~~~~~~~~~~~~~~~~~

The Initiator chooses a connection identifier C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by Initiator (1 bytes)
09
~~~~~~~~~~~~~~~~~~~~~~~

Note that since C_I is a byte string of length one, it is encoded as the corresponding integer subtracted by 24 (see bstr_identifier in {{bstr_id}}). Thus 0x09 = 09, 9 - 24 = -15, and -15 in CBOR encoding is equal to 0x2e.

~~~~~~~~~~~~~~~~~~~~~~~
C_I (1 byte)
2e
~~~~~~~~~~~~~~~~~~~~~~~ 

Since no unprotected opaque auxiliary data is sent in the message exchanges:

~~~~~~~~~~~~~~~~~~~~~~~
AD_1 (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The list of supported cipher suites needs to contain the selected cipher suite. The initiator truncates the list of supported cipher suites to one cipher suite only. In this case there is only one supported cipher suite indicated, 00. 

Because one single selected cipher suite is conveyed, it is encoded as an int instead of an array:

~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I (int)
0
~~~~~~~~~~~~~~~~~~~~~~~

With SUITES_I = 0, message_1 is constructed as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  h'',
  1,
  0,
  h'898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c',
  -15
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
40 01 00 58 20 89 8f f7 9a 02 06 7a 16 ea 1e cc b9 0f a5 22 46 f5 aa 4d 
d6 ec 07 6b ba 02 59 d9 04 b7 ec 8b 0c 2e 
~~~~~~~~~~~~~~~~~~~~~~~

### Message_2

Since METHOD_CORR mod 4 equals 1, C_I is omitted from data_2.

The Responder generates the following ephemeral key pair.

~~~~~~~~~~~~~~~~~~~~~~~
Y (Responder's ephemeral private key) (32 bytes)
fd 8c d8 77 c9 ea 38 6e 6a f3 4f f7 e6 06 c4 b6 4c a8 31 c8 ba 33 13 4f 
d4 cd 71 67 ca ba ec da
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_Y (Responder's ephemeral public key) (32 bytes)
71 a3 d5 99 c2 1d a1 89 02 a1 ae a8 10 b2 b6 38 2c cd 8d 5f 9b f0 19 52 
81 75 4c 5e bc af 30 1e 
~~~~~~~~~~~~~~~~~~~~~~~

From G_X and Y or from G_Y and X the ECDH shared secret is computed:

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (ECDH shared secret) (32 bytes)
2b b7 fa 6e 13 5b c3 35 d0 22 d6 34 cb fb 14 b3 f5 82 f3 e2 e3 af b2 b3 
15 04 91 49 5c 61 78 2b 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce for calculating the 'ciphertext' are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2e = HMAC-SHA-256(salt, G_XY)

Salt is the empty byte string.

~~~~~~~~~~~~~~~~~~~~~~~
salt (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_2e is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_2e (32 bytes)
ec 62 92 a0 67 f1 37 fc 7f 59 62 9d 22 6f bf c4 e0 68 89 49 f6 62 a9 7f 
d8 2f be b7 99 71 39 4a
~~~~~~~~~~~~~~~~~~~~~~~

The Responder's sign/verify key pair is the following:

~~~~~~~~~~~~~~~~~~~~~~~
SK_R (Responders's private authentication key) (32 bytes)
df 69 27 4d 71 32 96 e2 46 30 63 65 37 2b 46 83 ce d5 38 1b fc ad cd 44 
0a 24 c3 91 d2 fe db 94
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
PK_R (Responders's public authentication key) (32 bytes)
db d9 dc 8c d0 3f b7 c3 91 35 11 46 2b b2 38 16 47 7c 6b d8 d6 6e f5 a1 
a0 70 ac 85 4e d7 3f d2
~~~~~~~~~~~~~~~~~~~~~~~


Since neither the Initiator nor the Responder authenticates with a static Diffie-Hellman key, PRK_3e2m = PRK_2e

~~~~~~~~~~~~~~~~~~~~~~~
PRK_3e2m (32 bytes)
ec 62 92 a0 67 f1 37 fc 7f 59 62 9d 22 6f bf c4 e0 68 89 49 f6 62 a9 7f 
d8 2f be b7 99 71 39 4a 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder chooses a connection identifier C_R.

~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by Responder (1 byte)
00
~~~~~~~~~~~~~~~~~~~~~~~

Note that since C_R is a byte string of length one, it is encoded as the corresponding integer subtracted by 24 (see bstr_identifier in {{bstr_id}}). Thus 0x00 = 0, 0 - 24 = -24, and -24 in CBOR encoding is equal to 0x37.

~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
37
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of G_Y and C_R.

~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e',
  -24
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (35 bytes)
58 20 71 a3 d5 99 c2 1d a1 89 02 a1 ae a8 10 b2 b6 38 2c cd 8d 5f 9b f0 
19 52 81 75 4c 5e bc af 30 1e 37 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1, compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (73 bytes)
40 01 00 58 20 89 8f f7 9a 02 06 7a 16 ea 1e cc b9 0f a5 22 46 f5 aa 4d 
d6 ec 07 6b ba 02 59 d9 04 b7 ec 8b 0c 2e 58 20 71 a3 d5 99 c2 1d a1 89 
02 a1 ae a8 10 b2 b6 38 2c cd 8d 5f 9b f0 19 52 81 75 4c 5e bc af 30 1e 
37 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (32 bytes)
65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 7b fc 47 49 9e 
58 ca ab 23 a4 2c b8 40
~~~~~~~~~~~~~~~~~~~~~~~

The Responder's subject name is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
Responders's subject name (text string)
""
~~~~~~~~~~~~~~~~~~~~~~~


CRED_R is the certificate (X509_R) encoded as a CBOR byte string:
(Note that in this version of the test vectors CRED_R is not a real certificate, but instead a string of random bytes is used)

~~~~~~~~~~~~~~~~~~~~~~~
X509_R (100 bytes)
c7 88 37 00 16 b8 96 5b db 20 74 bf f8 2e 5a 20 e0 9b ec 21 f8 40 6e 86 
44 2b 87 ec 3f f2 45 b7 0a 47 62 4d c9 cd c6 82 4b 2a 4c 52 e9 5e c9 d6 
b0 53 4b 71 c2 b4 9e 4b f9 03 15 00 ce e6 86 99 79 c2 97 bb 5a 8b 38 1e 
98 db 71 41 08 41 5e 5c 50 db 78 97 4c 27 15 79 b0 16 33 a3 ef 62 71 be 
5c 22 5e b2
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (102 bytes)
58 64 c7 88 37 00 16 b8 96 5b db 20 74 bf f8 2e 5a 20 e0 9b ec 21 f8 40 
6e 86 44 2b 87 ec 3f f2 45 b7 0a 47 62 4d c9 cd c6 82 4b 2a 4c 52 e9 5e 
c9 d6 b0 53 4b 71 c2 b4 9e 4b f9 03 15 00 ce e6 86 99 79 c2 97 bb 5a 8b 
38 1e 98 db 71 41 08 41 5e 5c 50 db 78 97 4c 27 15 79 b0 16 33 a3 ef 62 
71 be 5c 22 5e b2 
~~~~~~~~~~~~~~~~~~~~~~~

And because certificates are identified by a hash value with the 'x5t' parameter, ID_CRED_R is the following:

ID_CRED_R = { 34 : COSE_CertHash }. In this example, the hash algorithm used is SHA-2 256-bit with hash truncated to 64-bits (value -15). The hash value is calculated over the certificate X509_R.

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{
  34: [-15, h'6844078A53F312F5']
}
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (14 bytes)
a1 18 22 82 2e 48 68 44 07 8a 53 f3 12 f5 
~~~~~~~~~~~~~~~~~~~~~~~

Since no unprotected opaque auxiliary data is sent in the message exchanges:

~~~~~~~~~~~~~~~~~~~~~~~
AD_2  (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Plaintext is defined as the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
P_2m (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Enc_structure is defined as follows: \[ "Encrypt0", << ID_CRED_R >>, << TH_2, CRED_R >> \]

~~~~~~~~~~~~~~~~~~~~~~~
A_2m =
[
  "Encrypt0", 
  h'A11822822E486844078A53F312F5',
  h'5820655CAB4D8CF4DE31A8A154CA064E20C9046EC37BFC47499E58CAAB23A42CB840
  5864C788370016B8965BDB2074BFF82E5A20E09BEC21F8406E86442B87EC3FF245B70A
  47624DC9CDC6824B2A4C52E95EC9D6B0534B71C2B49E4BF9031500CEE6869979C297BB
  5A8B381E98DB714108415E5C50DB78974C271579B01633A3EF6271BE5C225EB2'
  ]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2m (CBOR-encoded) (163 bytes)
83 68 45 6e 63 72 79 70 74 30 4e a1 18 22 82 2e 48 68 44 07 8a 53 f3 12 
f5 58 88 58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 
7b fc 47 49 9e 58 ca ab 23 a4 2c b8 40 58 64 c7 88 37 00 16 b8 96 5b db 
20 74 bf f8 2e 5a 20 e0 9b ec 21 f8 40 6e 86 44 2b 87 ec 3f f2 45 b7 0a 
47 62 4d c9 cd c6 82 4b 2a 4c 52 e9 5e c9 d6 b0 53 4b 71 c2 b4 9e 4b f9 
03 15 00 ce e6 86 99 79 c2 97 bb 5a 8b 38 1e 98 db 71 41 08 41 5e 5c 50 
db 78 97 4c 27 15 79 b0 16 33 a3 ef 62 71 be 5c 22 5e b2  
~~~~~~~~~~~~~~~~~~~~~~~

info for K_2m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2m =
[
  10,
  h'655CAB4D8CF4DE31A8A154CA064E20C9046EC37BFC47499E58CAAB23A42CB840', 
  "K_2m",
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2m (CBOR-encoded) (42 bytes)
84 0a 58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 7b 
fc 47 49 9e 58 ca ab 23 a4 2c b8 40 64 4b 5f 32 6d 10 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, K_2m is computed. Key K_2m is the output of HKDF-Expand(PRK_3e2m, info, L), where L is the length of K_2m, so 16 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
K_2m (16 bytes)
31 0c 1d 46 66 00 6b 3d 51 96 31 3f 87 d8 81 db
~~~~~~~~~~~~~~~~~~~~~~~

info for IV_2m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2m =
[
  10,
  h'655CAB4D8CF4DE31A8A154CA064E20C9046EC37BFC47499E58CAAB23A42CB840', 
  "IV_2m",
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2m (CBOR-encoded) (43 bytes)
84 0a 58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 7b 
fc 47 49 9e 58 ca ab 23 a4 2c b8 40 65 49 56 5f 32 6d 0d
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_2m is computed. IV_2m is the output of HKDF-Expand(PRK_3e2m, info, L), where L is the length of IV_2m, so 13 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
IV_2m (13 bytes)
b1 aa 78 11 5b 5c 18 06 e3 b8 85 cb f7 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, COSE_Encrypt0 is computed from the parameters above.

* protected header = CBOR-encoded ID_CRED_R

* external_aad = A_2m

* empty plaintext = P_2m

~~~~~~~~~~~~~~~~~~~~~~~
MAC_2 (8 bytes)
c1 d1 0e 48 96 1c 71 85
~~~~~~~~~~~~~~~~~~~~~~~

To compute the Signature_or_MAC_2, the key is the private authentication key of the Responder and 
the message M_2 to be signed = \[ "Signature1", << ID_CRED_R >>, << TH_2, CRED_R, ? AD_2 >>, MAC_2 \]

~~~~~~~~~~~~~~~~~~~~~~~
M_2 = 
[
  "Signature1",
  h'A11822822E486844078A53F312F5',
  h'5820655CAB4D8CF4DE31A8A154CA064E20C9046EC37BFC47499E58CAAB23A42CB84
  05864C788370016B8965BDB2074BFF82E5A20E09BEC21F8406E86442B87EC3FF245B7
  0A47624DC9CDC6824B2A4C52E95EC9D6B0534B71C2B49E4BF9031500CEE6869979C29
  7BB5A8B381E98DB714108415E5C50DB78974C271579B01633A3EF6271BE5C225EB2',
  h'C1D10E48961C7185'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
M_2 (174 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 68 44 07 8a 53 
f3 12 f5 58 88 58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 
6e c3 7b fc 47 49 9e 58 ca ab 23 a4 2c b8 40 58 64 c7 88 37 00 16 b8 96 
5b db 20 74 bf f8 2e 5a 20 e0 9b ec 21 f8 40 6e 86 44 2b 87 ec 3f f2 45 
b7 0a 47 62 4d c9 cd c6 82 4b 2a 4c 52 e9 5e c9 d6 b0 53 4b 71 c2 b4 9e 
4b f9 03 15 00 ce e6 86 99 79 c2 97 bb 5a 8b 38 1e 98 db 71 41 08 41 5e 
5c 50 db 78 97 4c 27 15 79 b0 16 33 a3 ef 62 71 be 5c 22 5e b2 48 c1 d1 
0e 48 96 1c 71 85 
~~~~~~~~~~~~~~~~~~~~~~~

Since the method = 0, Signature_or_Mac_3 is a signature:

~~~~~~~~~~~~~~~~~~~~~~~
Signature_or_MAC_2 (64 bytes)
fb 4f b1 9b 13 a9 31 e9 5d be b0 a1 20 15 bc b9 d6 58 a4 1e d3 68 b6 fd 
de ac 63 aa 94 7f 61 d8 76 15 64 34 84 7c dc 69 b8 d1 44 0a ea 85 07 6f 
4e 59 e6 79 7b 02 fc 63 b2 68 ea d3 f4 5e c8 0b 
~~~~~~~~~~~~~~~~~~~~~~~

CIPHERTEXT_2 is the ciphertext resulting from XOR between plaintext and KEYSTREAM_2 which is derived from TH_2 and the pseudorandom key PRK_2e.

* plaintext = CBOR Sequence of the items ID_CRED_R and Signature_or_MAC_2, in this order (AD_2 is empty).

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2e (CBOR Sequence) (80 bytes)
a1 18 22 82 2e 48 68 44 07 8a 53 f3 12 f5 58 40 fb 4f b1 9b 13 a9 31 e9 
5d be b0 a1 20 15 bc b9 d6 58 a4 1e d3 68 b6 fd de ac 63 aa 94 7f 61 d8 
76 15 64 34 84 7c dc 69 b8 d1 44 0a ea 85 07 6f 4e 59 e6 79 7b 02 fc 63 
b2 68 ea d3 f4 5e c8 0b 
~~~~~~~~~~~~~~~~~~~~~~~

KEYSTREAM_2 = Expand( PRK, info, length ), where length is the length of the plaintext, so 80.

~~~~~~~~~~~~~~~~~~~~~~~
info for KEYSTREAM_2 =
[
  10,
  h'655CAB4D8CF4DE31A8A154CA064E20C9046EC37BFC47499E58CAAB23A42CB840',
  "KEYSTREAM_2",
  80
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for KEYSTREAM_2 (CBOR-encoded) (50 bytes)
84 0a 58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 7b 
fc 47 49 9e 58 ca ab 23 a4 2c b8 40 6b 4b 45 59 53 54 52 45 41 4d 5f 32 
18 50 
~~~~~~~~~~~~~~~~~~~~~~~

From there, KEYSTREAM_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
KEYSTREAM_2 (80 bytes)
92 58 b5 aa 14 1f ea 42 91 f2 78 51 ac b3 9a ac d5 4d 5d 4e 4e 21 cf aa 
55 f1 5d 58 5c 8e 04 ab f3 d8 47 ef 96 ac d5 d0 85 cb 19 8f 2b fc 0b c5 
54 1c 95 68 3e e2 13 db df 90 6a 28 b3 06 dc 77 b0 16 66 c8 c5 1f 99 6b 
9b f4 12 5e 5d e5 21 f8 
~~~~~~~~~~~~~~~~~~~~~~~

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (80 bytes)
33 40 97 28 3a 57 82 06 96 78 2b a2 be 46 c2 ec 2e 02 ec d5 5d 88 fe 43 
08 4f ed f9 7c 9b b8 12 25 80 e3 f1 45 c4 63 2d 5b 67 7a 25 bf 83 6a 1d 
22 09 f1 5c ba 9e cf b2 67 41 2e 22 59 83 db 18 fe 4f 80 b1 be 1d 65 08 
29 9c f8 8d a9 bb e9 f3 
~~~~~~~~~~~~~~~~~~~~~~~

message_2 is the CBOR Sequence of data_2 and CIPHERTEXT_2, in this order:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  data_2,
  h'334097283A57820696782BA2BE46C2EC2E02ECD55D88FE43084FEDF97C9BB8122580
  E3F145C4632D5B677A25BF836A1D2209F15CBA9ECFB267412E225983DB18FE4F80B1BE
  1D6508299CF88DA9BBE9F3'
) 
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (117 bytes)
58 20 71 a3 d5 99 c2 1d a1 89 02 a1 ae a8 10 b2 b6 38 2c cd 8d 5f 9b f0 
19 52 81 75 4c 5e bc af 30 1e 37 58 50 33 40 97 28 3a 57 82 06 96 78 2b 
a2 be 46 c2 ec 2e 02 ec d5 5d 88 fe 43 08 4f ed f9 7c 9b b8 12 25 80 e3 
f1 45 c4 63 2d 5b 67 7a 25 bf 83 6a 1d 22 09 f1 5c ba 9e cf b2 67 41 2e 
22 59 83 db 18 fe 4f 80 b1 be 1d 65 08 29 9c f8 8d a9 bb e9 f3 
~~~~~~~~~~~~~~~~~~~~~~~

### Message_3

Since corr equals 1, C_R is not omitted from data_3.

The Initiator's sign/verify key pair is the following:

~~~~~~~~~~~~~~~~~~~~~~~
SK_I (Initiator's private authentication key) (32 bytes)
2f fc e7 a0 b2 b8 25 d3 97 d0 cb 54 f7 46 e3 da 3f 27 59 6e e0 6b 53 71 
48 1d c0 e0 12 bc 34 d7
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
PK_I (Responders's public authentication key) (32 bytes)
38 e5 d5 45 63 c2 b6 a4 ba 26 f3 01 5f 61 bb 70 6e 5c 2e fd b5 56 d2 e1 
69 0b 97 fc 3c 6d e1 49 
~~~~~~~~~~~~~~~~~~~~~~~

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_4x3m = HMAC-SHA-256 (PRK_3e2m, G_IY)

~~~~~~~~~~~~~~~~~~~~~~~
PRK_4x3m (32 bytes)
ec 62 92 a0 67 f1 37 fc 7f 59 62 9d 22 6f bf c4 e0 68 89 49 f6 62 a9 7f 
d8 2f be b7 99 71 39 4a 
~~~~~~~~~~~~~~~~~~~~~~~

data 3 is equal to C_R.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (1 bytes)
37
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2, and TH_2, compute the input to the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (117 bytes)
58 20 65 5c ab 4d 8c f4 de 31 a8 a1 54 ca 06 4e 20 c9 04 6e c3 7b fc 47 
49 9e 58 ca ab 23 a4 2c b8 40 58 50 33 40 97 28 3a 57 82 06 96 78 2b a2 
be 46 c2 ec 2e 02 ec d5 5d 88 fe 43 08 4f ed f9 7c 9b b8 12 25 80 e3 f1 
45 c4 63 2d 5b 67 7a 25 bf 83 6a 1d 22 09 f1 5c ba 9e cf b2 67 41 2e 22 
59 83 db 18 fe 4f 80 b1 be 1d 65 08 29 9c f8 8d a9 bb e9 f3 37
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (32 bytes)
75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 dc 95 f5 c7 4f 
72 5a 38 50 e4 4e 98 17 
~~~~~~~~~~~~~~~~~~~~~~~

The Initiator's subject name is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's subject name (text string)
""
~~~~~~~~~~~~~~~~~~~~~~~

CRED_I is the certificate (X509_I) encoded as a CBOR byte string:
(Note that in this version of the test vectors CRED_I is not a real certificate, but instead a string of random bytes is used)

~~~~~~~~~~~~~~~~~~~~~~~
X509_I (101 bytes)
54 13 20 4c 3e bc 34 28 a6 cf 57 e2 4c 9d ef 59 65 17 70 44 9b ce 7e c6 
56 1e 52 43 3a a5 5e 71 f1 fa 34 b2 2a 9c a4 a1 e1 29 24 ea e1 d1 76 60 
88 09 84 49 cb 84 8f fc 79 5f 88 af c4 9c be 8a fd d1 ba 00 9f 21 67 5e 
8f 6c 77 a4 a2 c3 01 95 60 1f 6f 0a 08 52 97 8b d4 3d 28 20 7d 44 48 65 
02 ff 7b dd a6
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (103 bytes)
58 65 54 13 20 4c 3e bc 34 28 a6 cf 57 e2 4c 9d ef 59 65 17 70 44 9b ce 
7e c6 56 1e 52 43 3a a5 5e 71 f1 fa 34 b2 2a 9c a4 a1 e1 29 24 ea e1 d1 
76 60 88 09 84 49 cb 84 8f fc 79 5f 88 af c4 9c be 8a fd d1 ba 00 9f 21 
67 5e 8f 6c 77 a4 a2 c3 01 95 60 1f 6f 0a 08 52 97 8b d4 3d 28 20 7d 44 
48 65 02 ff 7b dd a6 
~~~~~~~~~~~~~~~~~~~~~~~

And because certificates are identified by a hash value with the 'x5t' parameter, ID_CRED_I is the following:

ID_CRED_I = { 34 : COSE_CertHash }. In this example, the hash algorithm used is SHA-2 256-bit with hash truncated to 64-bits (value -15). The hash value is calculated over the certificate X509_I.

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{
  34: [-15, h'705D5845F36FC6A6']
}
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (14 bytes)
a1 18 22 82 2e 48 70 5d 58 45 f3 6f c6 a6 
~~~~~~~~~~~~~~~~~~~~~~~

Since no opaque auxiliary data is exchanged:

~~~~~~~~~~~~~~~~~~~~~~~
AD_3 (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Plaintext of the COSE_Encrypt is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
P_3m (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the CBOR Sequence of TH_3 and CRED_I, in this order:

~~~~~~~~~~~~~~~~~~~~~~~
A_3m (CBOR-encoded) (164 bytes)
83 68 45 6e 63 72 79 70 74 30 4e a1 18 22 82 2e 48 70 5d 58 45 f3 6f c6 
a6 58 89 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 
dc 95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 58 65 54 13 20 4c 3e bc 34 28 a6 
cf 57 e2 4c 9d ef 59 65 17 70 44 9b ce 7e c6 56 1e 52 43 3a a5 5e 71 f1 
fa 34 b2 2a 9c a4 a1 e1 29 24 ea e1 d1 76 60 88 09 84 49 cb 84 8f fc 79 
5f 88 af c4 9c be 8a fd d1 ba 00 9f 21 67 5e 8f 6c 77 a4 a2 c3 01 95 60 
1f 6f 0a 08 52 97 8b d4 3d 28 20 7d 44 48 65 02 ff 7b dd a6 
~~~~~~~~~~~~~~~~~~~~~~~

Info for K_3m is computed as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3m =
[
  10,
  h'75EC51A0AFD33182734F2BD43ABA09BA484F13DC95F5C74F725A3850E44E9817',
  "K_3m",
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3m (CBOR-encoded) (42 bytes)
84 0a 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 dc 
95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 64 4b 5f 33 6d 10 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, K_3m is computed. Key K_3m is the output of HKDF-Expand(PRK_4x3m, info, L), where L is the length of K_2m, so 16 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
K_3m (16 bytes)
76 26 73 92 b8 b0 3e 73 c6 63 f8 c2 08 e9 00 db 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3m is the output of HKDF-Expand(PRK_4x3m, info, L), where L = 13 bytes.

Info for IV_3m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3m =
[
  10,
  h'75EC51A0AFD33182734F2BD43ABA09BA484F13DC95F5C74F725A3850E44E9817',
  "IV_3m",
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3m (CBOR-encoded) (43 bytes)
84 0a 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 dc 
95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 65 49 56 5f 33 6d 0d 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_3m is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3m (13 bytes)
c3 6e e0 35 4b 38 e6 1f ee 98 92 da 7e 
~~~~~~~~~~~~~~~~~~~~~~~

MAC_3 is the 'ciphertext' of the COSE_Encrypt0:

~~~~~~~~~~~~~~~~~~~~~~~
MAC_3 (8 bytes)
6b ec ad 03 a1 b7 5a 45 
~~~~~~~~~~~~~~~~~~~~~~~

Since the method = 0, Signature_or_Mac_3 is a signature:

* The message M_3 to be signed = \[ "Signature1", << ID_CRED_I >>, << TH_3, CRED_I >>, MAC_3 \] 

* The signing key is the private authentication key of the Initiator.

~~~~~~~~~~~~~~~~~~~~~~~
M_3 =
[
  "Signature1", 
  h'A11822822E48705D5845F36FC6A6', 
  h'582075EC51A0AFD33182734F2BD43ABA09BA484F13DC95F5C74F725A3850E44E981
  758655413204C3EBC3428A6CF57E24C9DEF59651770449BCE7EC6561E52433AA55E71
  F1FA34B22A9CA4A1E12924EAE1D1766088098449CB848FFC795F88AFC49CBE8AFDD1B
  A009F21675E8F6C77A4A2C30195601F6F0A0852978BD43D28207D44486502FF7BDD
  A6',
  h'6BECAD03A1B75A45']
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
M_3 (175 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 4e a1 18 22 82 2e 48 70 5d 58 45 f3 
6f c6 a6 58 89 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 
4f 13 dc 95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 58 65 54 13 20 4c 3e bc 34 
28 a6 cf 57 e2 4c 9d ef 59 65 17 70 44 9b ce 7e c6 56 1e 52 43 3a a5 5e 
71 f1 fa 34 b2 2a 9c a4 a1 e1 29 24 ea e1 d1 76 60 88 09 84 49 cb 84 8f 
fc 79 5f 88 af c4 9c be 8a fd d1 ba 00 9f 21 67 5e 8f 6c 77 a4 a2 c3 01 
95 60 1f 6f 0a 08 52 97 8b d4 3d 28 20 7d 44 48 65 02 ff 7b dd a6 48 6b 
ec ad 03 a1 b7 5a 45 
~~~~~~~~~~~~~~~~~~~~~~~

From there, the signature can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
Signature_or_MAC_3 (64 bytes)
da df eb ae 51 7a 6b 1c 67 5b e8 c7 75 64 59 bf 69 a5 1c 24 0d 4c 5f 2c 
87 21 37 d2 3a 35 e6 37 a1 20 0d af c1 e6 16 d5 9d 88 30 8e d1 01 5c fd 
3b c7 a9 87 67 c5 7b a3 5d 85 41 22 6b 18 cc 06 
~~~~~~~~~~~~~~~~~~~~~~~ 

Finally, the outer COSE_Encrypt0 is computed.

The Plaintext is the following CBOR Sequence: 
plaintext = ( ID_CRED_I , Signature_or_MAC_3 )

~~~~~~~~~~~~~~~~~~~~~~~
P_3ae (CBOR Sequence) (80 bytes)
a1 18 22 82 2e 48 70 5d 58 45 f3 6f c6 a6 58 40 da df eb ae 51 7a 6b 1c 
67 5b e8 c7 75 64 59 bf 69 a5 1c 24 0d 4c 5f 2c 87 21 37 d2 3a 35 e6 37 
a1 20 0d af c1 e6 16 d5 9d 88 30 8e d1 01 5c fd 3b c7 a9 87 67 c5 7b a3 
5d 85 41 22 6b 18 cc 06 
~~~~~~~~~~~~~~~~~~~~~~~

The Associated data A is the following:
Associated data A = \[ "Encrypt0", h'', TH_3 \]

~~~~~~~~~~~~~~~~~~~~~~~
A_3ae (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b 
d4 3a ba 09 ba 48 4f 13 dc 95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3ae is the output of HKDF-Expand(PRK_3e2m, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3ae = 
[
  10,
  h'75EC51A0AFD33182734F2BD43ABA09BA484F13DC95F5C74F725A3850E44E9817',
  "K_3ae",
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3ae (CBOR-encoded) (43 bytes)
84 0a 58 20 a2 39 a6 27 ad a3 80 2d b8 da e5 1e c3 92 bf eb 92 6d 39 3e 
f6 ee e4 dd b3 2e 4a 27 ce 93 58 da 65 4b 5f 33 61 65 10 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3ae, so 16 bytes.

From these parameters, K_3ae is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3ae (16 bytes)
ec 25 67 ed b5 7e ea c0 e7 74 f1 0f 19 cd 3e cd
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3ae is the output of HKDF-Expand(PRK_3e2m, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3ae =
[
  10,
  h'75EC51A0AFD33182734F2BD43ABA09BA484F13DC95F5C74F725A3850E44E9817',
  "IV_3ae", 
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3ae (CBOR-encoded) (44 bytes)
84 0a 58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 dc 
95 f5 c7 4f 72 5a 38 50 e4 4e 98 17 66 49 56 5f 33 61 65 0d 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3ae, so 13 bytes.

From these parameters, IV_3ae is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3ae (13 bytes)
22 79 12 aa 14 9a 21 15 e4 c8 f3 c0 eb 
~~~~~~~~~~~~~~~~~~~~~~~

Using the parameters above, the 'ciphertext' CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (88 bytes)
1c 66 82 d6 08 d6 ad ce 9f 82 a3 eb 13 43 8d c7 db 43 aa 7e f0 b1 ac c3 
62 fe 6f 74 d8 c3 9b 31 de fb 9d 6e 9e 3a fb 24 a4 7f 9b 8b e7 21 22 63 
7d 92 2a 43 a1 d7 77 0b 87 19 be 1a 51 7b 75 be f9 65 81 2c 10 f7 d7 cd 
c6 63 bd aa 09 c5 c9 fa 34 2f eb 07 a3 c2 45 fa 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameter above, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).

~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'00',
  h'1C6682D608D6ADCE9F82A3EB13438DC7DB43AA7EF0B1ACC362FE6F74D8C39B31DEFB
  9D6E9E3AFB24A47F9B8BE72122637D922A43A1D7770B8719BE1A517B75BEF965812C10
  F7D7CDC663BDAA09C5C9FA342FEB07A3C245FA'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (91 bytes)
37 58 58 1c 66 82 d6 08 d6 ad ce 9f 82 a3 eb 13 43 8d c7 db 43 aa 7e f0 
b1 ac c3 62 fe 6f 74 d8 c3 9b 31 de fb 9d 6e 9e 3a fb 24 a4 7f 9b 8b e7 
21 22 63 7d 92 2a 43 a1 d7 77 0b 87 19 be 1a 51 7b 75 be f9 65 81 2c 10 
f7 d7 cd c6 63 bd aa 09 c5 c9 fa 34 2f eb 07 a3 c2 45 fa 
~~~~~~~~~~~~~~~~~~~~~~~



### OSCORE Security Context Derivation

From here, the Initiator and the Responder can derive an OSCORE Security Context, using the EDHOC-Exporter interface.

From TH_3 and CIPHERTEXT_3, compute the input to the transcript hash TH_4 = H( TH_3, CIPHERTEXT_3 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (124 bytes)
58 20 75 ec 51 a0 af d3 31 82 73 4f 2b d4 3a ba 09 ba 48 4f 13 dc 95 f5 
c7 4f 72 5a 38 50 e4 4e 98 17 58 58 1c 66 82 d6 08 d6 ad ce 9f 82 a3 eb 
13 43 8d c7 db 43 aa 7e f0 b1 ac c3 62 fe 6f 74 d8 c3 9b 31 de fb 9d 6e 
9e 3a fb 24 a4 7f 9b 8b e7 21 22 63 7d 92 2a 43 a1 d7 77 0b 87 19 be 1a 
51 7b 75 be f9 65 81 2c 10 f7 d7 cd c6 63 bd aa 09 c5 c9 fa 34 2f eb 07 
a3 c2 45 fa 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256(TH_3 , CIPHERTEXT_4)

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (32 bytes)
e6 2d fe 6d 32 36 a6 55 9d c6 ef 46 ff b4 ae c2 18 ee 46 fb 07 fd ad 59 
5f e7 8a 42 c9 f8 d7 fa 
~~~~~~~~~~~~~~~~~~~~~~~

The Master Secret and Master Salt are derived as follows:

Master Secret = EDHOC-Exporter( "OSCORE Master Secret", 16 ) = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Secret", 16) = Expand( PRK_4x3m, info_ms, 16 )

Master Salt   = EDHOC-Exporter( "OSCORE Master Salt", 8 ) = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Salt", 8) = Expand( PRK_4x3m, info_salt, 8 )

info_ms for OSCORE Master Secret is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info_ms = [
  10, 
  h'E62DFE6D3236A6559DC6EF46FFB4AEC218EE46FB07FDAD595FE78A42C9F8D7FA', 
  "OSCORE Master Secret", 
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info_ms for OSCORE Master Secret (CBOR-encoded) (58 bytes)
84 0a 58 20 e6 2d fe 6d 32 36 a6 55 9d c6 ef 46 ff b4 ae c2 18 ee 46 fb 
07 fd ad 59 5f e7 8a 42 c9 f8 d7 fa 74 4f 53 43 4f 52 45 20 4d 61 73 74 
65 72 20 53 65 63 72 65 74 10 
~~~~~~~~~~~~~~~~~~~~~~~


info_salt for OSCORE Master Salt is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info_salt = [
  10, 
  h'E62DFE6D3236A6559DC6EF46FFB4AEC218EE46FB07FDAD595FE78A42C9F8D7FA', 
  "OSCORE Master Salt", 
  8
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for OSCORE Master Salt (CBOR-encoded) (56 Bytes)
84 0a 58 20 e6 2d fe 6d 32 36 a6 55 9d c6 ef 46 ff b4 ae c2 18 ee 46 fb 
07 fd ad 59 5f e7 8a 42 c9 f8 d7 fa 72 4f 53 43 4f 52 45 20 4d 61 73 74 
65 72 20 53 61 6c 74 08 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, OSCORE Master Secret and OSCORE Master Salt are computed:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
31 8a 98 6d 6d 3a d6 bb 41 e9 66 0b 63 5b c7 22
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
64 c2 1f 5d d0 83 7d 3b
~~~~~~~~~~~~~~~~~~~~~~~

The client's OSCORE Sender ID is C_R and the server's OSCORE Sender ID is C_I.

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 bytes)
00 
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (0 bytes)
09
~~~~~~~~~~~~~~~~~~~~~~~

The AEAD Algorithm and the hash algorithm are the application AEAD and hash algorithms in the selected cipher suite.

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE AEAD Algorithm (int)
10
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Hash Algorithm (int)
-16
~~~~~~~~~~~~~~~~~~~~~~~


## Test Vectors for EDHOC Authenticated with Static Diffie-Hellman Keys

<!-- Test vector index (int) 34900 -->

EDHOC with static Diffie-Hellman keys and raw public keys is used. In this test vector, a key identifier is used to identify the raw public key.

~~~~~~~~~~~~~~~~~~~~~~~
method (Static DH Based Authentication)
3
~~~~~~~~~~~~~~~~~~~~~~~

CoAP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

From there, METHOD_CORR has the following value:

~~~~~~~~~~~~~~~~~~~~~~~
METHOD_CORR (4 * method + corr) (int)
13
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

There is only one supported cipher suite indicated by the Initiator.

~~~~~~~~~~~~~~~~~~~~~~~
Supported Cipher Suites (1 byte)
00
~~~~~~~~~~~~~~~~~~~~~~~

The cipher suite selected by the Initiator is the most preferred:

~~~~~~~~~~~~~~~~~~~~~~~
Selected Cipher Suite (int)
0
~~~~~~~~~~~~~~~~~~~~~~~

Cipher suite 0 is supported by both the Initiator and the Responder, see {{cipher-suites}}.

### Message_1 {#dh-ss-m1}

The Initiator generates its ephemeral key pair.

~~~~~~~~~~~~~~~~~~~~~~~
X (Initiator's ephemeral private key) (32 bytes)
ae 11 a0 db 86 3c 02 27 e5 39 92 fe b8 f5 92 4c 50 d0 a7 ba 6e ea b4 ad 
1f f2 45 72 f4 f5 7c fa
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_X (Initiator's ephemeral public key) (32 bytes)
8d 3e f5 6d 1b 75 0a 43 51 d6 8a c2 50 a0 e8 83 79 0e fc 80 a5 38 a4 44 
ee 9e 2b 57 e2 44 1a 7c
~~~~~~~~~~~~~~~~~~~~~~~

The Initiator chooses a connection identifier C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by Initiator (1 bytes)
16
~~~~~~~~~~~~~~~~~~~~~~~

Note that since C_I is a byte strings of length one, it is encoded as the corresponding integer - 24 (see bstr_identifier in {{bstr_id}}), i.e. 0x16 = 22, 22 - 24 = -2, and -2 in CBOR encoding is equal to 0x21.

~~~~~~~~~~~~~~~~~~~~~~~
C_I (1 byte)
21
~~~~~~~~~~~~~~~~~~~~~~~

Since no unprotected opaque auxiliary data is sent in the message exchanges:

~~~~~~~~~~~~~~~~~~~~~~~
AD_1 (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

Since the list of supported cipher suites needs to contain the selected cipher suite, the initiator truncates the list of supported cipher suites to one cipher suite only, 00. 

Because one single selected cipher suite is conveyed, it is encoded as an int instead of an array:

~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I (int)
0
~~~~~~~~~~~~~~~~~~~~~~~

With SUITES_I = 0, message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  h'',
  13,
  0,
  h'8D3EF56D1B750A4351D68AC250A0E883790EFC80A538A444EE9E2B57E2441A7C',
  -2
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
40 0d 00 58 20 8d 3e f5 6d 1b 75 0a 43 51 d6 8a c2 50 a0 e8 83 79 0e fc 
80 a5 38 a4 44 ee 9e 2b 57 e2 44 1a 7c 21 
~~~~~~~~~~~~~~~~~~~~~~~

### Message_2 {#dh-ss-m2}

Since METHOD_CORR mod 4 equals 1, C_I is omitted from data_2.

The Responder generates the following ephemeral key pair.

~~~~~~~~~~~~~~~~~~~~~~~
Y (Responder's ephemeral private key) (32 bytes)
c6 46 cd dc 58 12 6e 18 10 5f 01 ce 35 05 6e 5e bc 35 f4 d4 cc 51 07 49 
a3 a5 e0 69 c1 16 16 9a
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_Y (Responder's ephemeral public key) (32 bytes)
52 fb a0 bd c8 d9 53 dd 86 ce 1a b2 fd 7c 05 a4 65 8c 7c 30 af db fc 33 
01 04 70 69 45 1b af 35 
~~~~~~~~~~~~~~~~~~~~~~~

From G_X and Y or from G_Y and X the ECDH shared secret is computed:

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (ECDH shared secret) (32 bytes)
de fc 2f 35 69 10 9b 3d 1f a4 a7 3d c5 e2 fe b9 e1 15 0d 90 c2 5e e2 f0 
66 c2 d8 85 f4 f8 ac 4e
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce for calculating the 'ciphertext' are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2e = HMAC-SHA-256(salt, G_XY)

Salt is the empty byte string.

~~~~~~~~~~~~~~~~~~~~~~~
salt (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_2e is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_2e (32 bytes)
93 9f cb 05 6d 2e 41 4f 1b ec 61 04 61 99 c2 c7 63 d2 7f 0c 3d 15 fa 16 
71 fa 13 4e 0d c5 a0 4d 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder's static Diffie-Hellman key pair is the following:


~~~~~~~~~~~~~~~~~~~~~~~
R (Responder's private authentication key) (32 bytes)
bb 50 1a ac 67 b9 a9 5f 97 e0 ed ed 6b 82 a6 62 93 4f bb fc 7a d1 b7 4c 
1f ca d6 6a 07 94 22 d0 
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_R (Responder's public authentication key) (32 bytes)
a3 ff 26 35 95 be b3 77 d1 a0 ce 1d 04 da d2 d4 09 66 ac 6b cb 62 20 51 
b8 46 59 18 4d 5d 9a 32
~~~~~~~~~~~~~~~~~~~~~~~

Since the Responder authenticates with a static Diffie-Hellman key, PRK_3e2m = HKDF-Extract( PRK_2e, G_RX ), where G_RX is the ECDH shared secret calculated from G_R and X, or G_X and R.

From the Responder's authentication key and the Initiator's ephemeral key (see {{dh-ss-m1}}), the ECDH shared secret G_RX is calculated.

~~~~~~~~~~~~~~~~~~~~~~~
G_RX (ECDH shared secret) (32 bytes)
21 c7 ef f4 fb 69 fa 4b 67 97 d0 58 84 31 5d 84 11 a3 fd a5 4f 6d ad a6 
1d 4f cd 85 e7 90 66 68
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
PRK_3e2m (32 bytes)
75 07 7c 69 1e 35 01 2d 48 bc 24 c8 4f 2b ab 89 f5 2f ac 03 fe dd 81 3e 
43 8c 93 b1 0b 39 93 07 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder chooses a connection identifier C_R.

~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by Responder (1 byte)
00
~~~~~~~~~~~~~~~~~~~~~~~

Note that since C_R is a byte strings of length one, it is encoded as the corresponding integer - 24 (see bstr_identifier in {{bstr_id}}), i.e. 0x00 = 0, 0 - 24 = -24, and -24 in CBOR encoding is equal to 0x37.

~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
37
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of G_Y and C_R.

~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'52FBA0BDC8D953DD86CE1AB2FD7C05A4658C7C30AFDBFC3301047069451BAF35',
  37
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (35 bytes)
58 20 52 fb a0 bd c8 d9 53 dd 86 ce 1a b2 fd 7c 05 a4 65 8c 7c 30 af db 
fc 33 01 04 70 69 45 1b af 35 37 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1, compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_2 (CBOR Sequence) (73 bytes)
40 0d 00 58 20 8d 3e f5 6d 1b 75 0a 43 51 d6 8a c2 50 a0 e8 83 79 0e fc 
80 a5 38 a4 44 ee 9e 2b 57 e2 44 1a 7c 21 58 20 52 fb a0 bd c8 d9 53 dd 
86 ce 1a b2 fd 7c 05 a4 65 8c 7c 30 af db fc 33 01 04 70 69 45 1b af 35 
37  
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (32 bytes)
a5 1c 76 46 3e 8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 3e ac d9 e5 
ff 6e 3f ac 87 66 58 a5 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder's subject name is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
Responders's subject name (text string)
""
~~~~~~~~~~~~~~~~~~~~~~~

ID_CRED_R is the following:

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{
  4: h'05'
}
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (4 bytes)
a1 04 41 05 
~~~~~~~~~~~~~~~~~~~~~~~

CRED_R is the following COSE_Key:

~~~~~~~~~~~~~~~~~~~~~~~
{
  1: 1,
  -1: 4,
  -2: h'A3FF263595BEB377D1A0CE1D04DAD2D40966AC6BCB622051B84659184D5D9A32,
  "subject name": ""
}
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (54 bytes)
a4 01 01 20 04 21 58 20 a3 ff 26 35 95 be b3 77 d1 a0 ce 1d 04 da d2 d4 
09 66 ac 6b cb 62 20 51 b8 46 59 18 4d 5d 9a 32 6c 73 75 62 6a 65 63 74 
20 6e 61 6d 65 60 
~~~~~~~~~~~~~~~~~~~~~~~

Since no unprotected opaque auxiliary data is sent in the message exchanges:

~~~~~~~~~~~~~~~~~~~~~~~
AD_2  (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Plaintext is defined as the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
P_2m (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Enc_structure is defined as follows: \[ "Encrypt0", << ID_CRED_R >>, << TH_2, CRED_R >> \]

~~~~~~~~~~~~~~~~~~~~~~~
A_2m =
[
  "Encrypt0", 
  h'A1044105', 
  h'5820A51C76463E8AE58FD3B8DC5EDE1E27143CC92D223EACD9E5FF6E3FAC876658A5
  A401012004215820A3FF263595BEB377D1A0CE1D04DAD2D40966AC6BCB622051B84659
  184D5D9A326C7375626A656374206E616D6560'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2m (CBOR-encoded) (105 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 05 58 58 58 20 a5 1c 76 46 3e 
8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 3e ac d9 e5 ff 6e 3f ac 87 
66 58 a5 a4 01 01 20 04 21 58 20 a3 ff 26 35 95 be b3 77 d1 a0 ce 1d 04 
da d2 d4 09 66 ac 6b cb 62 20 51 b8 46 59 18 4d 5d 9a 32 6c 73 75 62 6a 
65 63 74 20 6e 61 6d 65 60 
~~~~~~~~~~~~~~~~~~~~~~~

info for K_2m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2m =
[
  10, 
  h'A51C76463E8AE58FD3B8DC5EDE1E27143CC92D223EACD9E5FF6E3FAC876658A5', 
  "K_2m", 
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2m (CBOR-encoded) (42 bytes)
84 0a 58 20 a5 1c 76 46 3e 8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 
3e ac d9 e5 ff 6e 3f ac 87 66 58 a5 64 4b 5f 32 6d 10
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, K_2m is computed. Key K_2m is the output of HKDF-Expand(PRK_3e2m, info, L), where L is the length of K_2m, so 16 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
K_2m (16 bytes)
89 2f e8 58 31 ec c1 6d b7 a9 8a 0a d1 dd f6 85 
~~~~~~~~~~~~~~~~~~~~~~~

info for IV_2m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2m =
[
  10, 
  h'A51C76463E8AE58FD3B8DC5EDE1E27143CC92D223EACD9E5FF6E3FAC876658A5', 
  "IV_2m", 
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2m (CBOR-encoded) (43 bytes)
84 0a 58 20 a5 1c 76 46 3e 8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 
3e ac d9 e5 ff 6e 3f ac 87 66 58 a5 65 49 56 5f 32 6d 0d
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_2m is computed. IV_2m is the output of HKDF-Expand(PRK_3e2m, info, L), where L is the length of IV_2m, so 13 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
IV_2m (13 bytes)
13 0a ba 71 74 68 96 15 5b fb 5a 20 e1
~~~~~~~~~~~~~~~~~~~~~~~

Finally, COSE_Encrypt0 is computed from the parameters above.

* protected header = CBOR-encoded ID_CRED_R

* external_aad = A_2m

* empty plaintext = P_2m

~~~~~~~~~~~~~~~~~~~~~~~
MAC_2 (8 bytes)
40 50 10 1d a6 18 79 17  
~~~~~~~~~~~~~~~~~~~~~~~

From there Signature_or_MAC_2 is the MAC (since method = 3):

~~~~~~~~~~~~~~~~~~~~~~~
Signature_or_MAC_2 (8 bytes)
40 50 10 1d a6 18 79 17
~~~~~~~~~~~~~~~~~~~~~~~

CIPHERTEXT_2 is the ciphertext resulting from XOR between plaintext and KEYSTREAM_2 which is derived from TH_2 and the pseudorandom key PRK_2e.

* plaintext = CBOR Sequence of the items ID_CRED_R and the CBOR encoded Signature_or_MAC_2, in this order (AD_2 is empty). 

Note that since ID_CRED_R contains a single 'kid' parameter, i.e., ID_CRED_R = { 4 : kid_R }, only the byte string kid_R is conveyed in the plaintext encoded as a bstr_identifier. kid_R is encoded as the corresponding integer - 24 (see bstr_identifier in {{bstr_id}}), i.e. 0x05 = 5, 5 - 24 = -19, and -19 in CBOR encoding is equal to 0x32.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2e (CBOR Sequence) (10 bytes)
32 48 40 50 10 1d a6 18 79 17
~~~~~~~~~~~~~~~~~~~~~~~

KEYSTREAM_2 = Expand( PRK, info, length ), where length is the length of the plaintext, so 10.

~~~~~~~~~~~~~~~~~~~~~~~
info for KEYSTREAM_2 =
[
  10, 
  h'A51C76463E8AE58FD3B8DC5EDE1E27143CC92D223EACD9E5FF6E3FAC876658A5', 
  "KEYSTREAM_2", 
  10
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for KEYSTREAM_2 (CBOR-encoded) (49 bytes)
84 0a 58 20 a5 1c 76 46 3e 8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 
3e ac d9 e5 ff 6e 3f ac 87 66 58 a5 6b 4b 45 59 53 54 52 45 41 4d 5f 32 
0a 
~~~~~~~~~~~~~~~~~~~~~~~

From there, KEYSTREAM_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
KEYSTREAM_2(10 bytes)
49 f7 2b f5 e7 18 5d 94 ba 99
~~~~~~~~~~~~~~~~~~~~~~~

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (10 bytes)
7b bf 6b a5 f7 05 fb 8c c3 8e 
~~~~~~~~~~~~~~~~~~~~~~~

message_2 is the CBOR Sequence of data_2 and CIPHERTEXT_2, in this order:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
 data_2,
 h'7BBF6BA5F705FB8CC38E'
) 
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (46 bytes)
58 20 52 fb a0 bd c8 d9 53 dd 86 ce 1a b2 fd 7c 05 a4 65 8c 7c 30 af db 
fc 33 01 04 70 69 45 1b af 35 37 4a 7b bf 6b a5 f7 05 fb 8c c3 8e 
~~~~~~~~~~~~~~~~~~~~~~~

### Message_3

Since corr equals 1, C_R is not omitted from data_3.

The Initiator's static Diffie-Hellman key pair is the following:

~~~~~~~~~~~~~~~~~~~~~~~
SK_I (Initiator's private authentication key) (32 bytes)
2b be a6 55 c2 33 71 c3 29 cf bd 3b 1f 02 c6 c0 62 03 38 37 b8 b5 90 99 
a4 43 6f 66 60 81 b0 8e 
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
G_I (Initiator's public authentication key) (32 bytes)
2c 44 0c c1 21 f8 d7 f2 4c 3b 0e 41 ae da fe 9c aa 4f 4e 7a bb 83 5e c3 
0f 1d e8 8a db 96 ff 71
~~~~~~~~~~~~~~~~~~~~~~~

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

From the Initiator's authentication key and the Responder's ephemeral key (see {{dh-ss-m2}}), the ECDH shared secret G_IY is calculated.

~~~~~~~~~~~~~~~~~~~~~~~
G_IY (ECDH shared secret) (32 bytes)
cb ff 8c d3 4a 81 df ec 4c b6 5d 9a 57 2e bd 09 64 45 0c 78 56 3d a4 98 
1d 80 d3 6c 8b 1a 75 2a 
~~~~~~~~~~~~~~~~~~~~~~~

PRK_4x3m = HMAC-SHA-256 (PRK_3e2m, G_IY).

~~~~~~~~~~~~~~~~~~~~~~~
PRK_4x3m (32 bytes)
02 56 2f 1f 01 78 5c 0a a5 f5 94 64 0c 49 cb f6 9f 72 2e 9e 6c 57 83 7d 
8e 15 79 ec 45 fe 64 7a
~~~~~~~~~~~~~~~~~~~~~~~

data 3 is equal to C_R.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (1 bytes)
37 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2, and TH_2, compute the input to the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_3 (CBOR Sequence) (46 bytes)
58 20 a5 1c 76 46 3e 8a e5 8f d3 b8 dc 5e de 1e 27 14 3c c9 2d 22 3e ac 
d9 e5 ff 6e 3f ac 87 66 58 a5 4a 7b bf 6b a5 f7 05 fb 8c c3 8e 37 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (32 bytes)
97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 01 68 aa 11 
15 fa f9 2d 9e 67 ef 04 
~~~~~~~~~~~~~~~~~~~~~~~

The initiator's subject name is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's subject name (text string)
""
~~~~~~~~~~~~~~~~~~~~~~~

And its credential is:

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{
  4: h'23'
}
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (4 bytes)
a1 04 41 23
~~~~~~~~~~~~~~~~~~~~~~~

CRED_I is the following COSE_Key:

~~~~~~~~~~~~~~~~~~~~~~~
{
  1: 1, 
  -1: 4,
   -2: h'2C440CC121F8D7F24C3B0E41AEDAFE9CAA4F4E7ABB835EC30F1DE88ADB96FF71', 
   "subject name": ""
 }
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (54 bytes)
a4 01 01 20 04 21 58 20 2c 44 0c c1 21 f8 d7 f2 4c 3b 0e 41 ae da fe 9c 
aa 4f 4e 7a bb 83 5e c3 0f 1d e8 8a db 96 ff 71 6c 73 75 62 6a 65 63 74 
20 6e 61 6d 65 60 
~~~~~~~~~~~~~~~~~~~~~~~

Since no opaque auxiliary data is exchanged:

~~~~~~~~~~~~~~~~~~~~~~~
AD_3 (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The Plaintext of the COSE_Encrypt is the empty string:

~~~~~~~~~~~~~~~~~~~~~~~
P_3m (0 bytes)
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the CBOR Sequence of TH_3 and CRED_I, in this order:

~~~~~~~~~~~~~~~~~~~~~~~
A_3m (CBOR-encoded) (105 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 23 58 58 58 20 97 d8 ad 42 33 
48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 01 68 aa 11 15 fa f9 2d 9e 
67 ef 04 a4 01 01 20 04 21 58 20 2c 44 0c c1 21 f8 d7 f2 4c 3b 0e 41 ae 
da fe 9c aa 4f 4e 7a bb 83 5e c3 0f 1d e8 8a db 96 ff 71 6c 73 75 62 6a 
65 63 74 20 6e 61 6d 65 60 
~~~~~~~~~~~~~~~~~~~~~~~

Info for K_3m is computed as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3m =
[
  10, 
  h'97D8AD42334833EB25B960A5EB0704505F89671A0168AA1115FAF92D9E67EF04', 
  "K_3m", 
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3m (CBOR-encoded) (42 bytes)
84 0a 58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 
01 68 aa 11 15 fa f9 2d 9e 67 ef 04 64 4b 5f 33 6d 10   
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, K_3m is computed. Key K_3m is the output of HKDF-Expand(PRK_4x3m, info, L), where L is the length of K_2m, so 16 bytes.

~~~~~~~~~~~~~~~~~~~~~~~
K_3m (16 bytes)
62 ac 65 ef 62 47 56 c4 3b c1 c6 a5 a1 f4 76 3a 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3m is the output of HKDF-Expand(PRK_4x3m, info, L), where L = 13 bytes.

Info for IV_3m is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3m =
[
  10, 
  h'97D8AD42334833EB25B960A5EB0704505F89671A0168AA1115FAF92D9E67EF04', 
  "IV_3m", 
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3m (CBOR-encoded) (43 bytes)
84 0a 58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 
01 68 aa 11 15 fa f9 2d 9e 67 ef 04 65 49 56 5f 33 6d 0d 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_3m is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3m (13 bytes)
02 a4 de 46 01 35 23 68 e6 a6 94 96 0d 
~~~~~~~~~~~~~~~~~~~~~~~

MAC_3 is the 'ciphertext' of the COSE_Encrypt0:

~~~~~~~~~~~~~~~~~~~~~~~
MAC_3 (8 bytes)
a6 d6 b3 9d ff e6 6d ee
~~~~~~~~~~~~~~~~~~~~~~~

Since the method = 3, Signature_or_Mac_3 is the MAC_3:

~~~~~~~~~~~~~~~~~~~~~~~
Signature_or_MAC_3 (8 bytes)
a6 d6 b3 9d ff e6 6d ee 
~~~~~~~~~~~~~~~~~~~~~~~ 

Finally, the outer COSE_Encrypt0 is computed.

The Plaintext is the following CBOR Sequence: 
plaintext = ( ID_CRED_I , Signature_or_MAC_3 ).  Note that since ID_CRED_I contains a single 'kid' parameter, i.e., ID_CRED_I = { 4 : kid_I }, only the byte string kid_I is conveyed in the plaintext encoded as a bstr_identifier. kid_I is encoded as the corresponding integer - 24 (see bstr_identifier in {{bstr_id}}), i.e. 0x23 = 35, 35 - 24 = 11, and 11 in CBOR encoding is equal to 0x0b.

~~~~~~~~~~~~~~~~~~~~~~~
P_3ae (CBOR Sequence) (10 bytes)
0b 48 a6 d6 b3 9d ff e6 6d ee  
~~~~~~~~~~~~~~~~~~~~~~~

The Associated data A is the following:
Associated data A = \[ "Encrypt0", h'', TH_3 \]

~~~~~~~~~~~~~~~~~~~~~~~
A_3ae (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 
a5 eb 07 04 50 5f 89 67 1a 01 68 aa 11 15 fa f9 2d 9e 67 ef 04 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3ae is the output of HKDF-Expand(PRK_3e2m, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3ae = 
[
  10, 
  h'97D8AD42334833EB25B960A5EB0704505F89671A0168AA1115FAF92D9E67EF04', 
  "K_3ae", 
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3ae (CBOR-encoded) (43 bytes)
84 0a 58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 
01 68 aa 11 15 fa f9 2d 9e 67 ef 04 65 4b 5f 33 61 65 10 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3ae, so 16 bytes.

From these parameters, K_3ae is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3ae (16 bytes)
e8 28 42 75 a4 73 35 a1 3b 91 1f d3 88 1f c9 64 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3ae is the output of HKDF-Expand(PRK_3e2m, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3ae =
[
  10, 
  h'97D8AD42334833EB25B960A5EB0704505F89671A0168AA1115FAF92D9E67EF04', 
  "IV_3ae", 
  13
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3ae (CBOR-encoded) (44 bytes)
84 0a 58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 
01 68 aa 11 15 fa f9 2d 9e 67 ef 04 66 49 56 5f 33 61 65 0d 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3ae, so 13 bytes.

From these parameters, IV_3ae is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3ae (13 bytes)
9c b8 98 98 c9 a1 86 40 14 ed 4a fd 09  
~~~~~~~~~~~~~~~~~~~~~~~

Using the parameters above, the 'ciphertext' CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (18 bytes)
a2 f9 21 46 c6 89 23 af b6 93 ab f3 d8 4d c1 f6 69 21 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameter above, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).

~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'00',
  h'A2F92146C68923AFB693ABF3D84DC1F66921'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (20 bytes)
37 52 a2 f9 21 46 c6 89 23 af b6 93 ab f3 d8 4d c1 f6 69 21
~~~~~~~~~~~~~~~~~~~~~~~

### OSCORE Security Context Derivation

From here, the Initiator and the Responder can derive an OSCORE Security Context, using the EDHOC-Exporter interface.

From TH_3 and CIPHERTEXT_3, compute the input to the transcript hash TH_4 = H( TH_3, CIPHERTEXT_3 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
Input to calculate TH_4 (CBOR Sequence) (53 bytes)
58 20 97 d8 ad 42 33 48 33 eb 25 b9 60 a5 eb 07 04 50 5f 89 67 1a 01 68 
aa 11 15 fa f9 2d 9e 67 ef 04 52 a2 f9 21 46 c6 89 23 af b6 93 ab f3 d8 
4d c1 f6 69 21  
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256(TH_3 , CIPHERTEXT_4)

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (32 bytes)
6e 8f 04 92 7c 99 98 cb df 82 01 fb 89 0a d7 3c e8 c9 f8 06 a1 43 e2 86 
ce 55 83 74 68 ef 5c 86
~~~~~~~~~~~~~~~~~~~~~~~

The Master Secret and Master Salt are derived as follows:

Master Secret = EDHOC-Exporter( "OSCORE Master Secret", 16 ) = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Secret", 16) = Expand( PRK_4x3m, info_ms, 16 )

Master Salt   = EDHOC-Exporter( "OSCORE Master Salt", 8 ) = EDHOC-KDF(PRK_4x3m, TH_4, "OSCORE Master Salt", 8) = Expand( PRK_4x3m, info_salt, 8 )

info_ms for OSCORE Master Secret is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info_ms = [
  10, 
  h'6E8F04927C9998CBDF8201FB890AD73CE8C9F806A143E286CE55837468EF5C86', 
  "OSCORE Master Secret", 
  16
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info_ms for OSCORE Master Secret (CBOR-encoded) (58 bytes)
84 0a 58 20 6e 8f 04 92 7c 99 98 cb df 82 01 fb 89 0a d7 3c e8 c9 f8 06 
a1 43 e2 86 ce 55 83 74 68 ef 5c 86 74 4f 53 43 4f 52 45 20 4d 61 73 74 
65 72 20 53 65 63 72 65 74 10 
~~~~~~~~~~~~~~~~~~~~~~~


info_salt for OSCORE Master Salt is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info_salt = [
  10, 
  h'6E8F04927C9998CBDF8201FB890AD73CE8C9F806A143E286CE55837468EF5C86', 
  "OSCORE Master Salt", 
  8
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info for OSCORE Master Salt (CBOR-encoded) (56 Bytes)
84 0a 58 20 6e 8f 04 92 7c 99 98 cb df 82 01 fb 89 0a d7 3c e8 c9 f8 06 
a1 43 e2 86 ce 55 83 74 68 ef 5c 86 72 4f 53 43 4f 52 45 20 4d 61 73 74 
65 72 20 53 61 6c 74 08 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, OSCORE Master Secret and OSCORE Master Salt are computed:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
24 26 df 74 5c ea f4 79 3f 95 e1 54 62 03 30 2b 
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
52 8f 26 37 60 0d 3d 41
~~~~~~~~~~~~~~~~~~~~~~~

The client's OSCORE Sender ID is C_R and the server's OSCORE Sender ID is C_I.

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 bytes)
00
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (0 bytes)
16
~~~~~~~~~~~~~~~~~~~~~~~

The AEAD Algorithm and the hash algorithm are the application AEAD and hash algorithms in the selected cipher suite.

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE AEAD Algorithm (int)
10
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Hash Algorithm (int)
-16
~~~~~~~~~~~~~~~~~~~~~~~

# Applicability Statement {#applicability}

EDHOC requires certain parameters to be agreed upon between Initiator and Responder. EDHOC supports cipher suite negotiation, but certain other parameters need to be agreed beforehand:

1. Method and correlation of underlying transport messages (METHOD_CORR; see {{method}} and {{corr}}).
2. How EDHOC messages are transported and how the peer detects that an EDHOC message is received, e.g. URI, media type (for an example using CoAP, see {{oscore}}).
3. Type of authentication credentials (CRED_I, CRED_R; see {{id_cred}}).
4. Type for identifying authentication credentials (ID_CRED_I, ID_CRED_R; see {{id_cred}}).
5. Type and use of Auxiliary Data (AD_1, AD_2, AD_3; see {{AD}}).
6. Identifier used as identity of endpoint (see {{auth-key-id}}).
7. If message_4 shall be sent/expected, and if not, how to ensure protected application message is sent from the Responder to the Initiator (see {{m4}}).


An example of an applicability statement is shown in the next section.

Note that for some of the parameters, like METHOD_CORR, ID_CRED_x, type of AD_x, the receiver is able to assert whether it supports the received parameter or not and thus, if the protocol fails because of this, to infer the reason why the protocol failed. 

For other parameters, like authentication credential which is not transported, it may be difficult to detect if integrity failed because of wrong credential or for some other reason. For example, in the case of public key certificates where there is a large variety of profiles and alternative encodings, unless the certificate (chain) is transported, the endpoints need to agree on the precise format.

Note also that it is not always necessary for the endpoints to agree on the transport for the EDHOC messages. For example, a mix of CoAP and HTTP may be used along the path and still allow correlation between message_1 and message_2.

EDHOC enables policy decisions based on the identity of the peer. If other information must to be conveyed, such as target application or use (e.g. if there is more than one application/use with different policies) then this may be signalled for example in URI or Auxiliary Data and could to be specified in the applicability statement.


## Template: Use of EDHOC in the XX Protocol

For use of EDHOC in the XX protocol, the following assumptions are made on the parameters.  

* METHOD_CORR = 5
   * method = 1 (I uses signature key, R uses static DH key.)
   * corr = 1 (CoAP Token or other transport data enables correlation between message_1 and message_2.)

* EDHOC requests are expected by the server at /app1-edh, no Content-Format needed.

* CRED_I is an 802.1AR IDevID encoded as a CBOR Certificate of type 0 {{I-D.mattsson-cose-cbor-cert-compress}}.
    * R acquires CRED_I out-of-band, indicated in AD_1
    * ID_CRED_I = {4: h''} is a kid with value empty byte string

* CRED_R is a COSE_Key of type OKP as specified in {{id_cred}}.
   * The CBOR map has parameters 1 (kty), -1 (crv), and -2 (x-coordinate).
* ID_CRED_R = CRED_R

* AD_1 contains Auxiliary Data of type A (TBD)
* AD_2 contains Auxiliary Data of type B (TBD)

* No use of message_4: the application sends protected messages from R to I.

* Auxiliary Data is processed as specified in {{I-D.selander-ace-ake-authz}}.

* Need to specify use of C\_I/C\_R ? (TBD)





# Acknowledgments
{: numbered="no"}

The authors want to thank Alessandro Bruni, Karthikeyan Bhargavan, Timothy Claeys, Martin Disch, Theis Grønbech Petersen, Dan Harkins, Klaus Hartke, Russ Housley, Stefan Hristozov, Alexandros Krontiris, Ilari Liusvaara, Karl Norrman, Salvador Pérez, Eric Rescorla, Michael Richardson, Thorvald Sahl Jørgensen, Jim Schaad, Carsten Schürmann, Ludwig Seitz, Stanislav Smyshlyaev, Valery Smyslov, Peter van der Stok, Rene Struik, Vaishnavi Sundararajan, Erik Thormarker, Marco Tiloca, Michel Veillette, and Malisa Vucinic for reviewing and commenting on intermediate versions of the draft. We are especially indebted to Jim Schaad for his continuous reviewing and implementation of different versions of the draft.

Work on this document has in part been supported by the H2020 project SIFIS-Home (grant agreement 952652).

--- fluff
