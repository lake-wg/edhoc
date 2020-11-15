// EDHOC Test Vectors
// Copyright (c) 2020, Ericsson and John Mattsson <john.mattsson@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <vector>
#include <sodium.h>
#include "aes.h"

using namespace std;
using vec = vector<uint8_t>;

enum EDHOCKeyType { sig, sdh, psk }; 
enum EDHOCCorrelation { corr_none, corr_12, corr_23, corr_123 }; 
enum EDHOCSuite { suite_0, suite_1 }; 

enum COSEHeader { kid = 4, x5bag = 32, x5chain = 33, x5t = 34, x5u = 35 }; 
enum COSEAlgorithm { SHA_256 = -16, SHA_256_64 = -15, EdDSA = -8, AES_CCM_16_64_128 = 10, AES_CCM_16_128_128 = 30 }; 
enum COSECurve { X25519 = 4, Ed25519 = 6 }; 
enum COSECommon { kty = 1 };
enum COSEOKP { x = -2, crv = -1, OKP = 1 }; 

// Concatenates two vectors
vec operator+( vec a, vec b ) {
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

// Fatal error
void syntax_error( string s ) {
    cout << "Syntax Error: " << s;
    exit(-1);
}

// Print an int to cout
void print( string s, int i ) {
    cout << endl << dec << s << " (int)" << endl << i << endl;    
}

// Print a string to cout
void print( string s, string s2 ) {
    cout << endl << s << " (text string)" << endl << "\"" << s2 << "\"" << endl;    
}

// Print a vec to cout
void print( string s, vec v ) {
    cout << endl << dec << s << " (" << v.size() << " bytes)";
    if  ( v.size() )
        cout << endl;
    for ( int i = 1; i <= v.size(); i++ ) {
        cout << hex << setfill('0') << setw( 2 ) << (int)v[i-1] << " ";        
        if ( i % 24 == 0 && i < v.size() )
            cout << endl;
    }
    cout << endl;
}

// Helper funtion for CBOR encoding
vec cbor_unsigned_with_type( uint8_t type, int i ) {
    type = type << 5;
    if ( i < 0 || i > 0xFFFF )
        syntax_error( "cbor_unsigned_with_type()" );
    if ( i < 24 )
        return { (uint8_t) (type | i) };
    else if ( i < 0x100 )
        return { (uint8_t) (type | 0x18), (uint8_t) i };
    else
        return { (uint8_t) (type | 0x19), (uint8_t) (i >> 8), (uint8_t) (i & 0xFF) };
}

// CBOR encodes an int
vec cbor( int i ) {
    if ( i < 0 )
        return cbor_unsigned_with_type( 1, -(i + 1) ); 
    else
	    return cbor_unsigned_with_type( 0, i ); 
}

// CBOR encodes a bstr
 vec cbor( vec v ) {
    return cbor_unsigned_with_type( 2, v.size() ) + v;
}

// CBOR encodes a tstr
vec cbor( string s ) {
    return cbor_unsigned_with_type( 3, s.size() ) + vec( s.begin(), s.end() );
}

vec cbor_arr( int length ) {
    return cbor_unsigned_with_type( 4, length );
}

vec cbor_map( int length ) {
    return cbor_unsigned_with_type( 5, length );
}

vec cbor_tag( int value ) {
    return cbor_unsigned_with_type( 6, value );
}

// CBOR encodes a bstr_indentifier as bstr or int
 vec cbor_id( vec v ) {
    if ( v.size() == 1 )
        return cbor( v[0] - 24 );
    else
        return cbor( v );
}

// CBOR encodes and optional AD
 vec cbor_AD( vec v ) {
    if ( v.size() == 0 )
        return v;
    else
        return cbor( v );
}

// Tries to compress ID_CRED_x
 vec compress_id_cred( vec v ) {
    if ( vec{ v[0], v[1] } == cbor_map( 1 ) + cbor( kid ) )
        return cbor_id( vec( v.begin() + 3, v.end() ) );
    else
        return v;
}

// Tries to compress SUTES_I
// Attention: Only supports suites in the range [-24, 23]
 vec compress_suites( vec v ) {
    if ( v.size() == 3 && v[1] == v[2] )
        return cbor( v[1] );
    else
        return v;
}

// Calculates the hash of m
vec HASH( int alg, vec m ) {
    if ( alg != SHA_256 && alg != SHA_256_64 )
        syntax_error( "hash()" );
    vec digest( crypto_hash_sha256_BYTES );
    crypto_hash_sha256( digest.data(), m.data(), m.size() );
    if ( alg == SHA_256_64 )
        digest.resize( 8 );
    return digest;
}

vec hmac( int alg, vec k, vec m ) {
    if ( alg != SHA_256 )
        syntax_error( "hmac()" );
    vec out( crypto_auth_hmacsha256_BYTES ); 
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init( &state, k.data(), k.size() );
    crypto_auth_hmacsha256_update( &state, m.data(), m.size() );
    crypto_auth_hmacsha256_final( &state, out.data() );
    return out;
}

// TODO: This function should be checked against another implementation
vec hkdf_expand( int alg, vec PRK, vec info, int L ) {
    vec out, T;
    for ( int i = 0; i <= L / 32; i++ ) {
        vec m = T + info + vec{ uint8_t( i + 1 ) };
        T = hmac( alg, PRK, m );
        out = out + T;
    }
    out.resize( L );
    return out;
}

vec xor_encryption( vec K, vec P ) {
    for( int i = 0; i < P.size(); ++i )
        P[i] ^= K[i];
    return P;
}

vec random_vector( int len ) {
    vec out( len );
    for( auto& i : out )
        i = rand();
    return out;
}

// TODO resumption
// TODO error message with SUITES_V
// TODO real X.509 certificates
// TODO other COSE algorithms like ECDSA, P-256, SHA-384, P-384, AES-GCM, ChaCha20-Poly1305
void test_vectors( EDHOCKeyType type_I, EDHOCKeyType type_R, EDHOCCorrelation corr, EDHOCSuite selected_suite,
                   COSEHeader attr_I, COSEHeader attr_R,
                   bool auxdata, bool subjectname, bool exporter, bool long_id, bool full_output ) {

    // TODO method will likely be replaced by key types in a future version
    int method = 2 * type_I + type_R;
    if ( type_I == psk || type_R == psk )
        method = 4;

    // METHOD_CORR and seed random number generation
    int METHOD_CORR = 4 * method + corr;
    srand( 100 * ( 25 * METHOD_CORR + 5 * attr_I + attr_R ) + selected_suite );

    // EDHOC and OSCORE algorithms
    vec SUITES_I, supported_suites = cbor( 0 ) + cbor( 1 ) + cbor( 2 ) + cbor( 3 );
    int edhoc_aead_alg, edhoc_hash_alg, edhoc_ecdh_curve, edhoc_sign_alg, edhoc_sign_curve, oscore_aead_alg, oscore_hash_alg;
    if ( selected_suite == suite_0 ) {
        SUITES_I = cbor_arr( 2 ) + cbor( selected_suite ) + cbor( 0 ); // One of several possible trucations of preferred suites
        edhoc_aead_alg = AES_CCM_16_64_128;
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = X25519;
        edhoc_sign_alg = EdDSA;
        edhoc_sign_curve = Ed25519;
        oscore_aead_alg = AES_CCM_16_64_128;
        oscore_hash_alg = SHA_256;
    }
    if ( selected_suite == suite_1 ) {
        SUITES_I = cbor_arr( 4 ) + cbor( selected_suite ) + cbor( 0 ) + cbor( 1 ) + cbor( 2 ); // One of several possible trucations of preferred suites
        edhoc_aead_alg = AES_CCM_16_128_128;
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = X25519;
        edhoc_sign_alg = EdDSA;
        edhoc_sign_curve = Ed25519;
        oscore_aead_alg = AES_CCM_16_64_128;
        oscore_hash_alg = -SHA_256;
    }

    // Calculate Ephemeral keys
    auto ecdh_key_pair = [=] () {
        vec G_Z( crypto_kx_PUBLICKEYBYTES );
        vec Z( crypto_kx_SECRETKEYBYTES );
        vec seed = random_vector( crypto_kx_SEEDBYTES );
        crypto_kx_seed_keypair( G_Z.data(), Z.data(), seed.data() );
        return make_tuple( Z, G_Z );
    };

    auto shared_secret = [=] ( vec A, vec G_B ) {
        vec G_AB( crypto_scalarmult_BYTES );
        if ( crypto_scalarmult( G_AB.data(), A.data(), G_B.data() ) == -1 )
            syntax_error( "crypto_scalarmult()" );
        return G_AB;
    };
    
    auto [ X, G_X ] = ecdh_key_pair();
    auto [ Y, G_Y ] = ecdh_key_pair();
    vec G_XY = shared_secret( X, G_Y );

    // Authentication keys, Only some of these keys are used depending on type_I and type_R
    auto sign_key_pair = [=] () {
        // EDHOC uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
        // Libsodium seed = RFC 8032 sk, Libsodium sk = pruned SHA-512(sk) in RFC 8032
        vec PK( crypto_sign_PUBLICKEYBYTES );
        vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
        vec SK = random_vector( crypto_sign_SEEDBYTES );
        crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
        return make_tuple( SK, PK );
    };

    auto [ R, G_R ] = ecdh_key_pair();
    auto [ I, G_I ] = ecdh_key_pair();
    vec G_RX = shared_secret( R, G_X );
    vec G_IY = shared_secret( I, G_Y );
    auto [ SK_R, PK_R ] = sign_key_pair();
    auto [ SK_I, PK_I ] = sign_key_pair();
    vec PSK = random_vector( 16 + (rand() % 2) * 16 );

    // PRKs
    auto hkdf_extract = [=] ( vec salt, vec IKM ) { return hmac( edhoc_hash_alg, salt, IKM ); };

    vec salt, PRK_2e;
    if ( type_I == psk || type_R == psk )
        salt = PSK;
    PRK_2e = hkdf_extract( salt, G_XY );

    vec PRK_3e2m = PRK_2e;
    if ( type_R == sdh )
        PRK_3e2m = hkdf_extract( PRK_2e, G_RX );

    vec PRK_4x3m = PRK_3e2m;
    if ( type_I == sdh )
        PRK_4x3m = hkdf_extract( PRK_3e2m, G_IY );
        
    // Subject names
    string NAME_I, NAME_R;
    if ( subjectname == true ) {
        NAME_I = "42-50-31-FF-EF-37-32-39";
        NAME_R = "example.edu";
    }

    // Calculate C_I != C_R
    auto bstr_id = [=] () {
        if ( long_id == true )
            return random_vector( 2 + rand() % 2 );
        else {
            int i = rand() % 49;
            if ( i == 48 )
                return vec{};
            else
                return vec{ (uint8_t) i };
        }
    };

    vec C_I, C_R;
    do {
        C_I = bstr_id();
        C_R = bstr_id();
    } while ( C_I == C_R );

    // Calculate ID_CRED_x and CRED_x
    auto gen_CRED = [=] ( EDHOCKeyType type, COSEHeader attr, vec PK_sig, vec PK_sdh, string name, string uri ) {
        vec ID_CRED, CRED;
        if ( attr == kid ) {
            CRED = cbor_map( 4 ) + cbor( kty ) + cbor( OKP ) + cbor( crv );
            if ( type == sig )
                CRED = CRED + cbor( edhoc_sign_curve ) + cbor( x ) + cbor( PK_sig );
            if ( type == sdh )
                CRED = CRED + cbor( edhoc_ecdh_curve ) + cbor( x ) + cbor( PK_sdh );
            CRED = CRED + cbor( "subject name" ) + cbor( name );
            ID_CRED = cbor_map( 1 ) + cbor( attr ) + cbor( bstr_id() );
        } else {
            vec X509 = random_vector( 100 + rand() % 50 );
            CRED = cbor( X509 );
            ID_CRED = cbor_map( 1 ) + cbor( attr );
            if ( attr == x5bag ||  attr == x5chain )
                ID_CRED = ID_CRED + cbor( CRED );
            if ( attr == x5t )
                ID_CRED = ID_CRED + cbor_arr( 2 ) + cbor( SHA_256_64 ) + cbor( HASH( SHA_256_64, X509 ) );
            if ( attr == x5u )
                ID_CRED = ID_CRED + cbor_tag( 32 ) + cbor( uri );
        }
        return make_tuple( ID_CRED, CRED );
    };

    auto [ ID_CRED_I, CRED_I ] = gen_CRED( type_I, attr_I, PK_I, G_I, NAME_I, "https://example.edu/2716057" );
    auto [ ID_CRED_R, CRED_R ] = gen_CRED( type_R, attr_R, PK_R, G_R, NAME_R, "https://example.edu/3370318" );
    vec ID_PSK = ID_CRED_I; // hack that works for test vectors

    // Auxiliary data
    vec AD_1, AD_2, AD_3;
    if ( auxdata == true ) {
        AD_1 = random_vector( 10 + rand() % 10 );
        AD_2 = random_vector( 10 + rand() % 10 );
        AD_3 = random_vector( 10 + rand() % 10 );
    }
 
    vec message_1 = cbor( METHOD_CORR ) + compress_suites( SUITES_I ) + cbor( G_X ) + cbor_id( C_I ) + cbor_AD( AD_1 );
    if ( type_I == psk || type_R == psk )
        message_1 = message_1 + compress_id_cred( ID_PSK );

    // Helper funtions using local variables ////////////////////////////////////////////////////////////////////////////

    auto H = [=] ( vec input ) { return HASH( edhoc_hash_alg, input ); };
    auto A = [] ( vec protect, vec external_aad ) { return cbor_arr( 3 ) + cbor( "Encrypt0" ) + protect + external_aad; };
    auto M = [] ( vec protect, vec external_aad, vec payload ) { return cbor_arr( 4 ) + cbor( "Signature1" ) + protect + external_aad + payload; };

    // Creates the info parameter and derives output key matrial with HKDF-Expand
    auto KDF = [=] ( vec PRK, vec transcript_hash, string label, int length ) {
        vec info = cbor_arr( 4 ) + cbor( edhoc_aead_alg ) + cbor( transcript_hash ) + cbor( label ) + cbor( length );
        vec OKM = hkdf_expand( edhoc_hash_alg, PRK, info, length );
        return make_tuple( info, OKM );
    };

    auto AEAD = [=] ( vec K, vec N, vec P, vec A ) {
        if( A.size() > (42 * 16 - 2) )
            syntax_error( "AEAD()" );
        int tag_length = ( edhoc_aead_alg == AES_CCM_16_64_128 ) ? 8 : 16;
        vec C( P.size() + tag_length );
        int r = aes_ccm_ae( K.data(), 16, N.data(), tag_length, P.data(), P.size(), A.data(), A.size(), C.data(), C.data() + P.size() );
        return C;
    };

    auto sign = [=] ( vec SK, vec M ) {
        vec signature( crypto_sign_BYTES );
        vec PK( crypto_sign_PUBLICKEYBYTES );
        vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
        crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
        crypto_sign_detached( signature.data(), nullptr, M.data(), M.size(), SK_libsodium.data() );
        return signature;
    };

    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_2 and TH_2
    vec data_2 = cbor_id( C_I ) + cbor( G_Y ) + cbor_id( C_R );
    if ( corr == corr_12 || corr == corr_123 )
        data_2 = cbor( G_Y ) + cbor_id( C_R );
    vec TH_2_input = message_1 + data_2;
    vec TH_2 = H( TH_2_input );

    vec protected_2 = cbor( ID_CRED_R );
    vec external_aad_2 = cbor( cbor( TH_2 ) + CRED_R ) + cbor_AD( AD_2 );

    // Calculate MAC_2
    vec P_2m;
    vec A_2m = A( protected_2, external_aad_2 );
    auto [ info_K_2m,   K_2m ] = KDF( PRK_3e2m, TH_2,  "K_2m", 16 );
    auto [ info_IV_2m, IV_2m ] = KDF( PRK_3e2m, TH_2, "IV_2m", 13 );
    vec MAC_2 = AEAD( K_2m, IV_2m, P_2m, A_2m );

    // Calculate Signature_or_MAC_2
    vec M_2 = M( protected_2, external_aad_2, cbor( MAC_2 ) );
    vec signature_or_MAC_2 = MAC_2;
    if ( type_R == sig )
        signature_or_MAC_2 = sign( SK_R, M_2 );

    // Calculate CIPHERTEXT_2
    vec P_2e = compress_id_cred( ID_CRED_R ) + cbor( signature_or_MAC_2 ) + cbor_AD( AD_2 );
    auto [ info_K_2e, K_2e ] = KDF( PRK_2e, TH_2, "K_2e", P_2e.size() );

    vec P_2ae = cbor_AD( AD_2 );
    vec A_2ae = A( cbor( vec{} ), cbor( TH_2 ) );
    auto [ info_K_2ae,   K_2ae ] = KDF( PRK_2e, TH_2,  "K_2ae", 16 );
    auto [ info_IV_2ae, IV_2ae ] = KDF( PRK_2e, TH_2, "IV_2ae", 13 );

    vec CIPHERTEXT_2 = xor_encryption( K_2e, P_2e );
    if ( type_R == psk )
        CIPHERTEXT_2 = AEAD( K_2ae, IV_2ae, P_2ae, A_2ae );

    // Calculate message_2
    vec message_2 = data_2 + cbor( CIPHERTEXT_2 );

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3 and TH_3
    vec data_3 = cbor_id( C_R );
    if ( corr == corr_23 || corr == corr_123 )
        data_3 = vec{};
    vec TH_3_input = cbor( TH_2 ) + cbor( CIPHERTEXT_2 ) + data_3;
    vec TH_3 = H( TH_3_input );

    vec protected_3 = cbor( ID_CRED_I );
    vec external_aad_3 = cbor( cbor( TH_3 ) + CRED_I ) + cbor_AD( AD_3 );

    // Calculate MAC_3
    vec P_3m = vec{};
    vec A_3m = A( protected_3, external_aad_3 );
    auto [ info_K_3m,   K_3m ] = KDF( PRK_4x3m, TH_3,  "K_3m", 16 );
    auto [ info_IV_3m, IV_3m ] = KDF( PRK_4x3m, TH_3, "IV_3m", 13 );
    vec MAC_3 = AEAD( K_3m, IV_3m, P_3m, A_3m );

    // Calculate Signature_or_MAC_3
    vec M_3 = M( protected_3, external_aad_3, cbor( MAC_3 ) );
    vec signature_or_MAC_3 = MAC_3;
    if ( type_I == sig )
        signature_or_MAC_3 = sign( SK_I, M_3 );

    // Calculate CIPHERTEXT_3
    vec P_3ae;
    if ( type_I != psk )
        P_3ae = compress_id_cred( ID_CRED_I ) + cbor( signature_or_MAC_3 );
    P_3ae = P_3ae + cbor_AD( AD_3 );
    vec A_3ae = A( cbor( vec{} ), cbor( TH_3 ) );
    auto [ info_K_3ae,   K_3ae ] = KDF( PRK_3e2m, TH_3,  "K_3ae", 16 );
    auto [ info_IV_3ae, IV_3ae ] = KDF( PRK_3e2m, TH_3, "IV_3ae", 13 );
    vec CIPHERTEXT_3 = AEAD( K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vec message_3 = data_3 + cbor( CIPHERTEXT_3 );

    // Exporter ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_3
    vec TH_4_input = cbor( TH_3 ) + cbor( CIPHERTEXT_3 );
    vec TH_4 = H( TH_4_input );

    // Export funtion
    auto Export = [=] ( string label, int length ) { return KDF( PRK_4x3m, TH_4, label, length ); };

    // Derive OSCORE Master Secret and Salt
    auto [ info_OSCORE_secret, OSCORE_secret ] = Export( "OSCORE Master Secret", 16 );
    auto [ info_OSCORE_salt,   OSCORE_salt ]   = Export( "OSCORE Master Salt",    8 );

    // Derive PSK for resumption
    auto [ info_PSK, chain_PSK ] = Export( "EDHOC Chaining PSK", 16 );
    auto [ info_kid, kid_psk ]   = Export( "EDHOC Chaining kid_psk",  4 );

    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    cout << endl << "---------------------------------------------------------------" << endl;
    cout << "Test Vectors for EHDOC";
    cout << endl << "---------------------------------------------------------------" << endl;

    // message_1 ////////////////////////////////////////////////////////////////////////////

    if ( full_output == true ) {
        print( "Initiator's Key Type", type_I );
        print( "Responder's Key Type", type_R );
        print( "method", method );
        print( "corr", corr );
        print( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
        print( "Selected Cipher Suite", selected_suite );
        print( "Supported Cipher Suites", supported_suites );
        print( "Uncompressed SUITES_I", SUITES_I );
    }
    print( "X (Initiator's ephemeral private key)", X );
    if ( full_output == true ) {
        print( "G_X (Initiator's ephemeral public key)", G_X );
        print( "Connection identifier chosen by Initiator", C_I );
        print( "AD_1", AD_1 );   
    }
    if ( type_I == psk || type_R == psk )
        print( "ID_PSK", ID_PSK );   
    print( "message_1 (CBOR Sequence)", message_1 );

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print( "Y (Responder's ephemeral private key)", Y );
    if ( full_output == true ) {
        print( "G_Y (Responder's ephemeral public key)", G_Y );
        print( "G_XY (ECDH shared secret)", G_XY );
        if ( type_I == psk || type_R == psk )
            print( "PSK", PSK );   
        print( "salt", salt );
        print( "PRK_2e", PRK_2e );   
    }
    if ( type_I == sig )
        print( "SK_R (Responders's private authentication key)", SK_R );
    if ( type_R == sdh ) {
        print( "R (Responder's private authentication key)", R );
        if ( full_output == true ) {
            print( "G_R (Responder's public authentication key)", G_R );
            print( "G_RX (ECDH shared secret)", G_RX );    
        }
    }
    if ( full_output == true ) {
        print( "PRK_3e2m", PRK_3e2m );   
        print( "Connection identifier chosen by Responder", C_R );
        print( "data_2 (CBOR Sequence)", data_2 );
        print( "Input to calculate TH_2 (CBOR Sequence)", TH_2_input );
        print( "TH_2", TH_2 );
        if ( type_R != psk ) {
            print( "Responders's subject name", NAME_R );
            print( "ID_CRED_R", ID_CRED_R );
            print( "CRED_R", CRED_R );
        }
        print( "AD_2 ", AD_2 );   
        if ( type_R != psk ) {
            print( "P_2m", P_2m );
            print( "A_2m (CBOR-encoded)", A_2m );   
            print( "info for K_2m (CBOR-encoded)", info_K_2m );   
            print( "K_2m", K_2m );   
            print( "info for IV_2m (CBOR-encoded)", info_IV_2m );   
            print( "IV_2m", IV_2m );   
            print( "MAC_2", MAC_2 );   
            if ( type_R == sig )
                print( "M_2", M_2 );   
            print( "Signature_or_MAC_2", signature_or_MAC_2 );
            print( "P_2e (CBOR Sequence)", P_2e );   
            print( "info for K_2e (CBOR-encoded)", info_K_2e );   
            print( "K_2e", K_2e );
        } else {
            print( "P_2ae (CBOR Sequence)", P_2ae );   
            print( "A_2ae (CBOR-encoded)", A_2ae );   
            print( "info for K_2ae (CBOR-encoded)", info_K_2ae );   
            print( "K_2ae", K_2ae );   
            print( "info for IV_2ae (CBOR-encoded)", info_IV_2ae );   
            print( "IV_2ae", IV_2ae );   
        }
        print( "CIPHERTEXT_2", CIPHERTEXT_2 );   
    }
    print( "message_2 (CBOR Sequence)", message_2 );

    // message_3 ////////////////////////////////////////////////////////////////////////////

    if ( type_I == sig )
        print( "SK_I (Initiator's private authentication key)", SK_I );
    if ( type_I == sdh ) {
            print( "I (Initiator's private authentication key)", I );
        if ( full_output == true ) {
            print( "G_I (Initiator's public authentication key)", G_I );
            print( "G_IY (ECDH shared secret)", G_IY );
        }
    }
    if ( full_output == true ) {
        print( "PRK_4x3m", PRK_4x3m );   
        print( "data_3 (CBOR Sequence)", data_3 );
        print( "Input to calculate TH_3 (CBOR Sequence)", TH_3_input );
        print( "TH_3", TH_3);
        if ( type_I != psk ) {
            print( "Initiator's subject name", NAME_I );
            print( "ID_CRED_I", ID_CRED_I );
            print( "CRED_I", CRED_I );
            print( "AD_3", AD_3 );   
            print( "P_3m", P_3m );   
            print( "A_3m (CBOR-encoded)", A_3m );   
            print( "info for K_3m (CBOR-encoded)", info_K_3m );   
            print( "K_3m", K_3m );   
            print( "info for IV_3m (CBOR-encoded)", info_IV_3m );   
            print( "IV_3m", IV_3m );   
            print( "MAC_3", MAC_3 );   
            if ( type_I == sig )
                print( "M_3", M_3 );   
            print( "Signature_or_MAC_3", signature_or_MAC_3 );
        }
        print( "P_3ae (CBOR Sequence)", P_3ae );   
        print( "A_3ae (CBOR-encoded)", A_3ae );   
        print( "info for K_3ae (CBOR-encoded)", info_K_3ae );   
        print( "K_3ae", K_3ae );   
        print( "info for IV_3ae (CBOR-encoded)", info_IV_3ae );   
        print( "IV_3ae", IV_3ae );   
        print( "CIPHERTEXT_3", CIPHERTEXT_3 );   
    }
    print( "message_3 (CBOR Sequence)", message_3 );

    // Exporter ////////////////////////////////////////////////////////////////////////////

    if ( exporter == true ) {
        if ( full_output == true ) {
            print( "Input to calculate TH_4 (CBOR Sequence)", TH_4_input );
            print( "TH_4", TH_4 );
            print( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );
            print( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
        }   
        print( "OSCORE Master Secret", OSCORE_secret );
        print( "OSCORE Master Salt", OSCORE_salt );
        print( "Client's OSCORE Sender ID", C_R );
        print( "Server's OSCORE Sender ID", C_I );
        print( "OSCORE AEAD Algorithm", oscore_aead_alg );
        print( "OSCORE Hash Algorithm", oscore_hash_alg );

        if ( full_output == true ) {
            print( "info for chaining PSK (CBOR-encoded)", info_PSK );
            print( "info for chaining kid (CBOR-encoded)", info_kid );   
        }
        print( "Chaining PSK", chain_PSK );
        print( "Chaining kid", kid_psk );
    }
}

int main( void ) {
    if ( sodium_init() == -1 )
        syntax_error( "sodium_init()" );

    // Full output
    test_vectors( sig, sig, corr_12,   suite_0, x5t,     x5t,   false, false, false, false, true );
    test_vectors( sdh, sdh, corr_12,   suite_0, kid,     kid,   false, false, false, false, true );
    test_vectors( psk, psk, corr_12,   suite_0, kid,     kid,   false, false, false, false, true );

    // Mixed key types
    test_vectors( sig, sdh, corr_12,   suite_0, x5t,     kid,   false, false, false, false, true );
    test_vectors( sdh, sig, corr_12,   suite_0, kid,     x5t,   false, false, false, false, true );

    // Other header attributes for sig and sdh
    test_vectors( sig, sig, corr_12,   suite_0, x5u,     x5u,   false, false, false, false, true );
    test_vectors( sig, sig, corr_12,   suite_0, x5chain, x5bag, false, false, false, false, true );
    test_vectors( sdh, sdh, corr_12,   suite_0, x5chain, x5u,   false, false, false, false, true );
    test_vectors( sdh, sdh, corr_12,   suite_0, x5t,     x5bag, false, false, false, false, true );

    // Cipher suite nr. 1 and non-compressed SUITES_I
    test_vectors( sig, sig, corr_12,   suite_1, x5t,     x5t,   false, false, false, false, true );
    test_vectors( sdh, sdh, corr_12,   suite_1, kid,     kid,   false, false, false, false, true );
    test_vectors( psk, psk, corr_12,   suite_1, kid,     kid,   false, false, false, false, true );

    // All other correlations
    test_vectors( sdh, sdh, corr_none, suite_0, kid,     kid,   false, false, false, false, true );
    test_vectors( sdh, sdh, corr_23,   suite_0, kid,     kid,   false, false, false, false, true );
    test_vectors( sdh, sdh, corr_123,  suite_0, kid,     kid,   false, false, false, false, true );

    // Auxileary data
    test_vectors( sdh, sdh, corr_12,   suite_0, kid,     kid,   true, false, false, false, true );
    test_vectors( psk, psk, corr_12,   suite_0, kid,     kid,   true, false, false, false, true );

    // Subject names
    test_vectors( sdh, sdh, corr_12,   suite_0, kid,     kid,   false, true, false, false, true );

    // Long non-compressed bstr_identifiers
    test_vectors( sdh, sdh, corr_12,   suite_0, kid,     kid,   false, false, false, true, true );
    test_vectors( psk, psk, corr_12,   suite_0, kid,     kid,   false, false, false, true, true );

    // Exporter
    test_vectors( sig, sig, corr_12,   suite_0, x5t,     x5t,   false, false, true, false, true );
    test_vectors( sdh, sdh, corr_12,   suite_0, kid,     kid,   false, false, true, false, true );
    test_vectors( psk, psk, corr_12,   suite_0, kid,     kid,   false, false, true, false, true );
}