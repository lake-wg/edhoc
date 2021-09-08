// EDHOC Test Vectors
//
// These test vectors are based on the -10 version of the draft
// https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-10
//
// Copyright (c) 2021, Ericsson and John Preuß Mattsson <john.mattsson@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <vector>
#include <sodium.h>
#include "aes.h"

using namespace std;
using vec = vector<uint8_t>;

enum EDHOCKeyType { sig, sdh }; 
enum COSEHeader { kid = 4, x5bag = 32, x5chain = 33, x5t = 34, x5u = 35, cwt = 42, uccs = 43 }; // cwt / uccs is TDB, 42 and 43 are just examples
enum COSEAlgorithm { SHA_256 = -16, SHA_256_64 = -15, EdDSA = -8, AES_CCM_16_64_128 = 10, AES_CCM_16_128_128 = 30 }; 
enum COSECurve { X25519 = 4, Ed25519 = 6 }; 
enum COSECommon { kty = 1 };
enum COSEKCP { kcp_kid = 2 }; 
enum COSEKTP { x = -2, crv = -1, OKP = 1 }; 
enum CWTClaims { sub = 2, cnf = 8 };
enum ConfMethod { COSE_Key = 1 };

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

// Compress ID_CRED_x if it contains a single 'kid' parameter
vec compress_id_cred( vec v ) {
    if ( vec{ v[0], v[1] } == cbor_map( 1 ) + cbor( kid ) )
        return vec( v.begin() + 2, v.end() );
    else
        return v;
}

// OSCORE id from EDHOC connection id
// This function does not work with bstr with length 24 or more
vec OSCORE_id( vec v ) {
    if ( v[0] >= 0x40 && v[0] <= 0x57 ) {
        return vec( v.begin() + 1, v.end() );
    } else {
        return v;
    }
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

vec sequence_vector( int len ) {
    vec out( len );
    for( int i = 0; i < len; i++ )
        out[i] = i;
    return out;
}

vec random_ead() {
    vec out;
    int len = rand() % 5;
    for( int i = 0; i < len; i++ ) {
        int ead_type = rand() % 6;
        if ( ead_type == 0 ) {
            out = out + cbor( rand() % 100 ) + vec{ 0xf5 };
        } else if ( ead_type == 1 ) {
            out = out + cbor( rand() % 100 ) + cbor( sequence_vector( 5 + rand() % 15 ) );
        } else if ( ead_type == 2 ) {
            out = out + cbor( rand() % 100 ) + vec{ 0xfb, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F };
        } else if ( ead_type == 3 ) {
            out = out + cbor( rand() % 100 ) + cbor( rand() % 10000 );
        } else if ( ead_type == 4 ) {
            out = out + cbor( rand() % 100 ) + cbor_arr(2) + cbor( sequence_vector( 5 + rand() % 5 ) ) + cbor( sequence_vector( 5 + rand() % 5 ) );
        } else if ( ead_type == 5 ) {
            out = out + cbor( rand() % 100 ) + cbor_map(1) + vec{ 0xf6 } + cbor( sequence_vector( 5 + rand() % 5 ) );
        }           
    }
    return out;
}

// TODO other COSE algorithms like ECDSA, P-256, SHA-384, P-384, AES-GCM, ChaCha20-Poly1305
void test_vectors( EDHOCKeyType type_I, EDHOCKeyType type_R, int selected_suite,
                   COSEHeader attr_I, COSEHeader attr_R,
                   bool full_output, bool complex ) {

    // METHOD and seed random number generation
    int method = 2 * type_I + type_R;
    vec METHOD = cbor( method );
    int seed = 10000 * method + 1000 * attr_I + 100 * attr_R + 10 * selected_suite + complex;
    srand( seed );

    // EDHOC and OSCORE algorithms
    int edhoc_hash_alg = SHA_256;
    int edhoc_ecdh_curve = X25519;
    int edhoc_sign_alg = EdDSA;
    int edhoc_sign_curve = Ed25519;
    int oscore_aead_alg = AES_CCM_16_64_128;
    int oscore_hash_alg = SHA_256;

    int edhoc_aead_alg, edhoc_mac_length_2 = 32, edhoc_mac_length_3 = 32;
    vec SUITES_I;
    // supported suites = 0, 2, 1, 3, 4, 5
    if ( selected_suite == 0 ) {
        SUITES_I = cbor( 0 );
        edhoc_aead_alg = AES_CCM_16_64_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 8;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 8;
    }
    if ( selected_suite == 1 ) {
        SUITES_I = cbor_arr( 3 ) + cbor( 0 ) + cbor( 2 ) + cbor( 1 );
        edhoc_aead_alg = AES_CCM_16_128_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 16;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 16;
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

    // PRKs
    auto hkdf_extract = [=] ( vec salt, vec IKM ) { return hmac( edhoc_hash_alg, salt, IKM ); };

    vec salt, PRK_2e;
    PRK_2e = hkdf_extract( salt, G_XY );

    vec PRK_3e2m = PRK_2e;
    if ( type_R == sdh )
        PRK_3e2m = hkdf_extract( PRK_2e, G_RX );

    vec PRK_4x3m = PRK_3e2m;
    if ( type_I == sdh )
        PRK_4x3m = hkdf_extract( PRK_3e2m, G_IY );

    // Functions for kid and connection IDs.
    auto identifier = [=] () {
        if ( complex == true )
            if ( rand() % 2 == 0 ) {
                return cbor( random_vector( 2 + rand() % 2 ) );
            } else {
                return cbor( rand() % 16777216 );
            }           
        else {
            int i = rand() % 49;
            if ( i == 48 ) {
                return cbor( vec{} );
            } else {
                return cbor( i - 24 );
            }           
        }
    };

    // Calculate C_I != C_R (required for OSCORE)
    vec C_I, C_R;
    do {
        C_I = identifier();
        C_R = identifier();
        if ( seed == 34400 ) 
            C_R = vec{ 0x40 };
    } while ( C_I == C_R );

    // Calculate ID_CRED_x and CRED_x
    // TODO TODO
    auto gen_CRED = [=] ( EDHOCKeyType type, COSEHeader attr, vec PK_sig, vec PK_sdh, string name, string uri ) {
        vec kid_id = identifier();
        vec uccs_map = cbor_map( 2 )
        + cbor( sub ) + cbor( name ) 
        + cbor( cnf ) + cbor_map( 1 )
        + cbor( COSE_Key ) + cbor_map( 4 )
        + cbor( kty ) + cbor( OKP )
        + cbor( kcp_kid ) + kid_id
        + cbor( crv );
        if ( type == sig )
            uccs_map = uccs_map + cbor( edhoc_sign_curve ) + cbor( x ) + cbor( PK_sig );
        if ( type == sdh )
            uccs_map = uccs_map + cbor( edhoc_ecdh_curve ) + cbor( x ) + cbor( PK_sdh );

        vec CRED, ID_CRED = cbor_map( 1 ) + cbor( attr );
        if ( attr == kid ) {
            CRED = uccs_map;
            ID_CRED = ID_CRED + kid_id;
        } else if ( attr == uccs ) {
            CRED = uccs_map;
            ID_CRED = ID_CRED + uccs_map;
        } else {
            vec X509 = sequence_vector( 100 + rand() % 50 );
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

    auto [ ID_CRED_I, CRED_I ] = gen_CRED( type_I, attr_I, PK_I, G_I, "42-50-31-FF-EF-37-32-39", "https://example.edu/2716057" );
    auto [ ID_CRED_R, CRED_R ] = gen_CRED( type_R, attr_R, PK_R, G_R, "example.edu", "https://example.edu/3370318" );

    // External Authorization Data
    vec EAD_1, EAD_2, EAD_3, EAD_4;
    if ( complex == true ) {
        EAD_1 = random_ead();
        EAD_2 = random_ead();
        EAD_3 = random_ead();
        EAD_4 = random_ead();        
    }
 
    vec message_1 = METHOD + SUITES_I + cbor( G_X ) + C_I + EAD_1;

    // Helper funtions using local variables ////////////////////////////////////////////////////////////////////////////

    auto H = [=] ( vec input ) { return HASH( edhoc_hash_alg, input ); };
    auto A = [] ( vec protect, vec external_aad ) { return cbor_arr( 3 ) + cbor( "Encrypt0" ) + protect + external_aad; };
    auto M = [] ( vec protect, vec external_aad, vec payload ) { return cbor_arr( 4 ) + cbor( "Signature1" ) + protect + external_aad + payload; };

    // Creates the info parameter and derives output key matrial with HKDF-Expand
    auto KDF = [=] ( vec PRK, vec transcript_hash, string label, vec context, int length ) {
        vec info = cbor( edhoc_aead_alg ) + cbor( transcript_hash ) + cbor( label ) + cbor( context ) + cbor( length );
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
    vec hash_message_1 = H( message_1 );
    vec TH_2_input = cbor( hash_message_1 ) + cbor( G_Y ) + C_R;
    vec TH_2 = H( TH_2_input );

    // Calculate MAC_2
    vec MAC_2_context = ID_CRED_R + CRED_R + EAD_2;
    auto [ info_MAC_2, MAC_2 ] = KDF( PRK_3e2m, TH_2, "MAC_2", MAC_2_context, edhoc_mac_length_2 );

    // Calculate Signature_or_MAC_2
    vec protected_2 = cbor( ID_CRED_R ); // bstr wrap
    vec external_aad_2 = cbor( cbor( TH_2 ) + CRED_R + EAD_2 ); // bstr wrap
    vec M_2 = M( protected_2, external_aad_2, cbor( MAC_2 ) );
    vec signature_or_MAC_2 = MAC_2;
    if ( type_R == sig )
        signature_or_MAC_2 = sign( SK_R, M_2 );

    // Calculate CIPHERTEXT_2
    vec PLAINTEXT_2 = compress_id_cred( ID_CRED_R ) + cbor( signature_or_MAC_2 ) + EAD_2;
    auto [ info_KEYSTREAM_2, KEYSTREAM_2 ] = KDF( PRK_2e, TH_2, "KEYSTREAM_2", vec{}, PLAINTEXT_2.size() );
    vec CIPHERTEXT_2 = xor_encryption( KEYSTREAM_2, PLAINTEXT_2 );

    // Calculate message_2
    vec G_Y_CIPHERTEXT_2 = cbor( G_Y + CIPHERTEXT_2 );
    vec message_2 = G_Y_CIPHERTEXT_2 + C_R;

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3 and TH_3
    vec TH_3_input = cbor( TH_2 ) + cbor( CIPHERTEXT_2 );
    vec TH_3 = H( TH_3_input );

    // Calculate MAC_3
    vec MAC_3_context = ID_CRED_I + CRED_I + EAD_3;
    auto [ info_MAC_3, MAC_3 ] = KDF( PRK_4x3m, TH_3, "MAC_3", MAC_3_context, edhoc_mac_length_3 );

    // Calculate Signature_or_MAC_3
    vec protected_3 = cbor( ID_CRED_I ); // bstr wrap
    vec external_aad_3 = cbor( cbor( TH_3 ) + CRED_I + EAD_3 ); // bstr wrap
    vec M_3 = M( protected_3, external_aad_3, cbor( MAC_3 ) );
    vec signature_or_MAC_3 = MAC_3;
    if ( type_I == sig )
        signature_or_MAC_3 = sign( SK_I, M_3 );

    // Calculate CIPHERTEXT_3
    vec P_3ae = compress_id_cred( ID_CRED_I ) + cbor( signature_or_MAC_3 ) + EAD_3;
    vec A_3ae = A( cbor( vec{} ), cbor( TH_3 ) );
    auto [ info_K_3ae,   K_3ae ] = KDF( PRK_3e2m, TH_3, "K_3ae",  vec{}, 16 );
    auto [ info_IV_3ae, IV_3ae ] = KDF( PRK_3e2m, TH_3, "IV_3ae", vec{}, 13 );
    vec CIPHERTEXT_3 = AEAD( K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vec message_3 = cbor( CIPHERTEXT_3 );

    // message_4 and Exporter ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vec TH_4_input = cbor( TH_3 ) + message_3;
    vec TH_4 = H( TH_4_input );

    // Export funtion
    auto Export = [=] ( string label, vec context, int length ) { return KDF( PRK_4x3m, TH_4, label, context, length ); };

    // Calculate message_4
    vec P_4ae = EAD_4;
    vec A_4ae = A( cbor( vec{} ), cbor( TH_4 ) );
    auto [ info_K_4ae,   K_4ae ] = Export( "EDHOC_message_4_Key",   vec{}, 16 );
    auto [ info_IV_4ae, IV_4ae ] = Export( "EDHOC_message_4_Nonce", vec{}, 13 );
    vec CIPHERTEXT_4 = AEAD( K_4ae, IV_4ae, P_4ae, A_4ae );
    vec message_4 = cbor( CIPHERTEXT_4 );

    // Derive OSCORE Master Secret and Salt
    auto [ info_OSCORE_secret, OSCORE_secret ] = Export( "OSCORE Master Secret", vec{}, 16 );
    auto [ info_OSCORE_salt,   OSCORE_salt ]   = Export( "OSCORE Master Salt",   vec{},  8 );

    // KeyUpdate funtion
    vec nonce = random_vector( 16 );
    vec PRK_4x3m_new = hkdf_extract( nonce, PRK_4x3m );
    auto Export2 = [=] ( string label, vec context, int length ) { return KDF( PRK_4x3m_new, TH_4, label, context, length ); };
    auto [ info_OSCORE_secretFS, OSCORE_secretFS ] = Export2( "OSCORE Master Secret", vec{}, 16 );
    auto [ info_OSCORE_saltFS,   OSCORE_saltFS ]   = Export2( "OSCORE Master Salt",   vec{},  8 );

    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    cout << endl << "---------------------------------------------------------------" << endl;
    cout << "Test Vector for EHDOC";
    cout << endl << "---------------------------------------------------------------" << endl;

    if ( full_output == true ) {
        print( "Test Vector Seed", seed ); 
    }
    cout << endl  << endl << endl  << endl;

    // message_1 ////////////////////////////////////////////////////////////////////////////

    if ( full_output == true ) {
        print( "METHOD (CBOR Data Item)", METHOD );
        print( "SUITES_I (CBOR Data Item)", SUITES_I );
    }
    print( "X (Raw Value) (Initiator's ephemeral private key)", X );
    if ( full_output == true ) {
        print( "G_X (Raw Value) (Initiator's ephemeral public key)", G_X );
        print( "G_X (CBOR Data Item) (Initiator's ephemeral public key)", cbor( G_X ) );
        print( "C_I (CBOR Data Item) (Connection identifier chosen by Initiator)", C_I );
        print( "EAD_1 (CBOR Sequence)", EAD_1 );   
    }
    print( "message_1 (CBOR Sequence)", message_1 );
    cout << endl  << endl << endl  << endl;
  
    // message_2 ////////////////////////////////////////////////////////////////////////////

    print( "Y (Raw Value) (Responder's ephemeral private key)", Y );
    if ( full_output == true ) {
        print( "G_Y (Raw Value) (Responder's ephemeral public key)", G_Y );
        print( "G_Y (CBOR Data Item) (Responder's ephemeral public key)", cbor( G_Y ) );
        print( "G_XY (Raw Value) (ECDH shared secret)", G_XY );
        print( "salt (Raw Value)", salt );
        print( "PRK_2e (Raw Value)", PRK_2e );   
    }
    if ( type_R == sig ) {
        print( "SK_R (Raw Value) (Responders's private authentication key)", SK_R );
        print( "PK_R (Raw Value) (Responders's public authentication key)", PK_R );
    }
    if ( type_R == sdh ) {
        print( "R (Raw Value) (Responder's private authentication key)", R );
        if ( full_output == true ) {
            print( "G_R (Raw Value) (Responder's public authentication key)", G_R );
            print( "G_RX (Raw Value) (ECDH shared secret)", G_RX );    
        }
    }
    if ( full_output == true ) {
        print( "PRK_3e2m (Raw Value)", PRK_3e2m );   
        print( "C_R (CBOR Data Item) (Connection identifier chosen by Responder)", C_R );
        print( "H(message_1) (Raw Value)", hash_message_1 );
        print( "H(message_1) (CBOR Data Item)", cbor( hash_message_1 ) );
        print( "Input to calculate TH_2 (CBOR Sequence)", TH_2_input );
        print( "TH_2 (Raw Value)", TH_2 );
        print( "TH_2 (CBOR Data Item)", cbor( TH_2 ) );
        print( "ID_CRED_R (CBOR Data Item)", ID_CRED_R );
        print( "CRED_R (CBOR Data Item)", CRED_R );
        print( "EAD_2 (CBOR Sequence)", EAD_2 );   
        print( "info for MAC_2 (CBOR Sequence)", info_MAC_2 );   
        print( "MAC_2 (Raw Value)", MAC_2 );   
        print( "MAC_2 (CBOR Data Item)", cbor( MAC_2 ) );   
        if ( type_R == sig )
            print( "Message to be signed 2 (CBOR Data Item)", M_2 );   
        print( "Signature_or_MAC_2 (Raw Value)", signature_or_MAC_2 );
        print( "Signature_or_MAC_2 (CBOR Data Item)", cbor( signature_or_MAC_2 ) );
        print( "PLAINTEXT_2 (CBOR Sequence)", PLAINTEXT_2 );   
        print( "info for KEYSTREAM_2 (CBOR Sequence)", info_KEYSTREAM_2 );   
        print( "KEYSTREAM_2 (Raw Value)", KEYSTREAM_2 );
        print( "CIPHERTEXT_2 (Raw Value)", CIPHERTEXT_2 );   
        print( "CIPHERTEXT_2 (CBOR Data Item)", cbor( CIPHERTEXT_2 ) );   
    }
    print( "message_2 (CBOR Sequence)", message_2 );
    cout << endl  << endl << endl  << endl;

    // message_3 ////////////////////////////////////////////////////////////////////////////

    if ( type_I == sig ) {
        print( "SK_I (Raw Value) (Initiator's private authentication key)", SK_I );
        print( "PK_I (Raw Value) (Responders's public authentication key)", PK_I );
    }
    if ( type_I == sdh ) {
            print( "I (Raw Value) (Initiator's private authentication key)", I );
        if ( full_output == true ) {
            print( "G_I (Raw Value) (Initiator's public authentication key)", G_I );
            print( "G_IY (Raw Value) (ECDH shared secret)", G_IY );
        }
    }
    if ( full_output == true ) {
        print( "PRK_4x3m (Raw Value)", PRK_4x3m );   
        print( "Input to calculate TH_3 (CBOR Sequence)", TH_3_input );
        print( "TH_3 (Raw Value)", TH_3);
        print( "TH_3 (CBOR Data Item)", cbor( TH_3) );
        print( "ID_CRED_I (CBOR Data Item)", ID_CRED_I );
        print( "CRED_I (CBOR Data Item)", CRED_I );
        print( "EAD_3 (CBOR Sequence)", EAD_3 );   
        print( "info for MAC_3 (CBOR Sequence)", info_MAC_3 );   
        print( "MAC_3 (Raw Value)", MAC_3 );   
        print( "MAC_3 (CBOR Data Item)", cbor( MAC_3 ) );   
        if ( type_I == sig )
            print( "Message to be signed 3 (CBOR Data Item)", M_3 );   
        print( "Signature_or_MAC_3 (Raw Value)", signature_or_MAC_3 );
        print( "Signature_or_MAC_3 (CBOR Data Item)", cbor( signature_or_MAC_3 ) );
        print( "P_3ae (CBOR Sequence)", P_3ae );   
        print( "A_3ae (CBOR Data Item)", A_3ae );   
        print( "info for K_3ae (CBOR Sequence)", info_K_3ae );   
        print( "K_3ae (Raw Value)", K_3ae );   
        print( "info for IV_3ae (CBOR Sequence)", info_IV_3ae );   
        print( "IV_3ae (Raw Value)", IV_3ae );   
        print( "CIPHERTEXT_3 (Raw Value)", CIPHERTEXT_3 );   
        print( "CIPHERTEXT_3 (CBOR Data Item)", cbor( CIPHERTEXT_3 ) );   
    }
    print( "message_3 (CBOR Sequence)", message_3 );
    cout << endl  << endl << endl  << endl;

    // message_4 and Exporter ////////////////////////////////////////////////////////////////////////////

    if ( full_output == true ) {
        print( "Input to calculate TH_4 (CBOR Sequence)", TH_4_input );
        print( "TH_4 (Raw Value)", TH_4 );
        print( "TH_4 (CBOR Data Item)", cbor( TH_4 ) );
        print( "EAD_4 (CBOR Sequence)", EAD_4 );   
        print( "P_4ae (CBOR Sequence)", P_4ae );   
        print( "A_4ae (CBOR Data Item)", A_4ae );   
        print( "info for K_4ae (CBOR Sequence)", info_K_4ae );   
        print( "K_4ae (Raw Value)", K_4ae );   
        print( "info for IV_4ae (CBOR Sequence)", info_IV_4ae );   
        print( "IV_4ae (Raw Value)", IV_4ae );   
        print( "CIPHERTEXT_4", CIPHERTEXT_4 );   
        print( "CIPHERTEXT_4 (CBOR Data Item)", cbor( CIPHERTEXT_4 ) );   
    }
    print( "message_4 (CBOR Sequence)", message_4 );
    print( "info for OSCORE Master Secret (CBOR Sequence)", info_OSCORE_secret );
    print( "OSCORE Master Secret (Raw Value)", OSCORE_secret );
    print( "info for OSCORE Master Salt (CBOR Sequence)", info_OSCORE_salt );   
    print( "OSCORE Master Salt (Raw Value)", OSCORE_salt );
    print( "Client's OSCORE Sender ID (Raw Value)", OSCORE_id( C_R ) );
    print( "Server's OSCORE Sender ID (Raw Value)", OSCORE_id( C_I ) );
    print( "OSCORE AEAD Algorithm", oscore_aead_alg );
    print( "OSCORE Hash Algorithm", oscore_hash_alg );

    print( "KeyUpdate Nonce (Raw Value)", nonce );
    if ( full_output == true ) {
        print( "PRK_4x3m  after KeyUpdate (Raw Value)", PRK_4x3m_new );   
    }
    print( "OSCORE Master Secret after KeyUpdate (Raw Value)", OSCORE_secretFS );
    print( "OSCORE Master Salt after KeyUpdate (Raw Value)", OSCORE_saltFS ); 
}

int main( void ) {
    if ( sodium_init() == -1 )
        syntax_error( "sodium_init()" );

    // Error ////////////////////////////////////////////////////////////////////////////

    cout << endl << "---------------------------------------------------------------" << endl;
    cout << "Example EDHOC error messages";
    cout << endl << "---------------------------------------------------------------" << endl;

    vec error0 = cbor( 0 ) + cbor_map( 3 ) + cbor( "sub" ) + cbor( "Skynet" )
                                           + cbor( "time" ) + cbor( "1997-08-29T02:14:00+05:00" )
                                           + cbor( "cert hash" ) + cbor( vec{ 0x57, 0xe9, 0xc0, 0x28, 0x0a, 0x85, 0x90, 0xe0, 0x51, 0xa7, 0xd3, 0x24, 0x1b, 0x82, 0x40, 0xfe } );
    vec error11 = cbor( 1 ) + cbor( "COSE header parameter x5u not supported" );
    vec error12 = cbor( 1 ) + cbor( "CA not trusted" );
    vec error13 = cbor( 1 ) + cbor( "Malformed message_2" );
    vec error14 = cbor( 1 ) + cbor( "Comic Sans MUST be used!" );
    vec error21 = cbor( 2 ) + cbor( 3 );
    vec error22 = cbor( 2 ) + cbor_arr( 2 ) + cbor( 25 ) + cbor( 24 );

    print( "Example error message with ERR_CODE = 0 (Success)", error0 ); 
    print( "Example error message with ERR_CODE = 1 (Unspecified)", error11 ); 
    print( "Example error message with ERR_CODE = 1 (Unspecified)", error12 ); 
    print( "Example error message with ERR_CODE = 1 (Unspecified)", error13 ); 
    print( "Example error message with ERR_CODE = 1 (Unspecified)", error14 ); 
    print( "Example error message with ERR_CODE = 2 (Wrong selected cipher suite)", error21 ); 
    print( "Example error message with ERR_CODE = 2 (Wrong selected cipher suite)", error22 ); 
    cout << endl  << endl << endl  << endl;

    // The four methods with COSE header parameters kid and x5t
    test_vectors( sdh, sdh, 0, kid, kid, true, false );
    test_vectors( sdh, sig, 0, kid, x5t, true, false );
    test_vectors( sig, sdh, 0, x5t, kid, true, false );
    test_vectors( sig, sig, 0, x5t, x5t, true, false );

    // Other COSE header parameters
    test_vectors( sdh, sdh, 0, x5u, x5u, true, false );
    test_vectors( sdh, sig, 0, x5chain, x5bag, true, false );
    test_vectors( sdh, sig, 0, uccs, cwt, true, false );

    // Cipher suite 1
    test_vectors( sdh, sdh, 1, kid, kid, true, false );
    test_vectors( sig, sig, 1, x5t, x5t, true, false );

    // More complex, with long id, EAD
    test_vectors( sdh, sdh, 0, kid, kid, true, true );
    test_vectors( sig, sig, 0, x5t, x5t, true, true );
}
