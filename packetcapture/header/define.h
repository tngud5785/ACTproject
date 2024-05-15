#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define ETHER_LENGTH	14
#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN		4

#define IPv4_HEADER	0x0800
#define ARP_HEADER	0x0806

//protocol type
#define ICMP		1
#define IGMP		2
#define TCP			6
#define EGP			8
#define UDP			17
#define OSPF		89

//ethernet type
#define SYN			0x02
#define PUSH		0x08
#define ACK			0x10
#define FIN_ACK		0x11
#define SYN_ACK		0x12
#define PUSH_ACK	0x18

#define EOOL	0x00            // End of Options List
#define NOP		0x01            // No Operation
#define SEC		0x82            // Security
#define LSR		0x83            // Loose Source Route
#define TS		0x44            // Time Stamp
#define E_SEC	0x85			// Extended Security
#define CIPSO	0x86            // Commercial Security
#define RR		0x07            // Record Route
#define STID	0x88            // Stream ID
#define SSR		0x89            // Strict Source Route
#define ZSU		0x0A            // Experimental Measurement
#define MTUP	0x0B            // MTU Probe
#define MTUR	0x0C            // MTU Reply
#define FINN	0xCD            // Experimental Flow Control
#define VISA	0x8E            // Experimental Access Control
#define ENCODE	0x0F            // Unknown
#define IMITD	0x90            // IMI Traffic Descriptor
#define EIP		0x91            // Extended Internet Protocol
#define TR		0x52            // Traceroute
#define ADDEXT	0x93            // Address Extension
#define RTRALT	0x94            // Router Alert
#define SDB		0x95            // Selective Directed Broadcast
#define UNA		0x96
#define DPS		0x97            // Dynamic Packet State
#define UMP		0x98            // Upstream Multicast Packet
#define QS		0x19            // Quick-Start
#define EXP		0x1E            // RFC3692-style Experiment

//tcp option
#define OPT_EOL             0x00
#define OPT_NOP             0x01
#define OPT_MSS             0x02
#define OPT_WSCALE          0x03
#define OPT_SACKPERMITTED   0x04
#define OPT_SACK            0x05
#define OPT_TIMESTAMP       0x08
#define OPT_USER_TIMEOUT    0x1C
#define OPT_TCP_A0          0x1D

//tcp port
#define HTTP            80
#define SMTP            25
#define POP3            110
#define IMAP            143
#define HTTPS           443
#define DNS             53
#define SSH             22
#define FTP_DATA        20
#define FTP_CONTROLL    21
#define TELNET          23

//record content type
#define CHANGE_CIPHER_SPEC 0x14
#define ALERT			   0x15
#define HANDSHAKE		   0x16
#define APPLICATION_DATA   0x17

//tls 1.2 handshake type
#define HELLO_REQUEST_RESERVED		    0x00
#define CLIENT_HELLO		            0x01
#define SERVER_HELLO		            0x02
#define HELLO_VERIFY_REQUEST_RESERVED   0x03
#define NEW_SESSION_TICKET	            0x04
#define END_OF_EARLY_DATA	            0x05
#define HELLO_RETRY_REQUEST_RESERVED    0x06
#define UNASSIGNED                      0x07
#define ENCRYPTED_EXTENSIONS            0x08
#define REQUEST_CONNNETCION_ID          0x09
#define NEW_CONNECTION_ID               0x0A
#define CERTIFICATE                     0x0B
#define SERVER_KEY_EXCHANGE_RESERVED    0x0C
#define CERTIFICATE_REQUEST	            0x0D
#define SERVER_HELLO_DONE_RESERVED      0x0E
#define CERTIFICATE_VERIFY	            0x0F
#define CLIENT_KEY_EXCHANGE_RESERVED    0x10
#define CLIENT_CERTIFICATE_REQUEST      0x11
#define UNASSIGNED18                    0x12
#define UNASSIGNED19                     0x13
#define FINISHED			            0x14
#define CERTIFICATE_URL_RESERVED        0x15
#define CERTOFICATE_STATUS_RESERVED     0x16
#define SUPPLEMENTAL_DATA_RESERVED      0x17
#define KEY_UPDATE			            0x18
#define COMPRESSED_CERTIFICATE          0x19
#define EKT_KEY 			            0x20
#define UNASSIGNED27_253	            0x21
#define MESSAGE_HASH			        0xFE
#define UNASSIGNED255			        0xFE


//tls 1.3 handshake type
#define ENCRYPTED_EXTENSIONS	0x08
#define KEY_UPDATE				0x18
#define MESSAGE_HASH			0xFE

//TLS version
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303

//alert protocol ��ȣ
#define CLOSE_NOTIFY                  0x00  // Close notify
#define UNEXPECTED_MESSAGE            0x0A  // Unexpected message
#define BAD_RECORD_MAC                0x14  // Bad record MAC
#define DECRYPTION_FAILED             0x15  // Decryption failed (reserved)
#define RECORD_OVERFLOW               0x16  // Record overflow
#define DECOMPRESSION_FAILURE         0x1E  // Decompression failure
#define HANDSHAKE_FAILURE             0x28  // Handshake failure
#define NO_CERTIFICATE                0x29  // No certificate (SSL 3.0 only, reserved)
#define BAD_CERTIFICATE               0x2A  // Bad certificate
#define UNSUPPORTED_CERTIFICATE       0x2B  // Unsupported certificate
#define CERTIFICATE_REVOKED           0x2C  // Certificate revoked
#define CERTIFICATE_EXPIRED           0x2D  // Certificate expired
#define CERTIFICATE_UNKNOWN           0x2E  // Certificate unknown
#define ILLEGAL_PARAMETER             0x2F  // Illegal parameter
#define UNKNOWN_CA                    0x30  // Unknown CA (Certificate authority)
#define ACCESS_DENIED                 0x31  // Access denied
#define DECODE_ERROR                  0x32  // Decode error
#define DECRYPT_ERROR                 0x33  // Decrypt error
#define EXPORT_RESTRICTION            0x3C  // Export restriction (reserved)
#define PROTOCOL_VERSION              0x46  // Protocol version
#define INSUFFICIENT_SECURITY         0x47  // Insufficient security
#define INTERNAL_ERROR                0x50  // Internal error
#define INAPPROPRIATE_FALLBACK        0x56  // Inappropriate fallback
#define USER_CANCELED                 0x5A  // User canceled
#define NO_RENEGOTIATION              0x64  // No renegotiation
#define UNSUPPORTED_EXTENSION         0x6E  // Unsupported extension
#define CERTIFICATE_UNOBTAINABLE      0x6F  // Certificate unobtainable
#define UNRECOGNIZED_NAME             0x70  // Unrecognized name
#define BAD_CERTIFICATE_STATUS_RESPONSE 0x71 // Bad certificate status response
#define BAD_CERTIFICATE_HASH_VALUE    0x72  // Bad certificate hash value
#define UNKNOWN_PSK_IDENTITY          0x73  // Unknown PSK identity
#define CERTIFICATE_REQUIRED          0x74  // Certificate required (TLS 1.3 only)
#define NO_APPLICATION_PROTOCOL       0x78  // No application protocol (TLS 1.3 only)


//cipher suite 
#define Reserved(GREASE)								0x7a7a
#define TLS_AES_128_GCM_SHA256							0x1301
#define TLS_AES_256_GCM_SHA384							0x1302
#define TLS_CHACHA20_POLY1305_SHA256					0x1303
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384			0xc02c
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256			0xc02b
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384			0xc030
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256			0xc02f
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384			0xc024
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256			0xc023
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384			0xc028
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256			0xc027
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA			0xc00a
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA			0xc009
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	0xcca9
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256		0xcca8
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA				0xc014
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA				0xc013
#define TLS_RSA_WITH_AES_256_GCM_SHA384					0x009d
#define TLS_RSA_WITH_AES_128_GCM_SHA256					0x009c
#define TLS_RSA_WITH_AES_256_CBC_SHA256					0x003d
#define TLS_RSA_WITH_AES_128_CBC_SHA256					0x003c
#define TLS_RSA_WITH_AES_256_CBC_SHA					0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA					0x002f

#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             0x009f
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       0xccaa
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             0x009e
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             0x006b
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256             0x0067
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA                0x0039
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA                0x0033
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV               0x00ff


//signature algorithms
#define rsa_pkcs1_sha256        0x0401
#define rsa_pkcs1_sha384        0x0501
#define rsa_pkcs1_sha512        0x0601
#define ecdsa_secp256r1_sha256  0x0403
#define ecdsa_secp384r1_sha384  0x0503
#define ecdsa_secp521r1_sha512  0x0603
#define rsa_pss_rsae_sha256     0x0804
#define rsa_pss_rsae_sha384     0x0805
#define rsa_pss_rsae_sha512     0x0806
#define ed25519                 0x0807
#define ed448                   0x0808
#define rsa_pss_pss_sha256      0x0809
#define rsa_pss_pss_sha384      0x080a
#define rsa_pss_pss_sha512      0x080b
#define rsa_pkcs1_sha1          0x0201
#define ecdsa_sha1              0x0203



//signature hash algorithm hash
#define SHAS_none        0x00
#define SHAS_md5         0x01
#define SHAS_sha1        0x02
#define SHAS_sha224      0x03
#define SHAS_sha256      0x04
#define SHAS_sha384      0x05
#define SHAS_sha512      0x06
#define SHAS_reserved    0x07 // unknown ó��
#define SHAS_Intrinsic   0x08 // unknown ó��
//������ reservedó��


//signature hash algorithm signature
#define SHAH_anonymous               0x00
#define SHAH_rsa                     0x01
#define SHAH_dsa                     0x02
#define SHAH_ecdsa                   0x03
#define SHAH_ed25519                 0x07
#define SHAH_ed448                   0x08
#define SHAH_gostr34102012_256       0x40
#define SHAH_gostr34102012_512       0x41
//�������� reservedó��


//server key exchange curve type
#define CURVE_UNASSIGNED                            0x00
#define CURVE_EXPLICIT_PRIME                        0x01
#define CURVE_EXPLICIT_CHAR2                        0x02
#define CURVE_NAMED_CURVE                           0x03
#define CURVE_UNASSIGNED_4_247                      0x04
#define CURVE_RESERVED_FOR_PRIVEATE_USE_248_255     0x05

//server key exchange ecdhe named curve
#define CURVE_DEPRECATED1_22            0x0001
#define CURVE_SECP256R1                 0x0017
#define CURVE_SECP384R1                 0x0018
#define CURVE_SECP521R1                 0x0019
#define CURVE_X25519                    0x001D
#define CURVE_X448                      0x001E
#define CURVE_RESERVED_0xFE00           0xFE00
#define CURVE_RESERVED_0xFEFF           0xFEFF
#define CURVE_DEPRECATED_0xFF01         0xFF01
#define CURVE_DEPRECATED_0xFF02         0xFF02


//extension
#define SERVER_NAME 0 // o 0�� host
#define MAX_FRAGMENT_LENGTH 1
#define CLIENT_CERTIFICATE_URL 2
#define TRUSTED_CA_KEYS 3
#define TRUNCATED_HMAC 4
#define STATUS_REQUEST 5 // o 1�� OCSP
#define USER_MAPPING 6
#define CLIENT_AUTHZ 7
#define SERVER_AUTHZ 8
#define CERT_TYPE 9
#define SUPPORTED_GROUPS 10 // o deprecated(1..22),
                           /*secp256r1 (23), secp384r1 (24), secp521r1 (25),
                           x25519(29), x448(30),
                           reserved (0xFE00..0xFEFF),
                           deprecated(0xFF01..0xFF02),*/


#define EC_POINT_FORMATS 11 // o 0�� uncompressed, 1,2�� deprecated, 248���� 255�� reserved
#define SRP 12
#define SIGNATURE_ALGORITHMS 13 // o
#define USE_SRTP 14
#define HEARTBEAT 15
#define APPLICATION_LAYER_PROTOCOL_NEGOTIATION 16 // o
#define STATUS_REQUEST_V2 17
#define SIGNED_CERTIFICATE_TIMESTAMP 18 // o
#define CLIENT_CERTIFICATE_TYPE 19
#define SERVER_CERTIFICATE_TYPE 20
#define PADDING 21 // o
#define ENCRYPT_THEN_MAC 22 // o
#define EXTENDED_MASTER_SECRET 23 // o
#define TOKEN_BINDING 24
#define CACHED_INFO 25
#define TLS_LTS 26
#define COMPRESS_CERTIFICATE 27 //o 0	Reserved	[RFC8879]
                                //1	zlib[RFC8879]
                                //2	brotli[RFC8879]
                                //3	zstd[RFC8879]
                                //4 - 16383	Unassigned
                                //16384 - 65535	Reserved for Experimental Use[RFC8879]
#define RECORD_SIZE_LIMIT 28
#define PWD_PROTECT 29
#define PWD_CLEAR 30
#define PASSWORD_SALT 31
#define TICKET_PINNING 32
#define TLS_CERT_WITH_EXTERN_PSK 33
#define DELEGATED_CREDENTIAL 34
#define SESSION_TICKET 35 // o
#define TLMSP 36
#define TLMSP_PROXYING 37
#define TLMSP_DELEGATE 38
#define SUPPORTED_EKT_CIPHERS 39
#define RESERVED_40 40
#define PRE_SHARED_KEY 41 // o
#define EARLY_DATA 42
#define SUPPORTED_VERSIONS 43
#define COOKIE 44
#define PSK_KEY_EXCHANGE_MODES 45/* o   0	psk_ke	Y	[RFC8446]
                                        1	psk_dhe_ke	Y[RFC8446]
                                        2 - 253	Unassigned
                                        254 - 255	Reserved for Private Use[RFC8446]*/
#define RESERVED_46 46
#define CERTIFICATE_AUTHORITIES 47
#define OID_FILTERS 48
#define POST_HANDSHAKE_AUTH 49
#define SIGNATURE_ALGORITHMS_CERT 50
#define KEY_SHARE 51 // o
#define TRANSPARENCY_INFO 52
#define CONNECTION_ID_DEPRECATED 53
#define CONNECTION_ID 54
#define EXTERNAL_ID_HASH 55
#define EXTERNAL_SESSION_ID 56
//#define QUIC_TRANSPORT_PARAMETERS 57
#define TICKET_REQUEST 58
#define DNSSEC_CHAIN 59
#define SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS 60
#define RRC 61
#define UNASSIGNED_62_TO_2569 62  // 62���� 2569���� �Ҵ���� ���� ������ ǥ��
#define Reserved_2570           2570
#define Reserved_51914          51914
#define Reserved_56026          56026
#define ENCRYPTED_CLIENT_HELLO  65037
#define RENEGOTIATION_INFO      65281      