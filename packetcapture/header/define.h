#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define ETHER_LENGTH	14
#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN		4

#define IPv4_HEADER	0x0800
#define IPv6_HEADER 0x86DD
#define ARP_HEADER	0x0806
#define RARP_HEADER 0x0835

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

//record content type
#define CHANGE_CIPHER_SPEC 0x14
#define ALERT			   0x15
#define HANDSHAKE		   0x16
#define APPLICATION_DATA   0x17

//tls 1.2 handshake type
#define HELLO_REQUEST		0x00
#define CLIENT_HELLO		0x01
#define SERVER_HELLO		0x02
#define NEW_SESSION_TICKET	0x04
#define CERTIFICATE			0x0B
#define SERVER_KEY_EXCHANGE	0x0C
#define CERTIFICATE_REQUEST	0x0D
#define SERVER_HELLO_DONE	0x0E
#define CERTIFICATE_VERIFY	0x0F
#define CLIENT_KEY_EXCHANGE	0x10
#define FINISHED			0x14

//tls 1.3 handshake type
#define NEW_SESSION_TICKET		0x04
#define END_OF_EARLY_DATA		0x05
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

//extension
#define SERVER_NAME 0
#define MAX_FRAGMENT_LENGTH 1
#define CLIENT_CERTIFICATE_URL 2
#define TRUSTED_CA_KEYS 3
#define TRUNCATED_HMAC 4
#define STATUS_REQUEST 5
#define USER_MAPPING 6
#define CLIENT_AUTHZ 7
#define SERVER_AUTHZ 8
#define CERT_TYPE 9
#define SUPPORTED_GROUPS 10
#define EC_POINT_FORMATS 11
#define SRP 12
#define SIGNATURE_ALGORITHMS 13
#define USE_SRTP 14
#define HEARTBEAT 15
#define APPLICATION_LAYER_PROTOCOL_NEGOTIATION 16
#define STATUS_REQUEST_V2 17
#define SIGNED_CERTIFICATE_TIMESTAMP 18
#define CLIENT_CERTIFICATE_TYPE 19
#define SERVER_CERTIFICATE_TYPE 20
#define PADDING 21
#define ENCRYPT_THEN_MAC 22
#define EXTENDED_MASTER_SECRET 23
#define TOKEN_BINDING 24
#define CACHED_INFO 25
#define TLS_LTS 26
#define COMPRESS_CERTIFICATE 27
#define RECORD_SIZE_LIMIT 28
#define PWD_PROTECT 29
#define PWD_CLEAR 30
#define PASSWORD_SALT 31
#define TICKET_PINNING 32
#define TLS_CERT_WITH_EXTERN_PSK 33
#define DELEGATED_CREDENTIAL 34
#define SESSION_TICKET 35
#define TLMSP 36
#define TLMSP_PROXYING 37
#define TLMSP_DELEGATE 38
#define SUPPORTED_EKT_CIPHERS 39
#define RESERVED_40 40
#define PRE_SHARED_KEY 41
#define EARLY_DATA 42
#define SUPPORTED_VERSIONS 43
#define COOKIE 44
#define PSK_KEY_EXCHANGE_MODES 45
#define RESERVED_46 46
#define CERTIFICATE_AUTHORITIES 47
#define OID_FILTERS 48
#define POST_HANDSHAKE_AUTH 49
#define SIGNATURE_ALGORITHMS_CERT 50
#define KEY_SHARE 51
#define TRANSPARENCY_INFO 52
#define CONNECTION_ID_DEPRECATED 53
#define CONNECTION_ID 54
#define EXTERNAL_ID_HASH 55
#define EXTERNAL_SESSION_ID 56
#define QUIC_TRANSPORT_PARAMETERS 57
#define TICKET_REQUEST 58
#define DNSSEC_CHAIN 59
#define SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS 60
#define RRC 61
#define UNASSIGNED_62_TO_2569 62  // 62���� 2569���� �Ҵ���� ���� ������ ǥ��