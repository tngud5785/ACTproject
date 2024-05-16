#pragma once
#include "define.h"
#include "include.h"

#pragma pack(push, 1)
typedef struct tls_header {
	u_char		tls_type;
	u_short		tls_version;
	u_short		tls_length;
}TLSHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ccs_proto {
	TLSHeader	tls_header;
	u_char		ccs_message;
}ChangeCipherSpec;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct alert_proto {
	TLSHeader	tls_header;
	u_char		alert_level;
	u_char		alert_descl;
}Alert;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct alert_proto_enc {
	TLSHeader	tls_header;
	u_char		alert_enc[];
}AlertEnc;
#pragma pack(pop)




#pragma pack(push, 1)
typedef struct handshake_proto {
	TLSHeader		tls_header;
	u_int			handshake_type_leng;
}Handshake;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct application_proto {
	TLSHeader	tls_header;
	u_char		app_enc_data[];
}ApplicationData;
#pragma pack(pop)


//hello request
#pragma pack(push, 1)
typedef struct hello_request {
	TLSHeader	tls_header;
}HelloRequest;
#pragma pack(pop)


//client hello
#pragma pack(push, 1)
typedef struct client_hello {
	Handshake		handshake_header;
	u_short			client_hello_version;
	u_char			ch_random_bytes[32];
}ClientHello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello_session {
	u_char			ch_session_id_length;
	u_char			ch_session_id[];
}ClientHelloSession;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello_cipher {
	u_short			ch_cipher_suites_length;
	u_short			ch_cipher_suites[];
}ClientHelloCipher;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello_compression {
	u_char			ch_compression_methods_length;
	u_char			ch_compression_methods;
}ClientHelloCompression;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello_extensions {
	u_short			extensions_total_length;
	u_short			extensions_type;
	u_short			extensions_length;
}ClientHelloExtensions;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct extensions_type_length {
	u_short			extensions_type;
	u_short			extensions_length;
} ExtensionsTypeLength;
#pragma pack(pop)



//server hello struct
#pragma pack(push, 1)
typedef struct server_hello {
	Handshake		handshake_header;
	u_short			server_hello_version;
	u_char			sh_random_bytes[32];
	u_char			sh_session_id_length;
	u_short			sh_cipher_suites;
	u_char			sh_compression_methods;
	u_short			sh_extensions_length;
}ServerHello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello_extensions {
	u_short			extensions_type;
	u_short			extensions_length;
}ServerHelloExtensions;
#pragma pack(pop)














//extension struct
#pragma pack(push, 1)
typedef struct server_name {
	ExtensionsTypeLength	extensions_type_length;
	u_short					server_name_list_length;
	u_char					server_name_type;
	u_short					server_name_length;
	u_char					server_domain_name[];
} ServerName;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct max_fragment_length {
	ExtensionsTypeLength	extensions_type_length;
} MaxFragmentLength;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_certificate_url {
	ExtensionsTypeLength	extensions_type_length;
} ClientCertificateURL;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct trusted_ca_keys {
	ExtensionsTypeLength	extensions_type_length;
} TrustedCAKeys;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct truncated_hmac {
	ExtensionsTypeLength	extensions_type_length;
} TruncatedHMAC;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct status_request {
	ExtensionsTypeLength	extensions_type_length;
	u_char					status_type;
	u_short					responder_id_list_length;
	u_short					request_extensions_length;
} StatusRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct user_mapping {
	ExtensionsTypeLength	extensions_type_length;
} UserMapping;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_authz {
	ExtensionsTypeLength	extensions_type_length;
} ClientAuthz;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_authz {
	ExtensionsTypeLength	extensions_type_length;
} ServerAuthz;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cert_type {
	ExtensionsTypeLength	extensions_type_length;
} CertType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_groups {
	ExtensionsTypeLength	extensions_type_length;
	u_short					sup_groups_list_length;
	u_short					sup_groups[];
} SupportedGroups;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ec_point_formats {
	ExtensionsTypeLength	extensions_type_length;
	u_char					ec_point_formats_length;
	u_char					ec_point_format[];
} ECPointFormats;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct srp{
	ExtensionsTypeLength	extensions_type_length;
	u_short					srp_length;
	u_char					_srp;
} ExtentsionSRP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signature_algorithms {
	ExtensionsTypeLength	extensions_type_length;
	u_short					signature_hash_algorithms_length;
	u_short					signature_hash_algorithms[];
} SignatureAlgorithms;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct use_srtp {
	ExtensionsTypeLength	extensions_type_length;
	u_short					use_srtp_length;
	u_char					_use_srtp;
} UseSrtp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct heartbeat {
	ExtensionsTypeLength	extensions_type_length;
	u_short					heartbeat_length;
	u_char					_heartbeat;
} Heartbeat;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct application_layer_protocol_negotiation {
	ExtensionsTypeLength	extensions_type_length;
	u_short					alpn_extension_length;
	u_char					alpn_string_length;
	u_char					alpn_next_protocol[]; // ascii
} Alpn;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct status_request_v2 {
	ExtensionsTypeLength	extensions_type_length;
	u_short					status_request_v2_length;
	u_char					_status_request_v2;
} StatusRequestV2;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signed_certificate_timestamp {
	ExtensionsTypeLength	extensions_type_length;
} SignedCertificateTimestamp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_certificate_type {
	ExtensionsTypeLength	extensions_type_length;
	u_short					client_certificate_type_length;
	u_char					_client_certificate_type;
} ClientCertificateType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_certificate_type {
	ExtensionsTypeLength	extensions_type_length;
	u_short					server_certificate_type_length;
	u_char					_server_certificate_type;
} ServerCertificateType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct padding {
	ExtensionsTypeLength	extensions_type_length;
	u_char					padding_data[];
} Padding;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypt_then_mac {
	ExtensionsTypeLength	extensions_type_length;
} EncryptThenMac;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct extended_master_secret {
	ExtensionsTypeLength	extensions_type_length;
} ExtendedMasterSecret;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct token_binding {
	ExtensionsTypeLength	extensions_type_length;
} TokenBinding;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cached_info {
	ExtensionsTypeLength	extensions_type_length;
} CachedInfo;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tls_lts {
	ExtensionsTypeLength	extensions_type_length;
} TlsLts;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct compress_certificate {
	ExtensionsTypeLength	extensions_type_length;
} CompressCertificate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct record_size_limit {
	ExtensionsTypeLength	extensions_type_length;
} RecordSizeLimit;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct pwd_protect {
	ExtensionsTypeLength	extensions_type_length;
} PwdProtect;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct pwd_clear {
	ExtensionsTypeLength	extensions_type_length;
} PwdClear;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct password_salt {
	ExtensionsTypeLength	extensions_type_length;
} PasswordSalt;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ticket_pinning {
	ExtensionsTypeLength	extensions_type_length;
} TicketPinning;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tls_cert_with_extern_psk {
	ExtensionsTypeLength	extensions_type_length;
} TlsCertWithExternPsk;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct delegated_credential {
	ExtensionsTypeLength	extensions_type_length;
} DelegatedCredential;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct session_ticket {
	ExtensionsTypeLength	extensions_type_length;
	u_char					session_ticket_data[];
} SessionTicket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp {
	ExtensionsTypeLength	extensions_type_length;
} Tlsmp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp_proxying {
	ExtensionsTypeLength	extensions_type_length;
} TlmspProxying;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp_delegate {
	ExtensionsTypeLength	extensions_type_length;
} TlmspDelegate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_ekt_ciphers {
	ExtensionsTypeLength	extensions_type_length;
} SupportedEktCiphers;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct reserved_40 {
	ExtensionsTypeLength	extensions_type_length;
} Reserved_40;
#pragma pack(pop)

typedef struct pre_shared_key{
	ExtensionsTypeLength	extensions_type_length;
	u_short					identities_length;
	u_short					identity_length;
	u_char					idnetity;
	u_int					obfuscated_ticket_age;
	u_short					psk_binders_length;
	u_char					psk_binders;
} PreSharedKey;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct early_data{
	ExtensionsTypeLength	extensions_type_length;
} EarlyData;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_versions {
	ExtensionsTypeLength	extensions_type_length;
	u_char					supported_versions_length;
	u_short					supported_version[];
} SupportedVersions;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cookie {
	ExtensionsTypeLength	extensions_type_length;
	u_short					cookie_length;
	u_char					cookie_data[];
} Cookie;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct psk_key_exchange_modes {
	ExtensionsTypeLength	extensions_type_length;
	u_char					psk_key_exchange_modes_length;
	u_char					psk_key_exchange_mode[];
} PskKeyExchangeModes;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct reserved_46 {
	ExtensionsTypeLength	extensions_type_length;
} Reserved_46;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_authorities {
	ExtensionsTypeLength	extensions_type_length;
} CertificateAuthorities;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct oid_filters {
	ExtensionsTypeLength	extensions_type_length;
} OidFilters;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct post_handshake_auth {
	ExtensionsTypeLength	extensions_type_length;
} PostHandshakeAuth;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signature_algorithms_cert {
	ExtensionsTypeLength	extensions_type_length;
} SignatureAlgorithmsCert;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct key_share {
	ExtensionsTypeLength	extensions_type_length;
	u_short					Client_key_share_length;
	u_short					group;
	u_short					key_exchange_length;
	u_char					key_exchange[];
} KeyShare;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct transparency_info {
	ExtensionsTypeLength	extensions_type_length;
} TransparencyInfo;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct connection_id_deprecated {
	ExtensionsTypeLength	extensions_type_length;
} ConnectionIdDeprecated;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct connection_id {
	ExtensionsTypeLength	extensions_type_length;
} ConnectionId;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct external_id_hash {
	ExtensionsTypeLength	extensions_type_length;
} ExternalIdHash;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct external_session_id {
	ExtensionsTypeLength	extensions_type_length;
} ExternalSessionId;
#pragma pack(pop)

//#pragma pack(push, 1)
//typedef struct quic_transport_parameters {
//	ExtensionsTypeLength	extensions_type_length;
//} QuicTransportParameters;
//#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ticket_request {
	ExtensionsTypeLength	extensions_type_length;
} TicketRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dnssec_chain {
	ExtensionsTypeLength	extensions_type_length;
} DnssecChain;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct sequence_number_encryption_algortithms {
	ExtensionsTypeLength	extensions_type_length;
} SequenceNumberEncryptionAlgortithms;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct rrc {
	ExtensionsTypeLength	extensions_type_length;
} Rrc;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypted_client_hello {
	ExtensionsTypeLength	extensions_type_length;
	u_char					client_hello_type; // 0Àº outer, 1Àº inner
	u_int					cipher_suite;
	u_char					config_id;
} EncryptedClientHello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypted_client_hello_enc {
	EncryptedClientHello	en_client_hello;
	u_short					enc_length;
	u_char					enc_data[];
} EncryptedClientHelloEnc;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypted_client_hello_payload{
	EncryptedClientHello	en_client_hello;
	u_short					payload_length;
	u_char					payload[];
} EncryptedClientHelloPayload;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct new_session_ticket {
	ExtensionsTypeLength	extensions_type_length;
}NewSessionTicket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct renegotiation_info {
	ExtensionsTypeLength	extensions_type_length;
	u_char					renegotiation_info_extension_length;
} RenegotiationInfo;
#pragma pack(pop)



//handshake-certificate
#pragma pack(push, 1)
typedef struct certificate {
	Handshake		handshake_header;
	u_char			certificates_length[3];
	u_char			certificate_length[3];
	u_char			certificate_data[];
}Certificate;
#pragma pack(pop)

//#pragma pack(push, 1)
//typedef struct signedcertificate {
//	
//}Certificate;
//#pragma pack(pop)



//handshake-serverkeyexchange
#pragma pack(push, 1)
typedef struct server_key_exchange {
	Handshake		handshake_header;
	u_char			curve_type;
	u_short			named_curve;
	u_char			pubkey_length;
	u_char			pubkey[];
}ServerKeyExchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signature_algorithm {
	u_short			signature_algorithm;
	u_short			sign_length;
	u_char			signature[];
}SignatureAlgorithm;
#pragma pack(pop)



#pragma pack(push, 1)
typedef struct certificate_request {

}CertificateRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello_done {

}ServerHelloDone;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_verify {

}CertificateVerify;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_key_exchange {

}ClientKeyExchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct finished {

}Finished;
#pragma pack(pop)
