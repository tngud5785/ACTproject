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
typedef struct application_proto {
	TLSHeader	tls_header;
	u_char		app_enc_data[];
}ApplicationData;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct handshake_protocol {
	TLSHeader	tls_header;
	u_int		handshake_type_leng;
	u_short		handshake_version;
}TLSHandshake;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct hello_request {

}HelloRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello {
	TLSHandshake	handshake_header;
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









//extension struct
#pragma pack(push, 1)
typedef struct client_hello_extensions {
	u_short			extensions_total_length;
	u_short			extensions_type;
	u_short			extensions_length;
}ClientHelloExtensions;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_name {
	ClientHelloExtensions	client_hello_extensions;
	u_short					server_name_list_length;
	u_char					server_name_type;
	u_short					server_name_length;
	u_char					server_domain_name[];
} ServerName;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct max_fragment_length {
	ClientHelloExtensions	client_hello_extensions;
	u_short					max_frag_leng;
} MaxFragmentLength;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_certificate_url {
	ClientHelloExtensions	client_hello_extensions;
	u_short					client_certificate_url_length;
	u_char					client_cert_url;
} ClientCertificateURL;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct trusted_ca_keys {
	ClientHelloExtensions	client_hello_extensions;
	u_short					trusted_ca_keys_length;
	u_char					trust_ca_keys;
} TrustedCAKeys;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct truncated_hmac {
	ClientHelloExtensions	client_hello_extensions;
	u_short					trun_hmac_length;
	u_char					trun_hmac;
} TruncatedHMAC;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct status_request {
	ClientHelloExtensions	client_hello_extensions;
	u_char					status_type;
	u_short					responder_id_list_length;
	u_short					request_extensions_length;
} StatusRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct user_mapping {
	ClientHelloExtensions	client_hello_extensions;
	u_short					user_map_length;
	u_char					user_map;
} UserMapping;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_authz {
	ClientHelloExtensions	client_hello_extensions;
	u_short					cli_authz_length;
	u_char					cli_authz;
} ClientAuthz;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_authz {
	ClientHelloExtensions	client_hello_extensions;
	u_short					ser_authz_length;
	u_char					ser_authz;
} ServerAuthz;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cert_type {
	ClientHelloExtensions	client_hello_extensions;
	u_short					ce_type_length;
	u_char					ce_type;
} CertType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_groups {
	ClientHelloExtensions	client_hello_extensions;
	u_short					sup_groups_list_length;
	u_short					sup_groups[];
} SupportedGroups;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ec_point_formats {
	ClientHelloExtensions	client_hello_extensions;
	u_char					ec_point_formats_length;
	u_char					ec_point_format;
} ECPointFormats;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct srp{
	ClientHelloExtensions	client_hello_extensions;
	u_short					srp_length;
	u_char					_srp;
} ExtentsionSRP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signature_algorithms {
	ClientHelloExtensions	client_hello_extensions;
	u_short					signature_hash_algorithms_length;
	u_short					signature_hash_algorithms[];
} SignatureAlgorithms;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct use_srtp {
	ClientHelloExtensions	client_hello_extensions;
	u_short					use_srtp_length;
	u_char					_use_srtp;
} UseSrtp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct heartbeat {
	ClientHelloExtensions	client_hello_extensions;
	u_short					heartbeat_length;
	u_char					_heartbeat;
} Heartbeat;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct application_layer_protocol_negotiation {
	ClientHelloExtensions	client_hello_extensions;
	u_short					alpn_extension_length;
	u_char					alpn_string_length;
	u_char					alpn_next_protocol[]; // ascii
} Alpn;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct status_request_v2 {
	ClientHelloExtensions	client_hello_extensions;
	u_short					status_request_v2_length;
	u_char					_status_request_v2;
} StatusRequestV2;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signed_certificate_timestamp {
	ClientHelloExtensions	client_hello_extensions;
} SignedCertificateTimestamp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_certificate_type {
	ClientHelloExtensions	client_hello_extensions;
	u_short					client_certificate_type_length;
	u_char					_client_certificate_type;
} ClientCertificateType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_certificate_type {
	ClientHelloExtensions	client_hello_extensions;
	u_short					server_certificate_type_length;
	u_char					_server_certificate_type;
} ServerCertificateType;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct padding {
	ClientHelloExtensions	client_hello_extensions;
	u_char					padding_data[];
} Padding;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypt_then_mac {
	ClientHelloExtensions	client_hello_extensions;
} EncryptThenMac;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct extended_master_secret {
	ClientHelloExtensions	client_hello_extensions;
} ExtendedMasterSecret;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct token_binding {
	ClientHelloExtensions	client_hello_extensions;
} TokenBinding;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cached_info {
	ClientHelloExtensions	client_hello_extensions;
} CachedInfo;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tls_lts {
	ClientHelloExtensions	client_hello_extensions;
} TlsLts;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct compress_certificate {
	ClientHelloExtensions	client_hello_extensions;
	u_char					algorithms_length;
	u_short					algorithm;
} CompressCertificate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct record_size_limit {
	ClientHelloExtensions	client_hello_extensions;
} RecordSizeLimit;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct pwd_protect {
	ClientHelloExtensions	client_hello_extensions;
} PwdProtect;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct pwd_clear {
	ClientHelloExtensions	client_hello_extensions;
} PwdClear;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct password_salt {
	ClientHelloExtensions	client_hello_extensions;
} PasswordSalt;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ticket_pinning {
	ClientHelloExtensions	client_hello_extensions;
} TicketPinning;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tls_cert_with_extern_psk {
	ClientHelloExtensions	client_hello_extensions;
} TlsCertWithExternPsk;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct delegated_credential {
	ClientHelloExtensions	client_hello_extensions;
} DelegatedCredential;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct session_ticket {
	ClientHelloExtensions	client_hello_extensions;
	u_char					session_ticket_data[];
} SessionTicket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp {
	ClientHelloExtensions	client_hello_extensions;
} Tlsmp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp_proxying {
	ClientHelloExtensions	client_hello_extensions;
} TlmspProxying;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tlmsp_delegate {
	ClientHelloExtensions	client_hello_extensions;
} TlmspDelegate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_ekt_ciphers {
	ClientHelloExtensions	client_hello_extensions;
} SupportedEktCiphers;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct reserved_40 {
	ClientHelloExtensions	client_hello_extensions;
} Reserved_40;
#pragma pack(pop)

typedef struct pre_shared_key{
	ClientHelloExtensions	client_hello_extensions;
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
	ClientHelloExtensions	client_hello_extensions;
} EarlyData;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct supported_versions {
	ClientHelloExtensions	client_hello_extensions;
	u_short					supported_versions_length;
	u_short					supported_version[];
} SupportedVersions;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cookie {
	ClientHelloExtensions	client_hello_extensions;
	u_short					cookie_length;
	u_char					cookie_data[];
} Cookie;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct psk_key_exchange_modes {
	ClientHelloExtensions	client_hello_extensions;
} PskKeyExchangeModes;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct reserved_46 {
	ClientHelloExtensions	client_hello_extensions;
} Reserved_46;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_authorities {
	ClientHelloExtensions	client_hello_extensions;
} CertificateAuthorities;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct oid_filters {
	ClientHelloExtensions	client_hello_extensions;
} OidFilters;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct post_handshake_auth {
	ClientHelloExtensions	client_hello_extensions;
} PostHandshakeAuth;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signature_algorithms_cert {
	ClientHelloExtensions	client_hello_extensions;
} SignatureAlgorithmsCert;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct key_share {
	ClientHelloExtensions	client_hello_extensions;
	u_short					client_key_share_length;
} KeyShare;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct key_share_entry {
	key_share		key_shard;
	u_short			key_share_group;
	u_short			key_exchange_length;
	u_char			key_exchange[];
} KeyShareEntry;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct transparency_info {
	ClientHelloExtensions	client_hello_extensions;
} TransparencyInfo;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct connection_id_deprecated {
	ClientHelloExtensions	client_hello_extensions;
} ConnectionIdDeprecated;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct connection_id {
	ClientHelloExtensions	client_hello_extensions;
} ConnectionId;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct external_id_hash {
	ClientHelloExtensions	client_hello_extensions;
} ExternalIdHash;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct external_session_id {
	ClientHelloExtensions	client_hello_extensions;
} ExternalSessionId;
#pragma pack(pop)

//#pragma pack(push, 1)
//typedef struct quic_transport_parameters {
//	ClientHelloExtensions	client_hello_extensions;
//} QuicTransportParameters;
//#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ticket_request {
	ClientHelloExtensions	client_hello_extensions;
} TicketRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dnssec_chain {
	ClientHelloExtensions	client_hello_extensions;
} DnssecChain;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct sequence_number_encryption_algortithms {
	ClientHelloExtensions	client_hello_extensions;
} SequenceNumberEncryptionAlgortithms;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct rrc {
	ClientHelloExtensions	client_hello_extensions;
} Rrc;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct unassigned {
	ClientHelloExtensions	client_hello_extensions;
} Unassigned;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct encrypted_client_hello {
	ClientHelloExtensions	client_hello_extensions;
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
typedef struct server_hello {

}ServerHello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct new_session_ticket {

}NewSessionTicket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate {

}Certificate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_key_exchange {

}ServerKeyExchange;
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