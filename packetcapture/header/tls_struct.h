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
	u_short			ch_compression_methods_length;
	u_short			ch_compression_methods[];
}ClientHelloCompression;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello_extensions {
	client_hello	client_hello_header;
	u_short			extensions_length;
}ClientHelloExtensions;
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