#include "tls_header.h"
#include "tcp_header.h"


void print_tls(const unsigned char* ether_data) {
	extern packet* pk;
	
	int tls_data = ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	int tls_repeat = pk->header->len - ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	int tls_offset = 0;

	ccs_proto* cp;

	alert_proto* ap;

	tls_header* th;
	th = (tls_header*)(ether_data + tls_data);

	application_proto* appli = (application_proto*)malloc(ntohs(th->tls_length) * sizeof(char));
	appli = (application_proto*)(ether_data + tls_data);

	handshake_protocol* hp;
	hp = (handshake_protocol*)(ether_data + tls_data);

	client_hello* ch = (client_hello*)(ether_data + tls_data);

	client_hello_session* chs;
	chs = (client_hello_session*)(ether_data + tls_data);
	chs = (client_hello_session*)malloc(ntohs(chs->ch_session_id_length) * sizeof(char));

	client_hello_cipher* chc;
	chc = (client_hello_cipher*)(ether_data + tls_data);
	chc = (client_hello_cipher*)malloc(ntohs(chc->ch_cipher_suites_length) * sizeof(char));
	
	client_hello_compression* chcom;
	chcom = (client_hello_compression*)(ether_data + tls_data);
	chcom = (client_hello_compression*)malloc(ntohs(chcom->ch_compression_methods_length) * sizeof(char));

	print_tcp(pk->tcp, pk->ip);
	//while (tls_repeat != tls_offset) {
		printf("****************** TLSv1.2 Record Layer *****************\n");
		printf("\n");
		if (th->tls_type == CHANGE_CIPHER_SPEC) {
			printf("Content Type: Change Cipher Spec (%d)\n", CHANGE_CIPHER_SPEC);
		}
		else if (th->tls_type == ALERT) {
			printf("Content Type: Alert (%d)\n", ALERT);
		}
		else if (th->tls_type == HANDSHAKE) {
			printf("Content Type: Handshake (%d)\n", HANDSHAKE);
		}
		else if (th->tls_type == APPLICATION_DATA) {
			printf("content Type: Application data (%d)\n", APPLICATION_DATA);
		}

		printf("\n");
		if (ntohs(th->tls_version) == TLS_1_0) {
			printf("Version: TLS 1.0 (0x%04x)\n", ntohs(th->tls_version));
		}
		else if (ntohs(th->tls_version) == TLS_1_1) {
			printf("Version: TLS 1.1 (0x%04x)\n", ntohs(th->tls_version));
		}
		else if (ntohs(th->tls_version) == TLS_1_2) {
			printf("Version: TLS 1.2 (0x%04x)\n", ntohs(th->tls_version));
		}

		printf("\n");
		printf("Length: %d\n", ntohs(th->tls_length));
		printf("\n");
		if (th->tls_type == CHANGE_CIPHER_SPEC) {
			cp = (ccs_proto*)(ether_data + tls_data);
			tls_offset += sizeof(tls_header) + cp->tls_header.tls_length;

			printf("Change Cipher Spec Message\n");
		}
		else if (th->tls_type == ALERT) {
			ap = (alert_proto*)(ether_data + tls_data);
			tls_offset += sizeof(tls_header) + ap->tls_header.tls_length;

			if ((ntohs(ap->tls_header.tls_length) == 2 && ap->alert_level == 1) || (ntohs(ap->tls_header.tls_length) == 2 && ap->alert_level == 2)) {
				if (ap->alert_level == 0x01) {
					printf("Level: Warning (%d)\n", ap->alert_level);
				}
				else if (ap->alert_level == 0x02) {
					printf("level: Fatal (%d)\n", ap->alert_level);
				}
				printf("\n");
				if (ap->alert_descl == CLOSE_NOTIFY) {
					printf("Description: CLOSE_NOTIFY (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNEXPECTED_MESSAGE) {
					printf("Description: UNEXPECTED_MESSAGE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == BAD_RECORD_MAC) {
					printf("Description: BAD_RECORD_MAC (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == DECRYPTION_FAILED) {
					printf("Description: DECRYPTION_FAILED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == RECORD_OVERFLOW) {
					printf("Description: RECORD_OVERFLOW (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == DECOMPRESSION_FAILURE) {
					printf("Description: DECOMPRESSION_FAILURE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == HANDSHAKE_FAILURE) {
					printf("Description: HANDSHAKE_FAILURE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == NO_CERTIFICATE) {
					printf("Description: NO_CERTIFICATE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == BAD_CERTIFICATE) { // 인증서 손상, 서명이 유효하지 않을 때 발생
					printf("Description: BAD_CERTIFICATE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNSUPPORTED_CERTIFICATE) { // 서버나 클라이언트가 제시한 인증서가 지원되지 않는 형식일때 발생
					printf("Description: UNSUPPORTED_CERTIFICATE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_REVOKED) { // 인증서가 취소된 경우 발생
					printf("Description: CERTIFICATE_REVOKED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_EXPIRED) { // 인증서의 유효 기간이 만료된 경우 발생
					printf("Description: CERTIFICATE_EXPIRED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_UNKNOWN) { // 인증서를 처리하는 동안 예상치 못한 오류 발생시
					printf("Description: CERTIFICATE_UNKNOWN (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == ILLEGAL_PARAMETER) {
					printf("Description: ILLEGAL_PARAMETER (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNKNOWN_CA) {
					printf("Description: UNKNOWN_CA (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == ACCESS_DENIED) {
					printf("Description: ACCESS_DENIED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == DECODE_ERROR) {
					printf("Description: DECODE_ERROR (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == DECRYPT_ERROR) { //키 교환 과정에서 발생한 암호 해독 오류와 관련, 키 교환에 사용된 서명 잘못된 경우
					printf("Description: DECRYPT_ERROR (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == EXPORT_RESTRICTION) {
					printf("Description: EXPORT_RESTRICTION (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == PROTOCOL_VERSION) {
					printf("Description: PROTOCOL_VERSION (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == INSUFFICIENT_SECURITY) {
					printf("Description: INSUFFICIENT_SECURITY (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == INTERNAL_ERROR) {
					printf("Description: INTERNAL_ERROR (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == INAPPROPRIATE_FALLBACK) {
					printf("Description: INAPPROPRIATE_FALLBACK (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == USER_CANCELED) {
					printf("Description: USER_CANCELED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == NO_RENEGOTIATION) {
					printf("Description: NO_RENEGOTIATION (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNSUPPORTED_EXTENSION) {
					printf("Description: UNSUPPORTED_EXTENSION (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_UNOBTAINABLE) {
					printf("Description: CERTIFICATE_UNOBTAINABLE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNRECOGNIZED_NAME) {
					printf("Description: UNRECOGNIZED_NAME (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == BAD_CERTIFICATE_STATUS_RESPONSE) {
					printf("Description: BAD_CERTIFICATE_STATUS_RESPONSE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == BAD_CERTIFICATE_HASH_VALUE) {
					printf("Description: BAD_CERTIFICATE_HASH_VALUE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNKNOWN_PSK_IDENTITY) {
					printf("Description: UNKNOWN_PSK_IDENTITY (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_REQUIRED) {
					printf("Description: CERTIFICATE_REQUIRED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == NO_APPLICATION_PROTOCOL) {
					printf("Description: NO_APPLICATION_PROTOCOL (%d)\n", ap->alert_descl);
				}
				else {
					printf("Description: UNKNOWN ALERT (%d)\n", ap->alert_descl);
				}
			}
			else if(ntohs(th->tls_version) == TLS_1_0 || ntohs(th->tls_version) == TLS_1_1 || ntohs(th->tls_version) == TLS_1_2){
				alert_proto_enc* ape;
				ape = (alert_proto_enc*)malloc(ntohs(th->tls_length) * sizeof(char));
				ape = (alert_proto_enc*)(ether_data + tls_data);
				printf("Alert Message: Encrypted Alert\n");
				printf("\n");
			}
		}
		else if (th->tls_type == APPLICATION_DATA) {
			printf("Encrypted Application Data: ");
			for (int i = 0; i < ntohs(appli->tls_header.tls_length); i++) {
				printf("%02x", appli->app_enc_data[i]);
			}
			printf("\n");
			if (appli->app_enc_data[0] == 0x00 && appli->app_enc_data[1] == 0x00 &&
				appli->app_enc_data[2] == 0x00 && appli->app_enc_data[3] == 0x00) {
				printf("[Application Data Protocol: HyperText Transfer Protocol 2]\n");
			}
			else {
				printf("[Application Data Protocol: HyperText Transfer Protocol]\n");
			}
		}
		else if (hp->tls_header.tls_type == HANDSHAKE) {
			if (ntohs(hp->tls_header.tls_length) == 0x0001 && cp->ccs_message == 0x01 && th->tls_type == 0x16) {
				printf("Handshake Protocol: Encrypted Handshake Message\n");
			}
			printf("****************** Handshake Type *****************\n");
			printf("\n");
			if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == HELLO_REQUEST) {
				printf("Handshake Type: Hello Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(ch->handshake_header.handshake_type_leng) >> 24 & 0xFF) == CLIENT_HELLO) {
				chcom = (client_hello_compression*)(ether_data + tls_data);
				printf("Handshake Type: Client Hello (%d)\n", ntohl(ch->handshake_header.handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(ch->handshake_header.handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(ch->handshake_header.handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(ch->handshake_header.handshake_version));
					printf("\n");
				}
				else if (ntohs(ch->handshake_header.handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(ch->handshake_header.handshake_version));
					printf("\n");
				}
				else if (ntohs(ch->handshake_header.handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(ch->handshake_header.handshake_version));
					printf("\n");
				}
				printf("Random: ");
				for (int i = 0; i < 32; i++) {
					printf("%02x", ch->ch_random_bytes[i]);
				}
				printf("\n");
				printf("\n");
				chs = (client_hello_session*)(ether_data + tls_data + sizeof(client_hello));
				printf("Session ID Length: %d\n", chs->ch_session_id_length);
				printf("\n");
				printf("Session ID: ");
				for (int i = 0; i < chs->ch_session_id_length; i++) {
					printf("%02x", chs->ch_session_id[i]);
				}
				printf("\n");
				printf("\n");
				chc = (client_hello_cipher*)(ether_data + tls_data + sizeof(client_hello) + 1 + chs->ch_session_id_length);
				printf("Cipher Suites Length: %d\n", ntohs(chc->ch_cipher_suites_length));
				printf("\n");
				printf("Cipher suites (%d suites)\n", ntohs(chc->ch_cipher_suites_length) / 2);
				printf("\n");
				int result = 0;
				for (int i = 0; i < ntohs(chc->ch_cipher_suites_length) / 2; i++) {
					if (ntohs(chc->ch_cipher_suites[i] & 0x0F0F) == 0x0a0a) {
						printf("Cipher Suite: Reserved (GREASE) (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						continue;
					}
					switch (ntohs(chc->ch_cipher_suites[i])) {
					case TLS_AES_256_GCM_SHA384:
						printf("Cipher Suite: TLS_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_AES_128_GCM_SHA256:
						printf("Cipher Suite: TLS_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_CHACHA20_POLY1305_SHA256:
						printf("Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
						printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
						printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_256_GCM_SHA384:
						printf("Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_128_GCM_SHA256:
						printf("Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_256_CBC_SHA256:
						printf("Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_128_CBC_SHA256:
						printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_256_CBC_SHA:
						printf("Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_RSA_WITH_AES_128_CBC_SHA:
						printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					default:
						printf("Unknown Cipher Suite (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
					}
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO) {
				printf("Handshake Type: Server Hello (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == NEW_SESSION_TICKET) {
				printf("Handshake Type: New Session Ticket (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE) {
				printf("Handshake Type: Certificate (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_KEY_EXCHANGE) {
				printf("Handshake Type: Server Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_REQUEST) {
				printf("Handshake Type: Certificate Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO_DONE) {
				printf("Handshake Type: Server Hello Done (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_VERIFY) {
				printf("Handshake Type: Certificate Verify (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_KEY_EXCHANGE) {
				printf("Handshake Type: Client Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}

			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == FINISHED) {
				printf("Handshake Type: Finished (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(hp->handshake_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}
				else if (ntohs(hp->handshake_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->handshake_version));
					printf("\n");
				}

			}

		}
	//	/*if (tls_data != pk->header->len) {
	//		tls_data += ntohs(th->tls_length);
	//		ap = (alert_proto*)ether_data + tls_data;
	//		cp = (ccs_proto*)ether_data + tls_data;
	//		th = (tls_header*)ether_data + tls_data;
	//		appli = (application_proto*)malloc(ntohs(th->tls_length) * sizeof(char));
	//		appli = (application_proto*)ether_data + tls_data;
	//		hp = (handshake_protocol*)((u_char*)ether_data + tls_data);
	//		ch = (client_hello*)ether_data + tls_data;
	//	}*/
	//	printf("\n");
	//}
}

