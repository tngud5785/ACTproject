#include "tls_header.h"
#include "tcp_header.h"


void print_tls(const unsigned char* ether_data) {
	extern packet* pk;
	
	int tls_data = ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	int tls_repeat = pk->header->len - ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	/*if (pk->header->len <= 60 && pk->header->len > 54) {
		tls_data += pk->header->len - ETHER_LENGTH - ntohs(pk->ip->tlen);
		tls_repeat += pk->header->len - ETHER_LENGTH - ntohs(pk->ip->tlen);
	}*/
	printf("\n");
	
	int tls_offset = 0;

	ccs_proto* cp;

	alert_proto* ap;

	tls_header* th;
	th = (tls_header*)(ether_data + tls_data);

	application_proto appli;

	handshake_protocol* hp;
	

	client_hello* ch = (client_hello*)(ether_data + tls_data);

	client_hello_session* chs;
	chs = (client_hello_session*)(ether_data + tls_data);
	chs = (client_hello_session*)malloc(ntohs(chs->ch_session_id_length) * sizeof(char));

	client_hello_cipher* chc;
	chc = (client_hello_cipher*)(ether_data + tls_data);
	chc = (client_hello_cipher*)malloc(ntohs(chc->ch_cipher_suites_length) * sizeof(char));
	

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
			application_proto* appli = (application_proto*)malloc(ntohs(th->tls_length) * sizeof(char));
			appli = (application_proto*)(ether_data + tls_data);
			tls_offset += sizeof(tls_header) + appli->tls_header.tls_length;

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
		else if (th->tls_type == HANDSHAKE) {
			hp = (handshake_protocol*)(ether_data + tls_data);
			tls_offset += sizeof(tls_header) + hp->tls_header.tls_length;

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
				int chs_start = tls_data + sizeof(client_hello);
				chs = (client_hello_session*)(ether_data + chs_start); // pkt_data 처음 위치에 tls까지 위치 + tls의 시작부분부터 random까지 위치
				printf("Session ID Length: %d\n", chs->ch_session_id_length);
				printf("\n");
				printf("Session ID: ");
				for (int i = 0; i < chs->ch_session_id_length; i++) {
					printf("%02x", chs->ch_session_id[i]);
				}
				printf("\n");
				printf("\n");
				int chc_start = chs_start + sizeof(chs->ch_session_id_length) + chs->ch_session_id_length;
				chc = (client_hello_cipher*)(ether_data + chc_start); // pkt_data 처음 위치에 tls까지 위치 + tls의 시작부분부터 session id까지 위치

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
						break;
					}
				}
				printf("\n");
				client_hello_compression* chcom;
				int chcom_start = chc_start + sizeof(chc->ch_cipher_suites_length) + ntohs(chc->ch_cipher_suites_length);
				chcom = (client_hello_compression*)(ether_data + chcom_start);// pkt_data 처음 위치에 tls까지 위치 + tls의 시작부분부터 compression methods까지

				printf("Compression Methods Length: %d\n", chcom->ch_compression_methods_length);
				printf("\n");
				printf("Compression Methods (%d method)\n", chcom->ch_compression_methods_length);
				printf("\n");
				if (chcom->ch_compression_methods == 0) {
					printf("Compression Methods: null (%d)", chcom->ch_compression_methods);
					printf("\n");
				}
				else {
					printf("Compression Methods: Unknown (%d)", chcom->ch_compression_methods);
					printf("\n");
				}
				int Extensions_start = chcom_start + sizeof(chcom->ch_compression_methods_length) + ntohs(chcom->ch_compression_methods_length);
				client_hello_extensions* che;
				che = (client_hello_extensions*)(ether_data + Extensions_start);
				printf("\n");
				printf("Extensions Length: %d\n", ntohs(che->extensions_length));
				printf("\n");

				switch (che->extensions_type) {
				case SERVER_NAME:
					server_name* sn;
					sn = (server_name*)malloc(ntohs(sn->server_name_length));

					printf("Extension: server_name (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: server_name (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Server Name Indication extension\n");
					printf("\n");
					printf("Server Name list length: %d\n", ntohs(sn->server_name_list_length));
					printf("\n");
					printf("Server Name Type: host_name (%d)\n", sn->server_name_type);
					printf("\n");
					printf("Server Name length: %d\n", ntohs(sn->server_name_length));
					printf("\n");
					for (int i = 0; i < ntohs(sn->server_name_length); i++) {
						printf("Server Name: %c\n", sn->server_domain_name[i]);
					}
					printf("\n");
					break;
				case MAX_FRAGMENT_LENGTH:
					printf("Extension: max_fragment_length (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: max_fragment_length (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CLIENT_CERTIFICATE_URL:
					printf("Extension: client_certificate_url (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: client_certificate_url (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TRUSTED_CA_KEYS:
					printf("Extension: trusted_ca_keys (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: trusted_ca_keys (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TRUNCATED_HMAC:
					printf("Extension: truncated_hmac (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: truncated_hmac (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case STATUS_REQUEST:
					printf("Extension: status_request (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: status_request (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case USER_MAPPING:
					break; printf("Extension: user_mapping (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: user_mapping (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CLIENT_AUTHZ:
					printf("Extension: client_authz (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: client_authz (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SERVER_AUTHZ:
					printf("Extension: server_authz (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: server_authz (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CERT_TYPE:
					printf("Extension: cert_type (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: cert_type (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SUPPORTED_GROUPS:
					printf("Extension: supported_groups (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: supported_groups (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case EC_POINT_FORMATS:
					printf("Extension: ec_point_formats (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type:  ec_point_formats (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SRP:
					printf("Extension: srp (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: srp (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SIGNATURE_ALGORITHMS:
					printf("Extension: signature_algorithms (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: signature_algorithms (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case USE_SRTP:
					printf("Extension: use_srtp (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: use_srtp (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case HEARTBEAT:
					printf("Extension: heartbeat (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: heartbeat (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
					printf("Extension: application_layer_protocol_negotiation (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: application_layer_protocol_negotiation (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case STATUS_REQUEST_V2:
					printf("Extension: status_request_v2 (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: status_request_v2 (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SIGNED_CERTIFICATE_TIMESTAMP:
					printf("Extension: signed_certificate_timestamp (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: signed_certificate_timestamp (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CLIENT_CERTIFICATE_TYPE:
					printf("Extension: client_certificate_type (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: client_certificate_type (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SERVER_CERTIFICATE_TYPE:
					printf("Extension: server_certificate_type (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: server_certificate_type (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PADDING:
					printf("Extension: padding (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: padding (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case ENCRYPT_THEN_MAC:
					printf("Extension: encrypt_then_mac (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: encrypt_then_mac (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case EXTENDED_MASTER_SECRET:
					printf("Extension: extended_master_secret (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: extended_master_secret (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TOKEN_BINDING:
					printf("Extension: token_binding (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: token_binding (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CACHED_INFO:
					printf("Extension: cached_info (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: cached_info (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TLS_LTS:
					printf("Extension: tls_lts (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: tls_lts (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case COMPRESS_CERTIFICATE:
					printf("Extension: compress_certificate (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: compress_certificate (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case RECORD_SIZE_LIMIT:
					printf("Extension: record_size_limit (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: record_size_limit (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PWD_PROTECT:
					printf("Extension: pwd_protect (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: pwd_protect (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PWD_CLEAR:
					printf("Extension: pwd_clear (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: pwd_clear (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PASSWORD_SALT:
					printf("Extension: password_salt (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: password_salt (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TICKET_PINNING:
					printf("Extension: ticket_pinning (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: ticket_pinning (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TLS_CERT_WITH_EXTERN_PSK:
					printf("Extension: tls_cert_with_extern_psk (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: tls_cert_with_extern_psk (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case DELEGATED_CREDENTIAL:
					printf("Extension: delegated_credential (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: delegated_credential (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SESSION_TICKET:
					printf("Extension: session_ticket (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: session_ticket (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TLMSP:
					printf("Extension: tlmsp (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: tlmsp (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TLMSP_PROXYING:
					printf("Extension: tlmsp_proxying (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: tlmsp_proxying (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TLMSP_DELEGATE:
					printf("Extension: tlmsp_delegate (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: tlmsp_delegate (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SUPPORTED_EKT_CIPHERS:
					printf("Extension: supported_ekt_ciphers (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: supported_ekt_ciphers (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case RESERVED_40:
					printf("Extension: reserved (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: reserved (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PRE_SHARED_KEY:
					printf("Extension: pre_shared_key (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: pre_shared_key (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case EARLY_DATA:
					printf("Extension: early_data (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: early_data (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SUPPORTED_VERSIONS:
					printf("Extension: supported_versions (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: supported_versions (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case COOKIE:
					printf("Extension: cookie (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: cookie (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case PSK_KEY_EXCHANGE_MODES:
					printf("Extension: psk_key_exchange_modes (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: psk_key_exchange_modes (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case RESERVED_46:
					printf("Extension: reserved (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: reserved (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CERTIFICATE_AUTHORITIES:
					printf("Extension: certificate_authorities (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: certificate_authorities (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case OID_FILTERS:
					printf("Extension: oid_filters (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: oid_filters (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case POST_HANDSHAKE_AUTH:
					printf("Extension: post_handshake_auth (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: post_handshake_auth (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SIGNATURE_ALGORITHMS_CERT:
					printf("Extension: signature_algorithms_cert (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: signature_algorithms_cert (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case KEY_SHARE:
					printf("Extension: key_share (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: key_share (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TRANSPARENCY_INFO:
					printf("Extension: transparency_info (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: transparency_info (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CONNECTION_ID_DEPRECATED:
					printf("Extension: connection_id_deprecated (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: connection_id_deprecated (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case CONNECTION_ID:
					printf("Extension: connection_id (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: connection_id (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case EXTERNAL_ID_HASH:
					printf("Extension: external_id_hash (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: external_id_hash (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case EXTERNAL_SESSION_ID:
					printf("Extension: external_session_id (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: external_session_id (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case TICKET_REQUEST:
					printf("Extension: ticket_request (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: ticket_request (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case DNSSEC_CHAIN:
					printf("Extension: dnssec_chain (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: dnssec_chain (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS:
					printf("Extension: sequence_number_encryption_algortithms (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: sequence_number_encryption_algortithms (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case RRC:
					printf("Extension: rrc (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: rrc (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				case ENCRYPTED_CLIENT_HELLO:
					printf("Extension: encrypted_client_hello (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: encrypted_client_hello (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
				default:
					printf("Extension: unknown (len=%d)\n", ntohs(che->extensions_length));
					printf("\n");
					printf("Type: unknown (%d)\n", ntohs(che->extensions_type));
					printf("\n");
					printf("Length: %d\n", ntohs(che->extensions_length));
					printf("\n");
					break;
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

