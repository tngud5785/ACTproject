#include "tls_header.h"
#include "tcp_header.h"


void print_tls(const unsigned char* pkt_data) {
	extern packet* pk;
	extern signing_data* sd;
	u_int extension_offset = 0;
	int tls_data = ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	int tcp_payload_length = ntohs(pk->ip->tlen) - (pk->ip->ip_leng * 4) - ((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4;
	
	/*if (pk->header->len <= 60 && pk->header->len > 54) {
		tls_data += pk->header->len - ETHER_LENGTH - ntohs(pk->ip->tlen);
		tls_repeat += pk->header->len - ETHER_LENGTH - ntohs(pk->ip->tlen);
	}*/

	int tls_offset = 0;

	ccs_proto* cp;
	cp = (ccs_proto*)(pkt_data + tls_data + sizeof(tls_header));
	alert_proto* ap;

	tls_header* th;
	th = (tls_header*)(pkt_data + tls_data);

	application_proto* appli;

	handshake_proto* hp;
	hp = (handshake_proto*)(pkt_data + tls_data);

	extensions_type_length* etl;

	server_hello* sh;
	sh = (server_hello*)(pkt_data + tls_data);

	//client extension ó��
	int chs_start = tls_data + sizeof(client_hello);

	client_hello_session* chs;
	chs = (client_hello_session*)(pkt_data + chs_start);

	int chc_start = chs_start + sizeof(chs->ch_session_id_length) + chs->ch_session_id_length;

	client_hello_cipher* chc;
	chc = (client_hello_cipher*)(pkt_data + chc_start);

	int chcom_start = chc_start + sizeof(chc->ch_cipher_suites_length) + ntohs(chc->ch_cipher_suites_length);

	client_hello_compression* chcom;
	chcom = (client_hello_compression*)(pkt_data + chcom_start);



	int Extensions_start = chcom_start + sizeof(chcom->ch_compression_methods_length) + chcom->ch_compression_methods_length;

	client_hello_extensions* che;
	che = (client_hello_extensions*)(pkt_data + Extensions_start);

	Extensions_start = chcom_start + sizeof(chcom->ch_compression_methods_length) + chcom->ch_compression_methods_length + sizeof(che->extensions_total_length);

	print_tcp(pk->tcp, pk->ip, pkt_data);
	while (tcp_payload_length != tls_offset) {
		int hand_offset = 0;

		th = (tls_header*)(pkt_data + tls_data + tls_offset);
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
			cp = (ccs_proto*)(pkt_data + tls_data + tls_offset);

			printf("Change Cipher Spec Message\n");

			tls_offset += sizeof(tls_header) + cp->tls_header.tls_length;
		}
		else if (th->tls_type == ALERT) {
			ap = (alert_proto*)(pkt_data + tls_data + tls_offset);

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
				else if (ap->alert_descl == BAD_CERTIFICATE) { // ������ �ջ�, ������ ��ȿ���� ���� �� �߻�
					printf("Description: BAD_CERTIFICATE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == UNSUPPORTED_CERTIFICATE) { // ������ Ŭ���̾�Ʈ�� ������ �������� �������� �ʴ� �����϶� �߻�
					printf("Description: UNSUPPORTED_CERTIFICATE (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_REVOKED) { // �������� ��ҵ� ��� �߻�
					printf("Description: CERTIFICATE_REVOKED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_EXPIRED) { // �������� ��ȿ �Ⱓ�� ����� ��� �߻�
					printf("Description: CERTIFICATE_EXPIRED (%d)\n", ap->alert_descl);
				}
				else if (ap->alert_descl == CERTIFICATE_UNKNOWN) { // �������� ó���ϴ� ���� ����ġ ���� ���� �߻���
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
				else if (ap->alert_descl == DECRYPT_ERROR) { //Ű ��ȯ �������� �߻��� ��ȣ �ص� ������ ����, Ű ��ȯ�� ���� ���� �߸��� ���
					printf("Description: DECRYPT_ERROR (%d)\n", ap->alert_descl);
					printf("\n");
					printf("*********************************decrypt data*********************************\n");
					printf("\n");
					printf("client random: %s\n", sd->ch_random);
					printf("\n");
					printf("server random: %s\n", sd->sh_random);
					printf("\n");
					printf("curve type: %d\n", sd->ske->curve_type);
					printf("\n");
					printf("name curve: 0x%04x\n", sd->ske->named_curve);
					printf("\n");
					printf("pubkey_length: %d\n", sd->ske->pubkey_length);
					printf("\n");
					printf("pubkey: %s\n", sd->ske_pubkey);
					printf("\n");
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
			else if (ntohs(th->tls_version) == TLS_1_0 || ntohs(th->tls_version) == TLS_1_1 || ntohs(th->tls_version) == TLS_1_2) {
				alert_proto_enc* ape;
				ape = (alert_proto_enc*)malloc(sizeof(TLSHeader) + ntohs(th->tls_length) * sizeof(char));
				ape = (alert_proto_enc*)(pkt_data + tls_data);
				printf("Alert Message: Encrypted Alert\n");
				printf("\n");

				tls_offset += sizeof(tls_header) + ap->tls_header.tls_length;
			}
		}
		else if (th->tls_type == APPLICATION_DATA) {
			application_proto* appli = (application_proto*)malloc(sizeof(TLSHeader) + ntohs(th->tls_length) * sizeof(char));
			appli = (application_proto*)(pkt_data + tls_data + tls_offset);

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

			tls_offset += sizeof(tls_header) + appli->tls_header.tls_length;
		}
		else if (th->tls_type == HANDSHAKE) {
			char combined_data[65]; 
			memset(combined_data, 0, sizeof(combined_data));
			
			if (ntohs(hp->tls_header.tls_length) == 0x0001 && cp->ccs_message == 0x01 && th->tls_type == 0x16) {
				printf("Handshake Protocol: Encrypted Handshake Message\n");
			}
			//while (tcp_payload_length != hand_offset) {
			hp = (handshake_proto*)(pkt_data + tls_data + tls_offset);
			printf("****************** Handshake Type *****************\n");
			printf("\n");
			if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == HELLO_REQUEST_RESERVED) {
				printf("Handshake Type: Hello Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				printf("\n");

				hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
				tls_offset += sizeof(tls_header) + hand_offset;
			}
			else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_HELLO) {
				client_hello* ch = (client_hello*)(pkt_data + tls_data + tls_offset);

				char ch_combined_data[65];
				memset(ch_combined_data, 0, sizeof(ch_combined_data));
				printf("Handshake Type: Client Hello (%d)\n", ntohl(ch->handshake_header.handshake_type_leng) >> 24 & 0xFF);
				printf("\n");
				printf("Length: %d\n", ntohl(ch->handshake_header.handshake_type_leng) & 0xFFFFFF);
				printf("\n");
				if (ntohs(ch->client_hello_version) == TLS_1_0) {
					printf("Version: TLS 1.0 (0x%04x)\n", ntohs(ch->client_hello_version));
					printf("\n");
				}
				else if (ntohs(ch->client_hello_version) == TLS_1_1) {
					printf("Version: TLS 1.1 (0x%04x)\n", ntohs(ch->client_hello_version));
					printf("\n");
				}
				else if (ntohs(ch->client_hello_version) == TLS_1_2) {
					printf("Version: TLS 1.2 (0x%04x)\n", ntohs(ch->client_hello_version));
					printf("\n");
				}
				printf("Random: ");
				for (int i = 0; i < 32; i++) {
					printf("%02x", ch->ch_random_bytes[i]);
				}
				printf("\n");
				printf("\n");
				for (int i = 0; i < 32; i++) {
					sprintf(ch_combined_data + (i * 2), "%02x", ch->ch_random_bytes[i]);
				}
				
				sd->ch_random = (const unsigned char*)ch_combined_data;
				chs = (client_hello_session*)malloc(sizeof(client_hello_session) + chs->ch_session_id_length * sizeof(char));
				chs = (client_hello_session*)(pkt_data + chs_start); // pkt_data ó�� ��ġ�� tls���� ��ġ + tls�� ���ۺκк��� random���� ��ġ			
				printf("Session ID Length: %d\n", chs->ch_session_id_length);
				printf("\n");
				printf("Session ID: ");
				for (int i = 0; i < chs->ch_session_id_length; i++) {
					printf("%02x", chs->ch_session_id[i]);
				}
				printf("\n");
				printf("\n");

				chc = (client_hello_cipher*)malloc(sizeof(client_hello_cipher) + ntohs(chc->ch_cipher_suites_length) * sizeof(char));
				chc = (client_hello_cipher*)(pkt_data + chc_start);
				printf("Cipher Suites Length: %d\n", ntohs(chc->ch_cipher_suites_length));
				printf("\n");
				printf("Cipher suites (%d suites)\n", ntohs(chc->ch_cipher_suites_length) / 2);
				printf("\n");

				for (int i = 0; i < ntohs(chc->ch_cipher_suites_length) / 2; i++) {
					if ((ntohs(chc->ch_cipher_suites[i]) & 0x0F0F) == 0x0a0a) {
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
					case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
						printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
						printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					default:
						printf("Unknown Cipher Suite (0x%04x)\n", ntohs(chc->ch_cipher_suites[i]));
						break;
					}
				}
				printf("\n");

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

				printf("\n");
				printf("Extensions Length: %d\n", ntohs(che->extensions_total_length));
				printf("\n");

				while (ntohs(che->extensions_total_length) != extension_offset) {
					etl = (extensions_type_length*)(pkt_data + Extensions_start + extension_offset);
					switch (ntohs(etl->extensions_type)) {
					case SERVER_NAME:
						server_name* sn;
						sn = (server_name*)malloc(sizeof(client_hello_extensions) + ntohs(etl->extensions_length) * sizeof(char));
						sn = (server_name*)(pkt_data + Extensions_start + extension_offset);

						printf("Extension: server_name (len=%d) name=", ntohs(etl->extensions_length));
						for (int i = 0; i < ntohs(sn->server_name_length); i++) {
							printf("%c", sn->server_domain_name[i]);
						}
						printf("\n");
						printf("\n");
						printf("Type: server_name (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Server Name Indication extension\n");
						printf("\n");
						printf("Server Name list length: %d\n", ntohs(sn->server_name_list_length));
						printf("\n");
						printf("Server Name Type: host_name (%d)\n", sn->server_name_type);
						printf("\n");
						printf("Server Name length: %d\n", ntohs(sn->server_name_length));
						printf("\n");
						printf("Server Name: ");
						for (int i = 0; i < ntohs(sn->server_name_length); i++) {
							printf("%c", sn->server_domain_name[i]);
						}
						printf("\n");
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case MAX_FRAGMENT_LENGTH:
						max_fragment_length* mfl;
						mfl = (max_fragment_length*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: max_fragment_length (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: max_fragment_length (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CLIENT_CERTIFICATE_URL:
						client_certificate_url* ccu;
						ccu = (client_certificate_url*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: client_certificate_url (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: client_certificate_url (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TRUSTED_CA_KEYS:
						trusted_ca_keys* tck;
						tck = (trusted_ca_keys*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: trusted_ca_keys (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: trusted_ca_keys (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TRUNCATED_HMAC:
						truncated_hmac* thmac;
						thmac = (truncated_hmac*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: truncated_hmac (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: truncated_hmac (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case STATUS_REQUEST:
						status_request* sr;
						sr = (status_request*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: status_request (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: status_request (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						if (sr->status_type == 1) {
							printf("Certificate Status Type: OCSP (%d)\n", sr->status_type);
						}
						else {
							printf("Certificate Status Type : Unknown (%d)\n", sr->status_type);
						}
						printf("\n");
						printf("Responder ID list Length: %d\n", ntohs(sr->responder_id_list_length));
						printf("\n");
						printf("Request Extensions Length: %d\n", ntohs(sr->request_extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case USER_MAPPING:
						user_mapping* um;
						um = (user_mapping*)(pkt_data + Extensions_start + extension_offset);
						break; printf("Extension: user_mapping (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: user_mapping (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CLIENT_AUTHZ:
						client_authz* ca;
						ca = (client_authz*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: client_authz (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: client_authz (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SERVER_AUTHZ:
						server_authz* saz;
						saz = (server_authz*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: server_authz (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: server_authz (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CERT_TYPE:
						cert_type* ct;
						ct = (cert_type*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: cert_type (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: cert_type (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SUPPORTED_GROUPS:
						supported_groups* sg;
						sg = (supported_groups*)malloc(sizeof(extensions_type_length) + ntohs(etl->extensions_length) - sizeof(etl->extensions_length));
						sg = (supported_groups*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: supported_groups (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: supported_groups (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Supported Groups List Length: %d\n", ntohs(sg->sup_groups_list_length));
						printf("\n");
						printf("Supported Groups (%d groups)\n", ntohs(sg->sup_groups_list_length) / 2);
						printf("\n");
						for (int i = 0; i < ntohs(sg->sup_groups_list_length) / 2; i++) {
							if (ntohs(sg->sup_groups[i]) >= 0x0001 && ntohs(sg->sup_groups[i]) <= 0x0016) {
								printf("Supported Group: deprecated (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x0017) {
								printf("Supported Group: secp256r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x0018) {
								printf("Supported Group: secp384r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x0019) {
								printf("Supported Group: secp521r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x001D) {
								printf("Supported Group: ffdhe2048 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x001E) {
								printf("Supported Group: ffdhe3072 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x18FF) {
								printf("Supported Group: ffdhe4096 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) >= 0xFE00 && ntohs(sg->sup_groups[i]) <= 0xFEFF) {
								printf("Supported Group: ffdhe6144 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) >= 0xFF01 && ntohs(sg->sup_groups[i]) <= 0xFF02) {
								printf("Supported Group: ffdhe8192 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x001D) {
								printf("Supported Group: x25519 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x001E) {
								printf("Supported Group: x448 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) == 0x6399) {
								printf("Supported Group: X25519Kyber768Draft00 (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if ((ntohs(sg->sup_groups[i]) >= 0xFE00 && ntohs(sg->sup_groups[i]) <= 0xFEFF) || (ntohs(sg->sup_groups[i] & 0x0F0F) == 0x0a0a)) {
								printf("Supported Group: Reserved (GREASE) (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else if (ntohs(sg->sup_groups[i]) >= 0xFF01 && ntohs(sg->sup_groups[i]) <= 0xFF02) {
								printf("Supported Group: deprecated (0x%04x)\n", ntohs(sg->sup_groups[i]));
							}
							else {
								printf("Supported Group: Unknown (0x%04x)\n", ntohs(ntohs(sg->sup_groups[i])));
							}
						}
						printf("\n");
						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case EC_POINT_FORMATS:
						ec_point_formats* epf;
						epf = (ec_point_formats*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: ec_point_formats (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type:  ec_point_formats (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("EC point format Length: %d\n", epf->ec_point_formats_length);
						printf("\n");
						printf("Elliptic curves point formats (%d)\n", epf->ec_point_formats_length);
						printf("\n");
						for (int i = 0; i < epf->ec_point_formats_length; i++) {
							if (epf->ec_point_format[i] == UNCOMPRESSED) {
								printf("EC Point format: uncompressed (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
							else if (epf->ec_point_format[i] == ANSIX962_COMPRESSED_PRIME) {
								printf("EC Point format: ansiX962_compressed_prime (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
							else if (epf->ec_point_format[i] == ANSIX962_COMPRESSED_CHAR2) {
								printf("EC Point format: ansiX962_compressed_char2 (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
							else if (epf->ec_point_format[i] >= 3 && epf->ec_point_format[i] <= 247) {
								printf("EC Point format: unassigned (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
							else if (epf->ec_point_format[i] >= 248 && epf->ec_point_format[i] <= 255) {
								printf("EC Point format: reserved_for_private_use (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
							else {
								printf("EC Point format: Unknown (%d)\n", epf->ec_point_format[i]);
								printf("\n");
							}
						}
						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SRP:
						srp* _srp;
						_srp = (srp*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: srp (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: srp (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SIGNATURE_ALGORITHMS:
						signature_algorithms* sa;
						sa = (signature_algorithms*)(pkt_data + Extensions_start + extension_offset);
						sa = (signature_algorithms*)malloc(ntohs(sa->signature_hash_algorithms_length));
						sa = (signature_algorithms*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: signature_algorithms (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: signature_algorithms (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Signature Hash Algorithms Length: %d\n", ntohs(sa->signature_hash_algorithms_length));
						printf("\n");
						printf("Signature Hash Algorithms (%d algorithm)\n", ntohs(sa->signature_hash_algorithms_length) / 2);
						printf("\n");
						for (int i = 0; i < ntohs(sa->signature_hash_algorithms_length) / 2; i++){
							if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha256) {
								printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp256r1_sha256) {
								printf("Signature Algorithm: ecdsa_secp256r1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha384) {
								printf("Signature Algorithm: rsa_pkcs1_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp384r1_sha384) {
								printf("Signature Algorithm: ecdsa_secp384r1_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha512) {
								printf("Signature Algorithm: rsa_pkcs1_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp521r1_sha512) {
								printf("Signature Algorithm: ecdsa_secp521r1_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha256) {
								printf("Signature Algorithm: rsa_pss_rsae_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha384) {
								printf("Signature Algorithm: rsa_pss_rsae_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha512) {
								printf("Signature Algorithm: rsa_pss_rsae_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ed25519) {
								printf("Signature Algorithm: ed25519 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: reserved (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ed448) {
								printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: Intrinsic (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha256) {
								printf("Signature Algorithm: rsa_pss_pss_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha384) {
								printf("Signature Algorithm: rsa_pss_pss_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha512) {
								printf("Signature Algorithm: rsa_pss_pss_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha1) {
								printf("Signature Algorithm: rsa_pkcs1_sha1 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_sha1) {
								printf("Signature Algorithm: ecdsa_sha1 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
							else {
								printf("Signature Algorithm: unknown (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
								printf("\n");
								printf("Signature Hash Algorithm Hash: unknown (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
								printf("\n");
								printf("Signature Algorithm: unknown (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
								printf("\n");
							}
						}
						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case USE_SRTP:
						use_srtp* us;
						us = (use_srtp*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: use_srtp (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: use_srtp (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case HEARTBEAT:
						heartbeat* hb;
						hb = (heartbeat*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: heartbeat (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: heartbeat (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
						application_layer_protocol_negotiation* alpn;
						alpn = (application_layer_protocol_negotiation*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: application_layer_protocol_negotiation (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: application_layer_protocol_negotiation (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case STATUS_REQUEST_V2:
						status_request_v2* srv;
						srv = (status_request_v2*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: status_request_v2 (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: status_request_v2 (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SIGNED_CERTIFICATE_TIMESTAMP:
						signed_certificate_timestamp* sct;
						sct = (signed_certificate_timestamp*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: signed_certificate_timestamp (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: signed_certificate_timestamp (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CLIENT_CERTIFICATE_TYPE:
						client_certificate_type* cct;
						cct = (client_certificate_type*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: client_certificate_type (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: client_certificate_type (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SERVER_CERTIFICATE_TYPE:
						server_certificate_type* setype;
						setype = (server_certificate_type*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: server_certificate_type (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: server_certificate_type (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PADDING:
						padding* pad;
						pad = (padding*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: padding (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: padding (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case ENCRYPT_THEN_MAC:
						encrypt_then_mac* etm;
						etm = (encrypt_then_mac*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: encrypt_then_mac (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: encrypt_then_mac (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case EXTENDED_MASTER_SECRET:
						extended_master_secret* ems;
						ems = (extended_master_secret*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: extended_master_secret (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: extended_master_secret (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TOKEN_BINDING:
						token_binding* tb;
						tb = (token_binding*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: token_binding (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: token_binding (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CACHED_INFO:
						cached_info* ci;
						ci = (cached_info*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: caetld_info (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: caetld_info (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TLS_LTS:
						tls_lts* tl;
						tl = (tls_lts*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: tls_lts (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: tls_lts (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case COMPRESS_CERTIFICATE:
						compress_certificate* cc;
						cc = (compress_certificate*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: compress_certificate (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: compress_certificate (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case RECORD_SIZE_LIMIT:
						record_size_limit* rsl;
						rsl = (record_size_limit*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: record_size_limit (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: record_size_limit (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PWD_PROTECT:
						pwd_protect* pp;
						pp = (pwd_protect*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: pwd_protect (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: pwd_protect (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PWD_CLEAR:
						pwd_clear* pc;
						pc = (pwd_clear*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: pwd_clear (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: pwd_clear (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PASSWORD_SALT:
						password_salt* ps;
						ps = (password_salt*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: password_salt (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: password_salt (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TICKET_PINNING:
						ticket_pinning* tp;
						tp = (ticket_pinning*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: ticket_pinning (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: ticket_pinning (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TLS_CERT_WITH_EXTERN_PSK:
						tls_cert_with_extern_psk* tcwep;
						tcwep = (tls_cert_with_extern_psk*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: tls_cert_with_extern_psk (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: tls_cert_with_extern_psk (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case DELEGATED_CREDENTIAL:
						delegated_credential* dc;
						dc = (delegated_credential*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: delegated_credential (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: delegated_credential (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SESSION_TICKET:
						session_ticket* st;
						st = (session_ticket*)(pkt_data + Extensions_start + extension_offset);
						st = (session_ticket*)malloc(ntohs(etl->extensions_length));
						st = (session_ticket*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: session_ticket (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: session_ticket (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						if (etl->extensions_length == 0) {
							printf("Session Ticket: <MISSING>\n");
						}
						else {
							printf("Session Ticket: ");
							for (int i = 0; i < ntohs(etl->extensions_length); i++) {
								printf("%x", st->session_ticket_data[i]);
							}
							printf("\n");
						}
						printf("\n");
						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TLMSP:
						tlmsp* tlm;
						tlm = (tlmsp*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: tlmsp (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: tlmsp (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TLMSP_PROXYING:
						tlmsp_proxying* tlmproxy;
						tlmproxy = (tlmsp_proxying*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: tlmsp_proxying (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: tlmsp_proxying (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TLMSP_DELEGATE:
						tlmsp_delegate* tlmspdel;
						tlmspdel = (tlmsp_delegate*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: tlmsp_delegate (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: tlmsp_delegate (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SUPPORTED_EKT_CIPHERS:
						supported_ekt_ciphers* sec;
						sec = (supported_ekt_ciphers*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: supported_ekt_ciphers (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: supported_ekt_ciphers (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case RESERVED_40:
						reserved_40* re_40;
						re_40 = (reserved_40*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: reserved (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: reserved (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PRE_SHARED_KEY:
						pre_shared_key* psk;
						psk = (pre_shared_key*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: pre_shared_key (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: pre_shared_key (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case EARLY_DATA:
						early_data* ed;
						ed = (early_data*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: early_data (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: early_data (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SUPPORTED_VERSIONS:
						supported_versions* sv;
						sv = (supported_versions*)(pkt_data + Extensions_start + extension_offset);
						sv = (supported_versions*)malloc(sv->supported_versions_length);
						sv = (supported_versions*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: supported_versions (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: supported_versions (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Suppoted Versions length: %d\n", sv->supported_versions_length);
						printf("\n");
						for (int i = 0; i < sv->supported_versions_length / 2; i++) {
							if (ntohs(sv->supported_version[i]) == SSL_3_0) {
								printf("Supported Version: SSL 3.0 (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
							else if (ntohs(sv->supported_version[i]) == TLS_1_0) {
								printf("Supported Version: TLS 1.0 (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
							else if (ntohs(sv->supported_version[i]) == TLS_1_1) {
								printf("Supported Version: TLS 1.1 (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
							else if (ntohs(sv->supported_version[i]) == TLS_1_2) {
								printf("Supported Version: TLS 1.2 (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
							else if (ntohs(sv->supported_version[i]) == TLS_1_3) {
								printf("Supported Version: TLS 1.3 (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
							else {
								printf("Supported Version: Unknown (0x%04x)\n", ntohs(sv->supported_version[i]));
								printf("\n");
							}
						}

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case COOKIE:
						cookie* ck;
						ck = (cookie*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: cookie (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: cookie (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case PSK_KEY_EXCHANGE_MODES:
						psk_key_exchange_modes* pkem;
						pkem = (psk_key_exchange_modes*)(pkt_data + Extensions_start + extension_offset);
						pkem = (psk_key_exchange_modes*)malloc(pkem->psk_key_exchange_modes_length);
						pkem = (psk_key_exchange_modes*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: psk_key_exchange_modes (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: psk_key_exchange_modes (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("PSK key Exchange Modes Length: %d\n", pkem->psk_key_exchange_modes_length);
						printf("\n");
						for (int i = 0; i < pkem->psk_key_exchange_modes_length; i++) {
							if (pkem->psk_key_exchange_mode[i] == PSK_KE) {
								printf("PSK key Exchange Mode: PSK key establishment (psk_ke) (%d)\n", pkem->psk_key_exchange_mode[i]);
								printf("\n");
							}
							else if (pkem->psk_key_exchange_mode[i] == PSK_DHE_KE) {
								printf("PSK key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (%d)\n", pkem->psk_key_exchange_mode[i]);
								printf("\n");
							}
							else if (pkem->psk_key_exchange_mode[i] >= UNASSIGNED_2 && pkem->psk_key_exchange_mode[i] <= UNASSIGNED_253) {
								printf("PSK key Exchange Mode: Unassigned (%d)\n", pkem->psk_key_exchange_mode[i]);
								printf("\n");
							}
							else if (pkem->psk_key_exchange_mode[i] >= RESERVED_FOR_PRIVATE_USE_254 && pkem->psk_key_exchange_mode[i] <= RESERVED_FOR_PRIVATE_USE_255) {
								printf("PSK key Exchange Mode: Reserved For Private Use (%d)\n", pkem->psk_key_exchange_mode[i]);
								printf("\n");
							}
							else {
								printf("PSK key Exchange Mode: Unknown (%d)\n", pkem->psk_key_exchange_mode[i]);
								printf("\n");
							}
						}

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case RESERVED_46:
						reserved_46* re_46;
						re_46 = (reserved_46*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: reserved (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: reserved (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CERTIFICATE_AUTHORITIES:
						certificate_authorities* certauth;
						certauth = (certificate_authorities*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: certificate_authorities (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: certificate_authorities (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case OID_FILTERS:
						oid_filters* of;
						of = (oid_filters*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: oid_filters (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: oid_filters (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case POST_HANDSHAKE_AUTH:
						post_handshake_auth* pha;
						pha = (post_handshake_auth*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: post_handshake_auth (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: post_handshake_auth (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SIGNATURE_ALGORITHMS_CERT:
						signature_algorithms_cert* sac;
						sac = (signature_algorithms_cert*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: signature_algorithms_cert (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: signature_algorithms_cert (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case KEY_SHARE:
						key_share* ks;
						ks = (key_share*)(pkt_data + Extensions_start + extension_offset);
						ks = (key_share*)malloc(ntohs(ks->key_exchange_length));
						ks = (key_share*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: key_share (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: key_share (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Key Share extension\n");
						printf("\n");
						printf("Client Key Share Length: %d\n", ntohs(ks->Client_key_share_length));
						printf("\n");
						if (ntohs(ks->group) == CURVE_SECP256R1) {
							printf("Key Share Entry: Group: secp256r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: secp256r1 (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}
						else if (ntohs(ks->group) == CURVE_SECP384R1) {
							printf("Key Share Entry: Group: secp384r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: secp384r1 (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}
						else if (ntohs(ks->group) == CURVE_SECP521R1) {
							printf("Key Share Entry: Group: secp521r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: secp521r1 (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}
						else if (ntohs(ks->group) == CURVE_X25519) {
							printf("Key Share Entry: Group: x25519, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: x25519 (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%01x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}
						else if (ntohs(ks->group) == CURVE_X448) {
							printf("Key Share Entry: Group: secp384r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: x25519 (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}
						else {
							printf("Key Share Entry: Group: Unknown, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("Group: Unknown (%d)\n", ntohs(ks->group));
							printf("\n");
							printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
							printf("\n");
							printf("key Exchange: ");
							for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
								printf("%x", ks->key_exchange[i]);
							}
							printf("\n");
							printf("\n");
						}

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TRANSPARENCY_INFO:
						transparency_info* ti;
						ti = (transparency_info*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: transparency_info (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: transparency_info (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CONNECTION_ID_DEPRECATED:
						connection_id_deprecated* cid;
						cid = (connection_id_deprecated*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: connection_id_deprecated (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: connection_id_deprecated (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case CONNECTION_ID:
						connection_id* conni;
						conni = (connection_id*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: connection_id (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: connection_id (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case EXTERNAL_ID_HASH:
						external_id_hash* eih;
						eih = (external_id_hash*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: external_id_hash (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: external_id_hash (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case EXTERNAL_SESSION_ID:
						external_session_id* esi;
						esi = (external_session_id*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: external_session_id (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: external_session_id (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case TICKET_REQUEST:
						ticket_request* tr;
						tr = (ticket_request*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: ticket_request (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: ticket_request (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case DNSSEC_CHAIN:
						dnssec_chain* dchain;
						dchain = (dnssec_chain*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: dnssec_chain (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: dnssec_chain (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS:
						sequence_number_encryption_algortithms* snea;
						snea = (sequence_number_encryption_algortithms*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: sequence_number_encryption_algortithms (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: sequence_number_encryption_algortithms (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case RRC:
						rrc* _rrc;
						_rrc = (rrc*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: rrc (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: rrc (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case ENCRYPTED_CLIENT_HELLO:
						encrypted_client_hello* ech;
						ech = (encrypted_client_hello*)(pkt_data + Extensions_start + extension_offset);
						printf("Extension: encrypted_client_hello (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: encrypted_client_hello (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case Reserved_51914:
						printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Data: <MISSING>\n");
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case Reserved_2570:
						printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Data: <MISSING>\n");
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case Reserved_56026:
						printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Data: <MISSING>\n");
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					case RENEGOTIATION_INFO:
						printf("Extension: renegotiation_info (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: renegotiation_info (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					default:
						printf("Extension: unknown (len=%d)\n", ntohs(etl->extensions_length));
						printf("\n");
						printf("Type: unknown (%d)\n", ntohs(etl->extensions_type));
						printf("\n");
						printf("Length: %d\n", ntohs(etl->extensions_length));
						printf("\n");

						extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
						break;
					}
				}
				hand_offset += 4 + (ntohl(ch->handshake_header.handshake_type_leng) & 0xFFFFFF);
				tls_offset += sizeof(tls_header) + hand_offset;
			}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO) {
					server_hello* sh = (server_hello*)(pkt_data + tls_data + tls_offset);
					char sh_combined_data[65];
					memset(sh_combined_data, 0, sizeof(sh_combined_data));
					
					printf("Handshake Type: Server Hello (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(sh->handshake_header.handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					if (ntohs(sh->handshake_header.tls_header.tls_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(sh->server_hello_version));
						printf("\n");
					}
					else if (ntohs(sh->server_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(sh->server_hello_version));
						printf("\n");
					}
					else if (ntohs(sh->server_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(sh->server_hello_version));
						printf("\n");
					}
					printf("Random: ");
					for (int i = 0; i < 32; i++) {
						printf("%02x", sh->sh_random_bytes[i]);
					}
					for (int i = 0; i < 32; i++) {
						sprintf(sh_combined_data + (i * 2), "%02x", sh->sh_random_bytes[i]);
					}

					sd->sh_random = (const unsigned char*)sh_combined_data;

					printf("\n");
					printf("\n");
					printf("Session ID Length: %d\n", sh->sh_session_id_length);
					printf("\n");
					if ((ntohs(sh->sh_cipher_suites) & 0x0F0F) == 0x0a0a) {
						printf("Cipher Suite: Reserved (GREASE) (0x%04x)\n", ntohs(sh->sh_cipher_suites));
						continue;
					}
					switch (ntohs(sh->sh_cipher_suites)) {
						case TLS_AES_256_GCM_SHA384:
							printf("Cipher Suite: TLS_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_AES_128_GCM_SHA256:
							printf("Cipher Suite: TLS_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_CHACHA20_POLY1305_SHA256:
							printf("Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
							printf("Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
							printf("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_256_GCM_SHA384:
							printf("Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_128_GCM_SHA256:
							printf("Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_256_CBC_SHA256:
							printf("Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_128_CBC_SHA256:
							printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_256_CBC_SHA:
							printf("Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_RSA_WITH_AES_128_CBC_SHA:
							printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
							printf("Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
							printf("Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
						default:
							printf("Unknown Cipher Suite (0x%04x)\n", ntohs(sh->sh_cipher_suites));
							break;
					}
					printf("\n");
					if (sh->sh_compression_methods == 0) {
						printf("Compression Methods: null (%d)", sh->sh_compression_methods);
						printf("\n");
					}
					else {
						printf("Compression Methods: Unknown (%d)", sh->sh_compression_methods);
						printf("\n");
					}
					printf("\n");
					printf("Extensions Length: %d\n", ntohs(sh->sh_extensions_length));
					printf("\n");

					//server extension ó��
					int Extensions_start = tls_data + sizeof(server_hello);

					server_hello_extensions* she;
					she = (server_hello_extensions*)(pkt_data + Extensions_start);

					while (ntohs(sh->sh_extensions_length) != extension_offset) {
						etl = (extensions_type_length*)(pkt_data + Extensions_start + extension_offset + tls_offset);
						switch (ntohs(etl->extensions_type)) {
							case SERVER_NAME:
								server_name* sn;
								sn = (server_name*)malloc(sizeof(server_hello_extensions) + ntohs(etl->extensions_length) * sizeof(char));
								sn = (server_name*)(pkt_data + Extensions_start + extension_offset);

								printf("Extension: server_name (len=%d) name=", ntohs(etl->extensions_length));
								for (int i = 0; i < ntohs(sn->server_name_length); i++) {
									printf("%c", sn->server_domain_name[i]);
								}
								printf("\n");
								printf("\n");
								printf("Type: server_name (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Server Name Indication extension\n");
								printf("\n");
								printf("Server Name list length: %d\n", ntohs(sn->server_name_list_length));
								printf("\n");
								printf("Server Name Type: host_name (%d)\n", sn->server_name_type);
								printf("\n");
								printf("Server Name length: %d\n", ntohs(sn->server_name_length));
								printf("\n");
								printf("Server Name: ");
								for (int i = 0; i < ntohs(sn->server_name_length); i++) {
									printf("%c", sn->server_domain_name[i]);
								}
								printf("\n");
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case MAX_FRAGMENT_LENGTH:
								max_fragment_length* mfl;
								mfl = (max_fragment_length*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: max_fragment_length (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: max_fragment_length (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CLIENT_CERTIFICATE_URL:
								client_certificate_url* ccu;
								ccu = (client_certificate_url*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: client_certificate_url (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: client_certificate_url (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TRUSTED_CA_KEYS:
								trusted_ca_keys* tck;
								tck = (trusted_ca_keys*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: trusted_ca_keys (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: trusted_ca_keys (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TRUNCATED_HMAC:
								truncated_hmac* thmac;
								thmac = (truncated_hmac*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: truncated_hmac (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: truncated_hmac (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case STATUS_REQUEST:
								status_request* sr;
								sr = (status_request*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: status_request (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: status_request (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								if (sr->status_type == 1) {
									printf("Certificate Status Type: OCSP (%d)\n", sr->status_type);
								}
								else {
									printf("Certificate Status Type : Unknown (%d)\n", sr->status_type);
								}
								printf("\n");
								printf("Responder ID list Length: %d\n", ntohs(sr->responder_id_list_length));
								printf("\n");
								printf("Request Extensions Length: %d\n", ntohs(sr->request_extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case USER_MAPPING:
								user_mapping* um;
								um = (user_mapping*)(pkt_data + Extensions_start + extension_offset);
								break; printf("Extension: user_mapping (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: user_mapping (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CLIENT_AUTHZ:
								client_authz* ca;
								ca = (client_authz*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: client_authz (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: client_authz (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SERVER_AUTHZ:
								server_authz* saz;
								saz = (server_authz*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: server_authz (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: server_authz (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CERT_TYPE:
								cert_type* ct;
								ct = (cert_type*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: cert_type (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: cert_type (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SUPPORTED_GROUPS:
								supported_groups* sg;
								sg = (supported_groups*)malloc(sizeof(extensions_type_length) + ntohs(etl->extensions_length) - sizeof(etl->extensions_length));
								sg = (supported_groups*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: supported_groups (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: supported_groups (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Supported Groups List Length: %d\n", ntohs(sg->sup_groups_list_length));
								printf("\n");
								printf("Supported Groups (%d groups)\n", ntohs(sg->sup_groups_list_length) / 2);
								printf("\n");
								for (int i = 0; i < ntohs(sg->sup_groups_list_length) / 2; i++) {
									if (ntohs(sg->sup_groups[i]) >= 0x0001 && ntohs(sg->sup_groups[i]) <= 0x0016) {
										printf("Supported Group: deprecated (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x0017) {
										printf("Supported Group: secp256r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x0018) {
										printf("Supported Group: secp384r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x0019) {
										printf("Supported Group: secp521r1 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x001D) {
										printf("Supported Group: ffdhe2048 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x001E) {
										printf("Supported Group: ffdhe3072 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x18FF) {
										printf("Supported Group: ffdhe4096 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) >= 0xFE00 && ntohs(sg->sup_groups[i]) <= 0xFEFF) {
										printf("Supported Group: ffdhe6144 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) >= 0xFF01 && ntohs(sg->sup_groups[i]) <= 0xFF02) {
										printf("Supported Group: ffdhe8192 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x001D) {
										printf("Supported Group: x25519 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x001E) {
										printf("Supported Group: x448 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) == 0x6399) {
										printf("Supported Group: X25519Kyber768Draft00 (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if ((ntohs(sg->sup_groups[i]) >= 0xFE00 && ntohs(sg->sup_groups[i]) <= 0xFEFF) || (ntohs(sg->sup_groups[i] & 0x0F0F) == 0x0a0a)) {
										printf("Supported Group: Reserved (GREASE) (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else if (ntohs(sg->sup_groups[i]) >= 0xFF01 && ntohs(sg->sup_groups[i]) <= 0xFF02) {
										printf("Supported Group: deprecated (0x%04x)\n", ntohs(sg->sup_groups[i]));
									}
									else {
										printf("Supported Group: Unknown (0x%04x)\n", ntohs(ntohs(sg->sup_groups[i])));
									}
								}
								printf("\n");
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case EC_POINT_FORMATS:
								ec_point_formats* epf;
								epf = (ec_point_formats*)(pkt_data + Extensions_start + extension_offset);
								epf = (ec_point_formats*)malloc(epf->ec_point_formats_length);
								epf = (ec_point_formats*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: ec_point_formats (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type:  ec_point_formats (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("EC point format Length: %d\n", ntohs(epf->ec_point_formats_length));
								printf("\n");
								printf("Elliptic curves point formats (%d)\n", epf->ec_point_formats_length);
								printf("\n");
								for (int i = 0; i < epf->ec_point_formats_length; i++) {
									if (epf->ec_point_format[i] == UNCOMPRESSED) {
										printf("EC Point format: uncompressed (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
									else if (epf->ec_point_format[i] == ANSIX962_COMPRESSED_PRIME) {
										printf("EC Point format: ansiX962_compressed_prime (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
									else if (epf->ec_point_format[i] == ANSIX962_COMPRESSED_CHAR2) {
										printf("EC Point format: ansiX962_compressed_char2 (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
									else if (epf->ec_point_format[i] >= 3 && epf->ec_point_format[i] <= 247) {
										printf("EC Point format: unassigned (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
									else if (epf->ec_point_format[i] >= 248 && epf->ec_point_format[i] <= 255) {
										printf("EC Point format: reserved_for_private_use (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
									else {
										printf("EC Point format: Unknown (%d)\n", epf->ec_point_format[i]);
										printf("\n");
									}
								}
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SRP:
								srp* _srp;
								_srp = (srp*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: srp (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: srp (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SIGNATURE_ALGORITHMS:
								signature_algorithms* sa;
								sa = (signature_algorithms*)(pkt_data + Extensions_start + extension_offset);
								sa = (signature_algorithms*)malloc(ntohs(sa->signature_hash_algorithms_length));
								sa = (signature_algorithms*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: signature_algorithms (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: signature_algorithms (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Signature Hash Algorithms Length: %d\n", ntohs(sa->signature_hash_algorithms_length));
								printf("\n");
								printf("Signature Hash Algorithms (%d algorithm)\n", ntohs(sa->signature_hash_algorithms_length) / 2);
								printf("\n");
								for (int i = 0; i < ntohs(sa->signature_hash_algorithms_length) / 2; i++) {
									if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha256) {
										printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp256r1_sha256) {
										printf("Signature Algorithm: ecdsa_secp256r1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha384) {
										printf("Signature Algorithm: rsa_pkcs1_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp384r1_sha384) {
										printf("Signature Algorithm: ecdsa_secp384r1_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha512) {
										printf("Signature Algorithm: rsa_pkcs1_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_secp521r1_sha512) {
										printf("Signature Algorithm: ecdsa_secp521r1_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha256) {
										printf("Signature Algorithm: rsa_pss_rsae_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha384) {
										printf("Signature Algorithm: rsa_pss_rsae_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_rsae_sha512) {
										printf("Signature Algorithm: rsa_pss_rsae_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ed25519) {
										printf("Signature Algorithm: ed25519 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: reserved (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ed448) {
										printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: Intrinsic (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha256) {
										printf("Signature Algorithm: rsa_pss_pss_sha256 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha384) {
										printf("Signature Algorithm: rsa_pss_pss_sha384 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pss_pss_sha512) {
										printf("Signature Algorithm: rsa_pss_pss_sha512 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ED448 (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == rsa_pkcs1_sha1) {
										printf("Signature Algorithm: rsa_pkcs1_sha1 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: RSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else if (ntohs(sa->signature_hash_algorithms[i]) == ecdsa_sha1) {
										printf("Signature Algorithm: ecdsa_sha1 (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
									else {
										printf("Signature Algorithm: unknown (0x%04x)\n", ntohs(sa->signature_hash_algorithms[i]));
										printf("\n");
										printf("Signature Hash Algorithm Hash: unknown (%d)\n", (ntohs(sa->signature_hash_algorithms[i]) >> 8) & 0xFF);
										printf("\n");
										printf("Signature Algorithm: unknown (%d)\n", ntohs(sa->signature_hash_algorithms[i]) & 0xFF);
										printf("\n");
									}
								}
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case USE_SRTP:
								use_srtp* us;
								us = (use_srtp*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: use_srtp (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: use_srtp (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case HEARTBEAT:
								heartbeat* hb;
								hb = (heartbeat*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: heartbeat (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: heartbeat (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
								application_layer_protocol_negotiation* alpn;
								alpn = (application_layer_protocol_negotiation*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: application_layer_protocol_negotiation (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: application_layer_protocol_negotiation (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case STATUS_REQUEST_V2:
								status_request_v2* srv;
								srv = (status_request_v2*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: status_request_v2 (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: status_request_v2 (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SIGNED_CERTIFICATE_TIMESTAMP:
								signed_certificate_timestamp* sct;
								sct = (signed_certificate_timestamp*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: signed_certificate_timestamp (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: signed_certificate_timestamp (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CLIENT_CERTIFICATE_TYPE:
								client_certificate_type* cct;
								cct = (client_certificate_type*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: client_certificate_type (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: client_certificate_type (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SERVER_CERTIFICATE_TYPE:
								server_certificate_type* setype;
								setype = (server_certificate_type*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: server_certificate_type (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: server_certificate_type (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PADDING:
								padding* pad;
								pad = (padding*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: padding (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: padding (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case ENCRYPT_THEN_MAC:
								encrypt_then_mac* etm;
								etm = (encrypt_then_mac*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: encrypt_then_mac (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: encrypt_then_mac (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case EXTENDED_MASTER_SECRET:
								extended_master_secret* ems;
								ems = (extended_master_secret*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: extended_master_secret (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: extended_master_secret (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TOKEN_BINDING:
								token_binding* tb;
								tb = (token_binding*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: token_binding (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: token_binding (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CACHED_INFO:
								cached_info* ci;
								ci = (cached_info*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: caetld_info (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: caetld_info (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TLS_LTS:
								tls_lts* tl;
								tl = (tls_lts*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: tls_lts (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: tls_lts (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case COMPRESS_CERTIFICATE:
								compress_certificate* cc;
								cc = (compress_certificate*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: compress_certificate (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: compress_certificate (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case RECORD_SIZE_LIMIT:
								record_size_limit* rsl;
								rsl = (record_size_limit*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: record_size_limit (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: record_size_limit (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PWD_PROTECT:
								pwd_protect* pp;
								pp = (pwd_protect*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: pwd_protect (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: pwd_protect (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PWD_CLEAR:
								pwd_clear* pc;
								pc = (pwd_clear*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: pwd_clear (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: pwd_clear (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PASSWORD_SALT:
								password_salt* ps;
								ps = (password_salt*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: password_salt (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: password_salt (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TICKET_PINNING:
								ticket_pinning* tp;
								tp = (ticket_pinning*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: ticket_pinning (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: ticket_pinning (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TLS_CERT_WITH_EXTERN_PSK:
								tls_cert_with_extern_psk* tcwep;
								tcwep = (tls_cert_with_extern_psk*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: tls_cert_with_extern_psk (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: tls_cert_with_extern_psk (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case DELEGATED_CREDENTIAL:
								delegated_credential* dc;
								dc = (delegated_credential*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: delegated_credential (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: delegated_credential (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SESSION_TICKET:
								session_ticket* st;
								st = (session_ticket*)(pkt_data + Extensions_start + extension_offset);
								st = (session_ticket*)malloc(ntohs(etl->extensions_length));
								st = (session_ticket*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: session_ticket (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: session_ticket (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								if (etl->extensions_length == 0) {
									printf("Session Ticket: <MISSING>\n");
								}
								else {
									printf("Session Ticket: ");
									for (int i = 0; i < ntohs(etl->extensions_length); i++) {
										printf("%x", st->session_ticket_data[i]);
									}
									printf("\n");
								}
								printf("\n");
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TLMSP:
								tlmsp* tlm;
								tlm = (tlmsp*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: tlmsp (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: tlmsp (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TLMSP_PROXYING:
								tlmsp_proxying* tlmproxy;
								tlmproxy = (tlmsp_proxying*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: tlmsp_proxying (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: tlmsp_proxying (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TLMSP_DELEGATE:
								tlmsp_delegate* tlmspdel;
								tlmspdel = (tlmsp_delegate*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: tlmsp_delegate (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: tlmsp_delegate (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SUPPORTED_EKT_CIPHERS:
								supported_ekt_ciphers* sec;
								sec = (supported_ekt_ciphers*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: supported_ekt_ciphers (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: supported_ekt_ciphers (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case RESERVED_40:
								reserved_40* re_40;
								re_40 = (reserved_40*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: reserved (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: reserved (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PRE_SHARED_KEY:
								pre_shared_key* psk;
								psk = (pre_shared_key*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: pre_shared_key (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: pre_shared_key (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case EARLY_DATA:
								early_data* ed;
								ed = (early_data*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: early_data (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: early_data (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SUPPORTED_VERSIONS:
								supported_versions* sv;
								sv = (supported_versions*)(pkt_data + Extensions_start + extension_offset);
								sv = (supported_versions*)malloc(sv->supported_versions_length);
								sv = (supported_versions*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: supported_versions (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: supported_versions (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Suppoted Versions length: %d\n", sv->supported_versions_length);
								printf("\n");
								for (int i = 0; i < sv->supported_versions_length / 2; i++) {
									if (ntohs(sv->supported_version[i]) == SSL_3_0) {
										printf("Supported Version: SSL 3.0 (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
									else if (ntohs(sv->supported_version[i]) == TLS_1_0) {
										printf("Supported Version: TLS 1.0 (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
									else if (ntohs(sv->supported_version[i]) == TLS_1_1) {
										printf("Supported Version: TLS 1.1 (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
									else if (ntohs(sv->supported_version[i]) == TLS_1_2) {
										printf("Supported Version: TLS 1.2 (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
									else if (ntohs(sv->supported_version[i]) == TLS_1_3) {
										printf("Supported Version: TLS 1.3 (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
									else {
										printf("Supported Version: Unknown (0x%04x)\n", ntohs(sv->supported_version[i]));
										printf("\n");
									}
								}

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case COOKIE:
								cookie* ck;
								ck = (cookie*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: cookie (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: cookie (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case PSK_KEY_EXCHANGE_MODES:
								psk_key_exchange_modes* pkem;
								pkem = (psk_key_exchange_modes*)(pkt_data + Extensions_start + extension_offset);
								pkem = (psk_key_exchange_modes*)malloc(pkem->psk_key_exchange_modes_length);
								pkem = (psk_key_exchange_modes*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: psk_key_exchange_modes (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: psk_key_exchange_modes (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("PSK key Exchange Modes Length: %d\n", pkem->psk_key_exchange_modes_length);
								printf("\n");
								for (int i = 0; i < pkem->psk_key_exchange_modes_length; i++) {
									if (pkem->psk_key_exchange_mode[i] == PSK_KE) {
										printf("PSK key Exchange Mode: PSK key establishment (psk_ke) (%d)\n", pkem->psk_key_exchange_mode[i]);
										printf("\n");
									}
									else if (pkem->psk_key_exchange_mode[i] == PSK_DHE_KE) {
										printf("PSK key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (%d)\n", pkem->psk_key_exchange_mode[i]);
										printf("\n");
									}
									else if (pkem->psk_key_exchange_mode[i] >= UNASSIGNED_2 && pkem->psk_key_exchange_mode[i] <= UNASSIGNED_253) {
										printf("PSK key Exchange Mode: Unassigned (%d)\n", pkem->psk_key_exchange_mode[i]);
										printf("\n");
									}
									else if (pkem->psk_key_exchange_mode[i] >= RESERVED_FOR_PRIVATE_USE_254 && pkem->psk_key_exchange_mode[i] <= RESERVED_FOR_PRIVATE_USE_255) {
										printf("PSK key Exchange Mode: Reserved For Private Use (%d)\n", pkem->psk_key_exchange_mode[i]);
										printf("\n");
									}
									else {
										printf("PSK key Exchange Mode: Unknown (%d)\n", pkem->psk_key_exchange_mode[i]);
										printf("\n");
									}
								}

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case RESERVED_46:
								reserved_46* re_46;
								re_46 = (reserved_46*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: reserved (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: reserved (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CERTIFICATE_AUTHORITIES:
								certificate_authorities* certauth;
								certauth = (certificate_authorities*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: certificate_authorities (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: certificate_authorities (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case OID_FILTERS:
								oid_filters* of;
								of = (oid_filters*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: oid_filters (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: oid_filters (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case POST_HANDSHAKE_AUTH:
								post_handshake_auth* pha;
								pha = (post_handshake_auth*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: post_handshake_auth (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: post_handshake_auth (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SIGNATURE_ALGORITHMS_CERT:
								signature_algorithms_cert* sac;
								sac = (signature_algorithms_cert*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: signature_algorithms_cert (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: signature_algorithms_cert (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case KEY_SHARE:
								key_share* ks;
								ks = (key_share*)(pkt_data + Extensions_start + extension_offset);
								ks = (key_share*)malloc(ntohs(ks->key_exchange_length));
								ks = (key_share*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: key_share (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: key_share (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Key Share extension\n");
								printf("\n");
								printf("Server Key Share Length: %d\n", ntohs(ks->Client_key_share_length));
								printf("\n");
								if (ntohs(ks->group) == CURVE_SECP256R1) {
									printf("Key Share Entry: Group: secp256r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: secp256r1 (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}
								else if (ntohs(ks->group) == CURVE_SECP384R1) {
									printf("Key Share Entry: Group: secp384r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: secp384r1 (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}
								else if (ntohs(ks->group) == CURVE_SECP521R1) {
									printf("Key Share Entry: Group: secp521r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: secp521r1 (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}
								else if (ntohs(ks->group) == CURVE_X25519) {
									printf("Key Share Entry: Group: x25519, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: x25519 (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%01x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}
								else if (ntohs(ks->group) == CURVE_X448) {
									printf("Key Share Entry: Group: secp384r1, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: x25519 (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}
								else {
									printf("Key Share Entry: Group: Unknown, Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("Group: Unknown (%d)\n", ntohs(ks->group));
									printf("\n");
									printf("Key Exchange length: %d\n", ntohs(ks->key_exchange_length));
									printf("\n");
									printf("key Exchange: ");
									for (int i = 0; i < ntohs(ks->key_exchange_length); i++) {
										printf("%x", ks->key_exchange[i]);
									}
									printf("\n");
									printf("\n");
								}

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TRANSPARENCY_INFO:
								transparency_info* ti;
								ti = (transparency_info*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: transparency_info (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: transparency_info (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CONNECTION_ID_DEPRECATED:
								connection_id_deprecated* cid;
								cid = (connection_id_deprecated*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: connection_id_deprecated (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: connection_id_deprecated (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case CONNECTION_ID:
								connection_id* conni;
								conni = (connection_id*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: connection_id (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: connection_id (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case EXTERNAL_ID_HASH:
								external_id_hash* eih;
								eih = (external_id_hash*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: external_id_hash (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: external_id_hash (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case EXTERNAL_SESSION_ID:
								external_session_id* esi;
								esi = (external_session_id*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: external_session_id (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: external_session_id (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case TICKET_REQUEST:
								ticket_request* tr;
								tr = (ticket_request*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: ticket_request (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: ticket_request (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case DNSSEC_CHAIN:
								dnssec_chain* dchain;
								dchain = (dnssec_chain*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: dnssec_chain (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: dnssec_chain (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS:
								sequence_number_encryption_algortithms* snea;
								snea = (sequence_number_encryption_algortithms*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: sequence_number_encryption_algortithms (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: sequence_number_encryption_algortithms (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case RRC:
								rrc* _rrc;
								_rrc = (rrc*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: rrc (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: rrc (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case ENCRYPTED_CLIENT_HELLO:
								encrypted_client_hello* ech;
								ech = (encrypted_client_hello*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: encrypted_client_hello (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: encrypted_client_hello (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case Reserved_51914:
								printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Data: <MISSING>\n");
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case Reserved_2570:
								printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Data: <MISSING>\n");
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case Reserved_56026:
								printf("Extension: Reserved (GREASE) (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: Reserved (GREASE) (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Data: <MISSING>\n");
								printf("\n");
								
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							case RENEGOTIATION_INFO:
								renegotiation_info* ri;
								ri = (renegotiation_info*)(pkt_data + Extensions_start + extension_offset);
								printf("Extension: renegotiation_info (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: renegotiation_info (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Renegotiation Info extension\n");
								printf("\n");
								printf("Renegotiation info extension length: %d\n", ri->renegotiation_info_extension_length);
								printf("\n");
								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
							default:
								printf("Extension: unknown (len=%d)\n", ntohs(etl->extensions_length));
								printf("\n");
								printf("Type: unknown (%d)\n", ntohs(etl->extensions_type));
								printf("\n");
								printf("Length: %d\n", ntohs(etl->extensions_length));
								printf("\n");

								extension_offset += sizeof(etl->extensions_type) + sizeof(etl->extensions_length) + ntohs(etl->extensions_length);
								break;
						}
					}
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == NEW_SESSION_TICKET) {
					printf("Handshake Type: New Session Ticket (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE) {
					certificate* cert;
					cert = (certificate*)(pkt_data + tls_data + tls_offset);

					int signedcertificate_start = tls_data + tls_offset + 4;


					printf("Handshake Type: Certificate (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					printf("Certificates Length: %d\n", cert->certificates_length[0] << 16 | cert->certificates_length[1] << 8 | cert->certificates_length[2]);
					printf("\n");
					printf("Certificates (%d bytes)\n", cert->certificates_length[0] << 16 | cert->certificates_length[1] << 8 | cert->certificates_length[2]);
					printf("\n");
					printf("Certificate Length : %d\n", cert->certificate_length[0] << 16 | cert->certificate_length[1] << 8 | cert->certificate_length[2]);
					printf("\n");
					printf("Certificate: ");
					printf("\n");
					for (int i = 0; i < (cert->certificate_length[0] << 16 | cert->certificate_length[1] << 8 | cert->certificate_length[2]); i++) {
						printf("%02x", cert->certificate_data[i]);
					}
					printf("\n");

					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_KEY_EXCHANGE_RESERVED) {
					server_key_exchange* ske;
					ske = (server_key_exchange*)(pkt_data + tls_data + tls_offset);
					ske = (server_key_exchange*)malloc(ske->pubkey_length);
					ske = (server_key_exchange*)(pkt_data + tls_data + tls_offset);
					
					sd->ske = ske;

					char ske_combined_data[512];
					memset(ske_combined_data, 0, sizeof(ske_combined_data));

					printf("Handshake Type: Server Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					printf("EC Diffie-Hellman Server Parms\n");
					printf("\n");
					if (ske->curve_type == CURVE_UNASSIGNED) {
						printf("Curve Type: unassigned (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else if (ske->curve_type == CURVE_EXPLICIT_PRIME) {
						printf("Curve Type: explicit_prime (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else if (ske->curve_type == CURVE_EXPLICIT_CHAR2) {
						printf("Curve Type: explicit_char2 (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else if (ske->curve_type == CURVE_NAMED_CURVE) {
						printf("Curve Type: named_curve (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else if (ske->curve_type >= 4 && ske->curve_type <= 247) {
						printf("Curve Type: unassigned (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else if (ske->curve_type >= 248 && ske->curve_type <= 255) {
						printf("Curve Type: reserved_for_private_use (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					else {
						printf("Curve Type: unknown (0x%02X)\n", ske->curve_type);
						printf("\n");
					}
					
					if (ntohs(ske->named_curve) == CURVE_SECP256R1) {
						printf("Name Curve: spec256r1 (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}
					else if (ntohs(ske->named_curve) == CURVE_SECP384R1) {
						printf("Name Curve: spec384r1 (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}
					else if (ntohs(ske->named_curve) == CURVE_SECP521R1) {
						printf("Name Curve: spec521r1 (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}
					else if (ntohs(ske->named_curve) == CURVE_X25519) {
						printf("Name Curve: x25519 (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}
					else if (ntohs(ske->named_curve) == CURVE_X448) {
						printf("Name Curve: x448 (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}
					else {
						printf("Name Curve: unknown (0x%04x)\n", ntohs(ske->named_curve));
						printf("\n");
					}

					printf("Pubkey Length: %d\n", ske->pubkey_length);
					printf("\n");
					printf("Pubkey: ");
					for (int i = 0; i < ske->pubkey_length; i++) {
						printf("%02x", ske->pubkey[i]);
					}
					for (int i = 0; i < ske->pubkey_length; i++) {
						sprintf(ske_combined_data + (i * 2), "%02x", ske->pubkey[i]);
					}

					sd->ske_pubkey = (const unsigned char*)ske_combined_data;
					printf("\n");
					printf("\n");
					
					signature_algorithm* sial;
					sial = (signature_algorithm*)(pkt_data + tls_data + tls_offset + sizeof(server_key_exchange) + ske->pubkey_length);
					sial = (signature_algorithm*)malloc(ntohs(sial->sign_length));
					sial = (signature_algorithm*)(pkt_data + tls_data + tls_offset + sizeof(server_key_exchange) + ske->pubkey_length);

					if (ntohs(sial->signature_algorithm) == rsa_pkcs1_sha256) {
						printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: RSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ecdsa_secp256r1_sha256) {
						printf("Signature Algorithm: ecdsa_secp256r1_sha256 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pkcs1_sha384) {
						printf("Signature Algorithm: rsa_pkcs1_sha384 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: RSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ecdsa_secp384r1_sha384) {
						printf("Signature Algorithm: ecdsa_secp384r1_sha384 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pkcs1_sha512) {
						printf("Signature Algorithm: rsa_pkcs1_sha512 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: RSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ecdsa_secp521r1_sha512) {
						printf("Signature Algorithm: ecdsa_secp521r1_sha512 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_rsae_sha256) {
						printf("Signature Algorithm: rsa_pss_rsae_sha256 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_rsae_sha384) {
						printf("Signature Algorithm: rsa_pss_rsae_sha384 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_rsae_sha512) {
						printf("Signature Algorithm: rsa_pss_rsae_sha512 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ed25519) {
						printf("Signature Algorithm: ed25519 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: reserved (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ed448) {
						printf("Signature Algorithm: rsa_pkcs1_sha256 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: Intrinsic (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_pss_sha256) {
						printf("Signature Algorithm: rsa_pss_pss_sha256 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA256 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_pss_sha384) {
						printf("Signature Algorithm: rsa_pss_pss_sha384 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA384 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pss_pss_sha512) {
						printf("Signature Algorithm: rsa_pss_pss_sha512 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA512 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ED448 (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == rsa_pkcs1_sha1) {
						printf("Signature Algorithm: rsa_pkcs1_sha1 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: RSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else if (ntohs(sial->signature_algorithm) == ecdsa_sha1) {
						printf("Signature Algorithm: ecdsa_sha1 (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: SHA1 (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: ECDSA (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					else {
						printf("Signature Algorithm: unknown (0x%04x)\n", ntohs(sial->signature_algorithm));
						printf("\n");
						printf("Signature Hash Algorithm Hash: unknown (%d)\n", (ntohs(sial->signature_algorithm) >> 8) & 0xFF);
						printf("\n");
						printf("Signature Algorithm: unknown (%d)\n", ntohs(sial->signature_algorithm) & 0xFF);
						printf("\n");
					}
					printf("signature Length: %d\n", ntohs(sial->sign_length));
					printf("\n");
					printf("Signature: ");
					for (int i = 0; i < ntohs(sial->sign_length); i++) {
						printf("%02x", sial->signature[i]);
					}
					printf("\n");
					printf("\n");

					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_REQUEST) {
					printf("Handshake Type: Certificate Request (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == SERVER_HELLO_DONE_RESERVED) {
					printf("Handshake Type: Server Hello Done (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CERTIFICATE_VERIFY) {
					printf("Handshake Type: Certificate Verify (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_KEY_EXCHANGE_RESERVED) {
					printf("Handshake Type: Client Key Exchange (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
				else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == FINISHED) {
					printf("Handshake Type: Finished (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
					printf("\n");
					printf("Length: %d\n", ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					printf("\n");
					/*if (ntohs(hp->client_hello_version) == TLS_1_0) {
						printf("Version: TLS 1.0 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_1) {
						printf("Version: TLS 1.1 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}
					else if (ntohs(hp->client_hello_version) == TLS_1_2) {
						printf("Version: TLS 1.2 (0x%04x)\n", ntohs(hp->client_hello_version));
						printf("\n");
					}*/
					hand_offset += 4 + (ntohl(hp->handshake_type_leng) & 0xFFFFFF);
					tls_offset += sizeof(tls_header) + hand_offset;
				}
			/*}*/
			//	/*if (tls_data != pk->header->len) {
			//		tls_data += ntohs(th->tls_length);
			//		ap = (alert_proto*)pkt_data + tls_data;
			//		cp = (ccs_proto*)pkt_data + tls_data;
			//		th = (tls_header*)pkt_data + tls_data;
			//		appli = (application_proto*)malloc(ntohs(th->tls_length) * sizeof(char));
			//		appli = (application_proto*)pkt_data + tls_data;
			//		hp = (handshake_protocol*)((u_char*)pkt_data + tls_data);
			//		ch = (client_hello*)pkt_data + tls_data;
			//	}*/
			//	printf("\n");
		
	}
}
}