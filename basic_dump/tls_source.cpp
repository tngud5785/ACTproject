#include "tls_header.h"
#include "tcp_header.h"
#include "struct.h"
#include "define.h"
#include "include.h"


void print_tls(record_layer* rl) {
	extern packet* pk;
	int sum = 0;


	alert_proto* ap;
	ap = (alert_proto*)rl;

	ccs_proto* cp;
	cp = (ccs_proto*)rl;

	application_proto* appli = (application_proto*)malloc(ntohs(rl->rl_length) * sizeof(char));
	appli = (application_proto*)rl;

	handshake_protocol* hp;
	hp = (handshake_protocol*)((u_char*)rl + 5);

	sum = ETHER_LENGTH + (pk->ip->ip_leng * 4) + (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	printf("%d\n", sum);
	printf("%d\n", pk->header->len);
	print_tcp(pk->tcp, pk->ip);
	//while (sum != pk->header->len) {
	printf("****************** TLSv1.2 Record Layer *****************\n");
	printf("\n");
	if (rl->rl_type == CHANGE_CIPHER_SPEC) {
		printf("Content Type: Change Cipher Spec (%d)\n", CHANGE_CIPHER_SPEC);
	}
	else if (rl->rl_type == ALERT) {
		printf("Content Type: Alert (%d)\n", ALERT);
	}
	else if (rl->rl_type == HANDSHAKE) {
		printf("Content Type: Handshake (%d)\n", HANDSHAKE);
	}
	else if (rl->rl_type == APPLICATION_DATA) {
		printf("Content Type: Application data (%d)\n", APPLICATION_DATA);
	}

	printf("\n");
	if (ntohs(rl->rl_version) == TLS_1_0) {
		printf("Version: TLS 1.0 (0x%04x)\n", ntohs(rl->rl_version));
	}
	else if (ntohs(rl->rl_version) == TLS_1_1) {
		printf("Version: TLS 1.1 (0x%04x)\n", ntohs(rl->rl_version));
	}
	else if (ntohs(rl->rl_version) == TLS_1_2) {
		printf("Version: TLS 1.2 (0x%04x)\n", ntohs(rl->rl_version));
	}

	printf("\n");
	printf("Length: %d\n", ntohs(rl->rl_length));
	printf("\n");
	if (rl->rl_type == CHANGE_CIPHER_SPEC) {
		printf("Change Cipher Spec Message\n");
	}
	else if (rl->rl_type == ALERT) {
		printf("Alert Message: Encrypted Alert\n");
		if (ap->alert_level == 0x01) {
			printf("Level: Warning (%d)\n", ap->alert_level);
		}
		else if (ap->alert_level == 0x02) {
			printf("level: Fatal (%d)\n", ap->alert_level);
		}

		if (ap->alert_descl == 0x00) {
			printf("Description: CLOSE_NOTIFY (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x64) {
			printf("Description: NO_RENEGOTIATION (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x0A) {
			printf("Description: UNEXPECTED_MESSAGE (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x14) {
			printf("Description: BAD_RECORD_MAC (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x15) {
			printf("Description: DECRYPTION_FAILED (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x28) {
			printf("Description: HANDSHAKE_FAILURE (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x2A) {
			printf("Description: BAD_CERTIFICATE (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x2B) {
			printf("Description: UNSUPPORTED_CERTIFICATE (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x2C) {
			printf("Description: CERTIFICATE_REVOKE (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x2D) {
			printf("Description: CERTIFICATE_EXPIRED (%d)\n", ap->alert_descl);
		}
		else if (ap->alert_descl == 0x70) {
			printf("Description: UNRECOGNIZED_NAME (%d)\n", ap->alert_descl);
		}
		else {
			printf("Description: UNKNOWN ALERT (%d)\n", ap->alert_descl);
		}
	}
	else if (rl->rl_type == APPLICATION_DATA) {
		printf("Encrypted Application Data: ");
		for (int i = 0; i < ntohs(appli->app_leng); i++) {
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
	else if (rl->rl_type == HANDSHAKE) {
		if (ntohs(cp->ccs_leng) == 0x0001 && cp->ccs_message == 0x01 && rl->rl_type == 0x16) {
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
		else if ((ntohl(hp->handshake_type_leng) >> 24 & 0xFF) == CLIENT_HELLO) {
			client_hello* ch;
			ch = (client_hello*)((u_char*)hp + 6);
			printf("Handshake Type: Client Hello (%d)\n", ntohl(hp->handshake_type_leng) >> 24 & 0xFF);
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
			_sleep(10000);
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
			_sleep(10000);
		}
		//}
	}
	printf("\n");
}

