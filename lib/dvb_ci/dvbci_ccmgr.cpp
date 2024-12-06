/* DVB CI Content Control Manager */
#include <lib/dvb_ci/dvbci_ccmgr.h>
#include <lib/dvb_ci/dvbci.h>
#include <lib/dvb_ci/aes_xcbc_mac.h>
#include <lib/dvb_ci/descrambler.h>
#include <lib/dvb_ci/dvbci_ccmgr_helper.h>
#include <openssl/aes.h>
#include <openssl/evp.h>  // Per gestione generica delle chiavi (RSA, DH)
#include <openssl/rsa.h>   // Per RSA
#include <openssl/dh.h>    // Per DH
#include <openssl/x509.h>

eDVBCICcSession::eDVBCICcSession(eDVBCISlot *slot, int version)
    : m_slot(slot), m_akh_index(0),
      m_root_ca_store(nullptr), m_cust_cert(nullptr), m_device_cert(nullptr),
      m_ci_cust_cert(nullptr), m_ci_device_cert(nullptr),
      m_rsa_device_key(nullptr), m_dh(nullptr)  // Usato EVP_PKEY per RSA e DH
{
    uint8_t buf[32], host_id[8];

    m_slot->setCCManager(this);
    m_descrambler_fd = -1;
    m_current_ca_demux_id = 0;
    m_descrambler_new_key = false;

    parameter_init(m_slot->getSlotID(), m_dh_p, m_dh_g, m_dh_q, m_s_key, m_key_data, m_iv);

    m_ci_elements.init();

    memset(buf, 0, 1);
    if (!m_ci_elements.set(STATUS_FIELD, buf, 1))
        eWarning("[CI%d RCC] can not set status", m_slot->getSlotID());

    memset(buf, 0, 32);
    buf[31] = 0x01; // URI_PROTOCOL_V1
    if (version >= 2)
        buf[31] |= 0x02; // URI_PROTOCOL_V2
    if (version >= 4)
        buf[31] |= 0x04; // URI_PROTOCOL_V4

    if (!m_ci_elements.set(URI_VERSIONS, buf, 32))
        eWarning("[CI%d RCC] can not set uri_versions", m_slot->getSlotID());

    if (!get_authdata(host_id, m_dhsk, buf, m_slot->getSlotID(), m_akh_index))
    {
        memset(buf, 0, sizeof(buf));
        m_akh_index = 5;
    }

    if (!m_ci_elements.set(AKH, buf, 32))
        eWarning("[CI%d RCC] can not set AKH", m_slot->getSlotID());

    if (!m_ci_elements.set(HOST_ID, host_id, 8))
        eWarning("[CI%d RCC] can not set host_id", m_slot->getSlotID());
}

eDVBCICcSession::~eDVBCICcSession()
{
    m_slot->setCCManager(0);
    if (m_slot->getDescramblingOptions() != 1 && m_slot->getDescramblingOptions() != 3)
        descrambler_deinit(m_descrambler_fd);

    if (m_root_ca_store)
        X509_STORE_free(m_root_ca_store);
    if (m_cust_cert)
        X509_free(m_cust_cert);
    if (m_device_cert)
        X509_free(m_device_cert);
    if (m_ci_cust_cert)
        X509_free(m_ci_cust_cert);
    if (m_ci_device_cert)
        X509_free(m_ci_device_cert);

    // Gestione delle chiavi con EVP_PKEY
    if (m_rsa_device_key)
        EVP_PKEY_free(m_rsa_device_key);  // Deallocazione della chiave RSA
    if (m_dh)
        EVP_PKEY_free(m_dh);  // Deallocazione della chiave DH

    m_ci_elements.init();
}


int eDVBCICcSession::receivedAPDU(const unsigned char *tag, const void *data, int len)
{
	eTraceNoNewLineStart("[CI%d CC] SESSION(%d)/CC %02x %02x %02x: ", m_slot->getSlotID(), session_nb, tag[0], tag[1], tag[2]);
	for (int i = 0; i < len; i++)
		eTraceNoNewLine("%02x ", ((const unsigned char *)data)[i]);
	eTraceNoNewLine("\n");

	if ((tag[0] == 0x9f) && (tag[1] == 0x90))
	{
		switch (tag[2])
		{
		case 0x01:
			cc_open_req();
			break;
		case 0x03:
			cc_data_req((const uint8_t *)data, len);
			break;
		case 0x05:
			cc_sync_req((const uint8_t *)data, len);
			break;
		case 0x07:
			cc_sac_data_req((const uint8_t *)data, len);
			break;
		case 0x09:
			cc_sac_sync_req((const uint8_t *)data, len);
			break;
		default:
			eWarning("[CI%d RCC] unknown APDU tag %02x", m_slot->getSlotID(), tag[2]);
			break;
		}
	}

	return 0;
}

int eDVBCICcSession::doAction()
{
	switch (state)
	{
	case stateStarted:
		break;
	default:
		eWarning("[CI%d CC] unknown state", m_slot->getSlotID());
		break;
	}
	return 0;
}

void eDVBCICcSession::send(const unsigned char *tag, const void *data, int len)
{
	sendAPDU(tag, data, len);
}

void eDVBCICcSession::addProgram(uint16_t program_number, std::vector<uint16_t> &pids)
{
	// first open ca device and set descrambler key if it's not set yet
	set_descrambler_key();

	eDebugNoNewLineStart("[CI%d CC] SESSION(%d)/ADD PROGRAM %04x: ", m_slot->getSlotID(), session_nb, program_number);
	for (std::vector<uint16_t>::iterator it = pids.begin(); it != pids.end(); ++it)
		eDebugNoNewLine("%02x ", *it);
	eDebugNoNewLine("\n");

	for (std::vector<uint16_t>::iterator it = pids.begin(); it != pids.end(); ++it)
		descrambler_set_pid(m_descrambler_fd, m_slot, 1, *it);
}

void eDVBCICcSession::removeProgram(uint16_t program_number, std::vector<uint16_t> &pids)
{
	eDebugNoNewLineStart("[CI%d CC] SESSION(%d)/REMOVE PROGRAM %04x: ", m_slot->getSlotID(), session_nb, program_number);
	for (std::vector<uint16_t>::iterator it = pids.begin(); it != pids.end(); ++it)
		eDebugNoNewLine("%02x ", *it);
	eDebugNoNewLine("\n");

	for (std::vector<uint16_t>::iterator it = pids.begin(); it != pids.end(); ++it)
		descrambler_set_pid(m_descrambler_fd, m_slot, 0, *it);

	if (m_slot->getDescramblingOptions() == 1 || m_slot->getDescramblingOptions() == 3)
		descrambler_deinit(m_descrambler_fd);
}

void eDVBCICcSession::cc_open_req()
{
	const uint8_t tag[3] = {0x9f, 0x90, 0x02};
	const uint8_t bitmap = 0x01;
	send(tag, &bitmap, 1);
}

void eDVBCICcSession::cc_data_req(const uint8_t *data, unsigned int len)
{
	uint8_t cc_data_cnf_tag[3] = {0x9f, 0x90, 0x04};
	uint8_t dest[BUFSIZ];
	int dt_nr;
	int id_bitmask;
	int answ_len;
	unsigned int rp = 0;

	if (len < 2)
	{
		eWarning("[CI%d RCC] cc_data_req too short data", m_slot->getSlotID());
		return;
	}

	id_bitmask = data[rp++];

	dt_nr = data[rp++];
	rp += data_get_loop(&data[rp], len - rp, dt_nr);

	if (len < rp + 1)
		return;

	dt_nr = data[rp++];

	unsigned int dest_len = sizeof(dest);
	if (dest_len < 2)
	{
		eWarning("[CI%d RCC] cc_data_req not enough space", m_slot->getSlotID());
		return;
	}

	dest[0] = id_bitmask;
	dest[1] = dt_nr;

	answ_len = data_req_loop(&dest[2], dest_len - 2, &data[rp], len - rp, dt_nr);
	if (answ_len <= 0)
	{
		eWarning("[CI%d RCC] cc_data_req can not get data", m_slot->getSlotID());
		return;
	}

	answ_len += 2;

	send(cc_data_cnf_tag, dest, answ_len);
}

void eDVBCICcSession::cc_sync_req(const uint8_t *data, unsigned int len)
{
	const uint8_t tag[3] = {0x9f, 0x90, 0x06};
	const uint8_t status = 0x00; /* OK */

	send(tag, &status, 1);
}

void eDVBCICcSession::cc_sac_data_req(const uint8_t *data, unsigned int len)
{
    const uint8_t data_cnf_tag[3] = {0x9f, 0x90, 0x08};
    uint8_t dest[BUFSIZ];
    uint8_t tmp[len];
    int id_bitmask, dt_nr;
    unsigned int serial;
    int answ_len;
    int pos = 0;
    unsigned int rp = 0;

    if (len < 10)
        return;

    eTraceNoNewLineStart("[CI%d RCC] cc_sac_data_req: ", m_slot->getSlotID());
    traceHexdump(data, len);

    // Decrypt the data using EVP interface
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        eWarning("[CI%d RCC] Failed to create EVP_CIPHER_CTX", m_slot->getSlotID());
        return;
    }

    uint8_t key[16], iv[16]; // Replace these with actual key and IV
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
    {
        eWarning("[CI%d RCC] EVP_DecryptInit_ex failed", m_slot->getSlotID());
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len = 0, final_len = 0;

    if (EVP_DecryptUpdate(ctx, tmp, &out_len, data, len) != 1)
    {
        eWarning("[CI%d RCC] EVP_DecryptUpdate failed", m_slot->getSlotID());
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptFinal_ex(ctx, tmp + out_len, &final_len) != 1)
    {
        eWarning("[CI%d RCC] EVP_DecryptFinal_ex failed", m_slot->getSlotID());
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);

    unsigned int decrypted_len = out_len + final_len;
    eDebug("[CI%d RCC] Decrypted data length: %u", m_slot->getSlotID(), decrypted_len);

    if (!sac_check_auth(tmp, decrypted_len))
    {
        eWarning("[CI%d RCC] cc_sac_data_req check_auth of message failed", m_slot->getSlotID());
        return;
    }

    serial = UINT32(&tmp[rp], 4);
    eDebug("[CI%d RCC] cc_sac_data_req serial %u\n", m_slot->getSlotID(), serial);

    /* skip serial & header */
    rp += 8;

    id_bitmask = tmp[rp++];

    /* handle data loop */
    dt_nr = tmp[rp++];
    rp += data_get_loop(&tmp[rp], decrypted_len - rp, dt_nr);

    if (decrypted_len < rp + 1)
    {
        eWarning("[CI%d RCC] cc_sac_data_req check_auth of message too short", m_slot->getSlotID());
        return;
    }

    dt_nr = tmp[rp++];

    /* create answer */
    unsigned int dest_len = sizeof(dest);

    if (dest_len < 10)
    {
        eWarning("[CI%d RCC] cc_sac_data_req not enough space", m_slot->getSlotID());
        return;
    }

    pos += BYTE32(&dest[pos], serial);
    pos += BYTE32(&dest[pos], 0x01000000);

    dest[pos++] = id_bitmask;
    dest[pos++] = dt_nr; /* dt_nbr */

    answ_len = data_req_loop(&dest[pos], dest_len - 10, &tmp[rp], decrypted_len - rp, dt_nr);
    if (answ_len <= 0)
    {
        eWarning("[CI%d RCC] cc_sac_data_req can not get data", m_slot->getSlotID());
        return;
    }
    pos += answ_len;

    cc_sac_send(data_cnf_tag, dest, pos);
}

void eDVBCICcSession::cc_sac_sync_req(const uint8_t *data, unsigned int len)
{
    const uint8_t sync_cnf_tag[3] = {0x9f, 0x90, 0x10};
    uint8_t dest[64];
    unsigned int serial;
    int pos = 0;

    eTraceNoNewLineStart("[CI%d RCC] cc_sac_sync_req: ", m_slot->getSlotID());
    traceHexdump(data, len);

    // Verifica lunghezza minima dei dati
    if (len < 4)
    {
        eWarning("[CI%d RCC] cc_sac_sync_req: data too short", m_slot->getSlotID());
        return;
    }

    // Estrai il seriale dai dati
    serial = UINT32(data, 4);
    eTrace("[CI%d RCC] serial %u\n", m_slot->getSlotID(), serial);

    // Crea la risposta con seriale e stato OK
    pos += BYTE32(&dest[pos], serial);
    pos += BYTE32(&dest[pos], 0x01000000); // Versione o codice risposta
    dest[pos++] = 0; // Stato OK

    // Imposta la chiave per il descrambler
    set_descrambler_key();

    // Invio della risposta con crittografia e autenticazione
    cc_sac_send(sync_cnf_tag, dest, pos);
}

void eDVBCICcSession::cc_sac_send(const uint8_t *tag, uint8_t *data, unsigned int pos)
{
	if (pos < 8)
	{
		eWarning("[CI%d RCC] cc_sac_send: data too short", m_slot->getSlotID());
		return;
	}

    // Padding per allineamento dati (multiplo di 16 byte)
    int padding = add_padding(&data[pos], pos - 8, 16);
    if (padding < 0)
    {
        eWarning("[CI%d RCC] cc_sac_send: padding failed", m_slot->getSlotID());
        return;
    }
    pos += padding;

    // Imposta la lunghezza dell'header
    BYTE16(&data[6], pos - 8);

    // Genera autenticazione del messaggio
    int auth_len = sac_gen_auth(&data[pos], data, pos);
    if (auth_len <= 0)
    {
        eWarning("[CI%d RCC] cc_sac_send: authentication failed", m_slot->getSlotID());
        return;
    }
    pos += auth_len;

    // Crittografia dei dati (AES)
    if (!sac_crypt(&data[8], &data[8], pos - 8, AES_ENCRYPT))
    {
        eWarning("[CI%d RCC] cc_sac_send: encryption failed", m_slot->getSlotID());
        return;
    }

    // Invio del messaggio tramite APDU
    send(tag, data, pos);

	return;
}

int eDVBCICcSession::data_get_loop(const uint8_t *data, unsigned int datalen, unsigned int items)
{
    unsigned int pos = 0;

    for (unsigned int i = 0; i < items; i++)
    {
        // Controllo: ci sono abbastanza dati per leggere dt_id e dt_len?
        if (pos + 3 > datalen)
        {
            eWarning("[CI%d RCC] data_get_loop: insufficient data for element header (item %u)", 
                     m_slot->getSlotID(), i);
            return -1; // Errore: dati insufficienti
        }

        // Lettura di dt_id e dt_len
        int dt_id = data[pos++];
        int dt_len = (data[pos++] << 8) | data[pos++];

        // Controllo: ci sono abbastanza dati per il contenuto dell'elemento?
        if (pos + dt_len > datalen)
        {
            eWarning("[CI%d RCC] data_get_loop: insufficient data for element content (id %d, len %d)", 
                     m_slot->getSlotID(), dt_id, dt_len);
            return -1; // Errore: contenuto incompleto
        }

        // Log per il debug: elemento letto
        eTraceNoNewLineStart("[CI%d RCC] set element id=%d, len=%d: ", 
                             m_slot->getSlotID(), dt_id, dt_len);
        traceHexdump(&data[pos], dt_len);

        // Salvataggio dell'elemento
        if (!m_ci_elements.set(dt_id, &data[pos], dt_len))
        {
            eWarning("[CI%d RCC] data_get_loop: failed to set element id=%d", 
                     m_slot->getSlotID(), dt_id);
            return -1; // Errore: impossibile salvare l'elemento
        }

        // Gestione personalizzata dell'elemento
        data_get_handle_new(dt_id);

		pos += dt_len;
	}

	return pos;
}

int eDVBCICcSession::data_req_loop(uint8_t *dest, unsigned int dest_len, const uint8_t *data, unsigned int data_len, unsigned int items)
{
    unsigned int pos = 0;

    // Verifica che il numero di items non superi la lunghezza dei dati disponibili
    if (items > data_len)
    {
        eWarning("[CI%d RCC] data_req_loop: items count exceeds available data length", m_slot->getSlotID());
        return -1; // Errore, numero di elementi maggiore della lunghezza dei dati
    }

    for (unsigned int i = 0; i < items; i++)
    {
        int dt_id = data[i];

        // Gestisce eventuali azioni necessarie prima di inviare la risposta
        data_req_handle_new(dt_id);

        // Recupera la lunghezza del buffer per l'elemento identificato da dt_id
        unsigned int len = m_ci_elements.get_buf(nullptr, dt_id);

        // Controlla se c'è spazio sufficiente nel buffer di destinazione
        if ((len + 3) > dest_len)
        {
            eWarning("[CI%d RCC] req element %d: not enough space in destination buffer", 
                     m_slot->getSlotID(), dt_id);
            return -1; // Errore, spazio insufficiente nel buffer di destinazione
        }

        // Ottieni il contenuto dell'elemento e inseriscilo nel buffer di destinazione
        len = m_ci_elements.get_req(dest, dt_id);
        if (len > 0)
        {
            // Mostra il contenuto dell'elemento nel log per il debug
            eTraceNoNewLineStart("[CI%d RCC] req element id=%d, len=%d: ", 
                                 m_slot->getSlotID(), dt_id, len - 3);
            traceHexdump(&dest[3], len - 3); // Mostra solo i dati, escludendo i 3 byte di intestazione
        }

        // Aggiorna i puntatori e la lunghezza residua del buffer
        pos += len;
        dest += len;
        dest_len -= len;
    }

    // Restituisce il numero totale di byte scritti nel buffer di destinazione
    return pos;
}

int eDVBCICcSession::data_get_handle_new(unsigned int id)
{
    switch (id)
    {
    case CICAM_BRAND_CERT:
    case DHPM:
    case CICAM_DEV_CERT:
    case SIGNATURE_B:
        // Se i certificati CI sono validi, non fare nulla. Altrimenti, avvia un challenge Diffie-Hellman
        if (check_ci_certificates())
            break;

        // Se i certificati non sono validi, avvia un challenge Diffie-Hellman
        check_dh_challenge();
        break;

    case AUTH_NONCE:
        // Riavvia il challenge Diffie-Hellman se necessario
        restart_dh_challenge();
        break;

    case NS_MODULE:
        // Se si tratta di un modulo NS, genera l'host, la chiave seed, e i parametri di sicurezza
        generate_ns_host();
        generate_key_seed();
        generate_SAK_SEK();
        break;

    case CICAM_ID:
    case KP:
    case KEY_REGISTER:
        // Gestisce nuovi registri di chiavi
        check_new_key();
        break;

    case PROGRAM_NUMBER:
    case URI_MESSAGE:
        // Se l'ID è legato a un programma o a un messaggio URI, genera una conferma URI
        generate_uri_confirm();
        break;

    default:
        // Se l'ID non è gestito, genera un avviso
        eWarning("[CI%d RCC] unhandled id %u", m_slot->getSlotID(), id);
        break;
    }

    return 0;
}

int eDVBCICcSession::data_req_handle_new(unsigned int id)
{
    switch (id)
    {
    case AKH:
    {
        uint8_t akh[32], host_id[8];

        memset(akh, 0, sizeof(akh));

        if (m_akh_index != 5)
        {
            if (!get_authdata(host_id, m_dhsk, akh, m_slot->getSlotID(), m_akh_index++))
                m_akh_index = 5;

            if (!m_ci_elements.set(AKH, akh, 32))
                eWarning("[CI%d RCC] can not set AKH in elements", m_slot->getSlotID());

            if (!m_ci_elements.set(HOST_ID, host_id, 8))
                eWarning("[CI%d RCC] can not set host_id in elements", m_slot->getSlotID());
        }
        break;
    }
    case CRITICAL_SEC_UPDATE:
    {
        uint8_t csu[1];
        csu[0] = 0x00;
        m_ci_elements.set(CRITICAL_SEC_UPDATE, csu, 1);
        break;
    }
    default:
        break;
    }

    return 0;
}
int eDVBCICcSession::generate_akh()
{
	uint8_t akh[32];
	SHA256_CTX sha;

	SHA256_Init(&sha);
	SHA256_Update(&sha, m_ci_elements.get_ptr(CICAM_ID), m_ci_elements.get_buf(NULL, CICAM_ID));
	SHA256_Update(&sha, m_ci_elements.get_ptr(HOST_ID), m_ci_elements.get_buf(NULL, HOST_ID));
	SHA256_Update(&sha, m_dhsk, 256);
	SHA256_Final(akh, &sha);

	m_ci_elements.set(AKH, akh, sizeof(akh));

	return 0;
}

int eDVBCICcSession::compute_dh_key()
{
	int len = DH_size(m_dh);
	if (len > 256)
	{
		eWarning("[CI%d RCC] too long shared key", m_slot->getSlotID());
		return -1;
	}

	BIGNUM *bn_in = BN_bin2bn(m_ci_elements.get_ptr(DHPM), 256, NULL);

#if 0
	// verify DHPM
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *out = BN_new();

	if (BN_cmp(BN_value_one(), bn_in) >= 0)
		eWarning("[CI%d RCC] DHPM <= 1!!!", m_slot->getSlotID());

	if (BN_cmp(bn_in, m_dh->p) >= 0)
		eWarning("[CI%d RCC] DHPM >= dh_p!!!", m_slot->getSlotID());

	BN_mod_exp(out, bn_in, m_dh->q, m_dh->p, ctx);
	if (BN_cmp(out, BN_value_one()) != 0)
		eWarning("[CI%d RCC] DHPM ^ dh_q mod dh_p != 1!!!", m_slot->getSlotID());

	BN_free(out);
	BN_CTX_free(ctx);
#endif

	int codes = 0;
	int ok = DH_check_pub_key(m_dh, bn_in, &codes);
	if (ok == 0)
		eDebug("[CI%d RCC] check_pub_key failed", m_slot->getSlotID());
	if (codes & DH_CHECK_PUBKEY_TOO_SMALL)
		eDebug("[CI%d RCC] too small public key", m_slot->getSlotID());
	if (codes & DH_CHECK_PUBKEY_TOO_LARGE)
		eDebug("[CI%d RCC] too large public key", m_slot->getSlotID());

	int gap = 256 - len;
	memset(m_dhsk, 0, gap);
	DH_compute_key(m_dhsk + gap, bn_in, m_dh);

	BN_free(bn_in);

	return 0;
}

bool eDVBCICcSession::check_dh_challenge()
{
	if (!m_ci_elements.valid(AUTH_NONCE))
		return false;

	if (!m_ci_elements.valid(CICAM_ID))
		return false;

	if (!m_ci_elements.valid(DHPM))
		return false;

	if (!m_ci_elements.valid(SIGNATURE_B))
		return false;

	compute_dh_key();
	generate_akh();

	m_akh_index = 5;

	eDebug("[CI%d RCC] writing...", m_slot->getSlotID());
	write_authdata(m_slot->getSlotID(), m_ci_elements.get_ptr(HOST_ID), m_dhsk, m_ci_elements.get_ptr(AKH));

	return true;
}

int eDVBCICcSession::generate_dh_key()
{
	uint8_t dhph[256];
	int len;
	unsigned int gap;
	BIGNUM *p, *g, *q;
	const BIGNUM *pub_key;

	m_dh = DH_new();

	p = BN_bin2bn(m_dh_p, sizeof(m_dh_p), 0);
	g = BN_bin2bn(m_dh_g, sizeof(m_dh_g), 0);
	q = BN_bin2bn(m_dh_q, sizeof(m_dh_q), 0);
	DH_set0_pqg(m_dh, p, q, g);
	DH_set_flags(m_dh, DH_FLAG_NO_EXP_CONSTTIME);

	DH_generate_key(m_dh);

	DH_get0_key(m_dh, &pub_key, NULL);
	len = BN_num_bytes(pub_key);
	if (len > 256)
	{
		eWarning("[CI%d RCC] too long public key", m_slot->getSlotID());
		return -1;
	}

#if 0
	// verify DHPH
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *out = BN_new();

	if (BN_cmp(BN_value_one(), m_dh->pub_key) >= 0)
		eWarning("[CI%d RCC] DHPH <= 1!!!", m_slot->getSlotID());
	if (BN_cmp(m_dh->pub_key, m_dh->p) >= 0)
		eWarning("[CI%d RCC] DHPH >= dh_p!!!", m_slot->getSlotID());
	BN_mod_exp(out, m_dh->pub_key, m_dh->q, m_dh->p, ctx);
	if (BN_cmp(out, BN_value_one()) != 0)
		eWarning("[CI%d RCC] DHPH ^ dh_q mod dh_p != 1!!!", m_slot->getSlotID());

	BN_free(out);
	BN_CTX_free(ctx);
#endif

	gap = 256 - len;
	memset(dhph, 0, gap);
	BN_bn2bin(pub_key, &dhph[gap]);

	m_ci_elements.set(DHPH, dhph, sizeof(dhph));

	return 0;
}

int eDVBCICcSession::generate_sign_A()
{
	unsigned char dest[302];
	uint8_t hash[20];
	unsigned char dbuf[256];
	unsigned char sign_A[256];

	if (!m_ci_elements.valid(AUTH_NONCE))
		return -1;

	if (!m_ci_elements.valid(DHPH))
		return -1;

	dest[0x00] = 0x00; /* version */
	dest[0x01] = 0x00;
	dest[0x02] = 0x08; /* len (bits) */
	dest[0x03] = 0x01; /* version data */

	dest[0x04] = 0x01; /* msg_label */
	dest[0x05] = 0x00;
	dest[0x06] = 0x08; /* len (bits) */
	dest[0x07] = 0x02; /* message data */

	dest[0x08] = 0x02; /* auth_nonce */
	dest[0x09] = 0x01;
	dest[0x0a] = 0x00; /* len (bits) */
	memcpy(&dest[0x0b], m_ci_elements.get_ptr(AUTH_NONCE), 32);

	dest[0x2b] = 0x04; /* DHPH */
	dest[0x2c] = 0x08;
	dest[0x2d] = 0x00; /* len (bits) */
	memcpy(&dest[0x2e], m_ci_elements.get_ptr(DHPH), 256);

	SHA1(dest, 0x12e, hash);

	m_rsa_device_key = rsa_privatekey_open("/etc/ciplus/device.pem");
	if (!m_rsa_device_key)
	{
		eWarning("[CI%d RCC] can not read private key", m_slot->getSlotID());
		return -1;
	}

	RSA_padding_add_PKCS1_PSS(m_rsa_device_key, dbuf, hash, EVP_sha1(), 20);
	RSA_private_encrypt(sizeof(dbuf), dbuf, sign_A, m_rsa_device_key, RSA_NO_PADDING);

	m_ci_elements.set(SIGNATURE_A, sign_A, sizeof(sign_A));

	return 0;
}

int eDVBCICcSession::restart_dh_challenge()
{
	if (!m_ci_elements.valid(AUTH_NONCE))
		return -1;

	// eDebug("[CI%d RCC] rechecking...", m_slot->getSlotID());

	m_root_ca_store = X509_STORE_new();
	if (!m_root_ca_store)
	{
		eWarning("[CI%d RCC] can not create root_ca", m_slot->getSlotID());
		return -1;
	}

	if (X509_STORE_load_locations(m_root_ca_store, "/etc/ciplus/root.pem", NULL) != 1)
	{
		eWarning("[CI%d RCC] can not load root_ca", m_slot->getSlotID());
		return -1;
	}

	m_cust_cert = certificate_load_and_check(m_root_ca_store, "/etc/ciplus/customer.pem");
	m_device_cert = certificate_load_and_check(m_root_ca_store, "/etc/ciplus/device.pem");

	if (!m_cust_cert || !m_device_cert)
	{
		eWarning("[CI%d RCC] can not check loader certificates", m_slot->getSlotID());
		return -1;
	}

	if (!ci_element_set_certificate(HOST_BRAND_CERT, m_cust_cert))
		eWarning("[CI%d RCC] can not store brand certificate", m_slot->getSlotID());

	if (!ci_element_set_certificate(HOST_DEV_CERT, m_device_cert))
		eWarning("[CI%d RCC] can not store device certificate", m_slot->getSlotID());

	if (!ci_element_set_hostid_from_certificate(HOST_ID, m_device_cert))
		eWarning("[CI%d RCC] can not store HOST_ID", m_slot->getSlotID());

	m_ci_elements.invalidate(CICAM_ID);
	m_ci_elements.invalidate(DHPM);
	m_ci_elements.invalidate(SIGNATURE_B);
	m_ci_elements.invalidate(AKH);

	generate_dh_key();
	generate_sign_A();

	return 0;
}

int eDVBCICcSession::generate_uri_confirm()
{
	SHA256_CTX sha;
	uint8_t uck[32];
	uint8_t uri_confirm[32];

	// eDebug("[CI%d RCC] uri_confirm...", m_slot->getSlotID());

	// UCK
	SHA256_Init(&sha);
	SHA256_Update(&sha, m_sak, 16);
	SHA256_Final(uck, &sha);

	// uri_confirm
	SHA256_Init(&sha);
	SHA256_Update(&sha, m_ci_elements.get_ptr(URI_MESSAGE), m_ci_elements.get_buf(NULL, URI_MESSAGE));
	SHA256_Update(&sha, uck, 32);
	SHA256_Final(uri_confirm, &sha);

	m_ci_elements.set(URI_CONFIRM, uri_confirm, 32);

	return 0;
}

void eDVBCICcSession::check_new_key()
{
	AES_KEY aes_ctx;
	uint8_t dec[32];
	uint8_t *kp;
	uint8_t slot;
	unsigned int i;

	if (!m_ci_elements.valid(KP))
		return;

	if (!m_ci_elements.valid(KEY_REGISTER))
		return;

	// eDebug("[CI%d RCC] key checking...", m_slot->getSlotID());

	kp = m_ci_elements.get_ptr(KP);
	m_ci_elements.get_buf(&slot, KEY_REGISTER);

	AES_set_encrypt_key(m_s_key, 128, &aes_ctx);
	for (i = 0; i < 32; i += 16)
		AES_ecb_encrypt(&kp[i], &dec[i], &aes_ctx, 1);

	for (i = 0; i < 32; i++)
		dec[i] ^= kp[i];

	if (slot != 0 && slot != 1)
		slot = 1;

	memcpy(m_descrambler_key_iv, dec, 32);
	m_descrambler_odd_even = slot;
	m_descrambler_new_key = true;

	eDVBCIInterfaces::getInstance()->revertCIPlusRouting(m_slot->getSlotID());

	m_ci_elements.invalidate(KP);
	m_ci_elements.invalidate(KEY_REGISTER);
}

/* Opens /dev/caX device if it's not open yet.
 * If ca demux has changed close current /dev/caX device and open new ca device.
 * Sets new key or old one if /dev/caX device has changed */
void eDVBCICcSession::set_descrambler_key()
{
	eDebug("[CI%d RCC] set_descrambler_key", m_slot->getSlotID());
	bool set_key = (m_current_ca_demux_id != m_slot->getCADemuxID()) || (m_slot->getTunerNum() > 7);

	if (m_descrambler_fd != -1 && m_current_ca_demux_id != m_slot->getCADemuxID())
	{
		descrambler_deinit(m_descrambler_fd);
		m_descrambler_fd = descrambler_init(m_slot, m_slot->getCADemuxID());
		m_current_ca_demux_id = m_slot->getCADemuxID();
	}

	if (m_descrambler_fd == -1 && m_slot->getCADemuxID() > -1)
	{
		m_descrambler_fd = descrambler_init(m_slot, m_slot->getCADemuxID());
		m_current_ca_demux_id = m_slot->getCADemuxID();
	}

	if (m_descrambler_fd != -1 && (set_key || m_descrambler_new_key))
	{
		eDebug("[CI%d RCC] setting key: new ca device: %d, new key: %d", m_slot->getSlotID(), set_key, m_descrambler_new_key);
		descrambler_set_key(m_descrambler_fd, m_slot, m_descrambler_odd_even, m_descrambler_key_iv);
		if (m_descrambler_new_key)
		{
			m_descrambler_new_key = false;
		}
	}
}

void eDVBCICcSession::generate_key_seed()
{
	SHA256_CTX sha;

	SHA256_Init(&sha);
	SHA256_Update(&sha, &m_dhsk[240], 16);
	SHA256_Update(&sha, m_ci_elements.get_ptr(AKH), m_ci_elements.get_buf(NULL, AKH));
	SHA256_Update(&sha, m_ci_elements.get_ptr(NS_HOST), m_ci_elements.get_buf(NULL, NS_HOST));
	SHA256_Update(&sha, m_ci_elements.get_ptr(NS_MODULE), m_ci_elements.get_buf(NULL, NS_MODULE));
	SHA256_Final(m_ks_host, &sha);
}

void eDVBCICcSession::generate_ns_host()
{
	uint8_t buf[8];
	get_random(buf, sizeof(buf));
	m_ci_elements.set(NS_HOST, buf, sizeof(buf));
}

int eDVBCICcSession::generate_SAK_SEK()
{
	AES_KEY key;
	uint8_t dec[32];
	int i;

	AES_set_encrypt_key(m_key_data, 128, &key);

	for (i = 0; i < 2; i++)
		AES_ecb_encrypt(&m_ks_host[16 * i], &dec[16 * i], &key, 1);

	for (i = 0; i < 16; i++)
		m_sek[i] = m_ks_host[i] ^ dec[i];

	for (i = 0; i < 16; i++)
		m_sak[i] = m_ks_host[16 + i] ^ dec[16 + i];

	return 0;
}

bool eDVBCICcSession::sac_check_auth(const uint8_t *data, unsigned int len)
{
	struct aes_xcbc_mac_ctx ctx = {};
	uint8_t calced_signature[16];

	if (len < 16)
	{
		eWarning("[CI%d RCC] signature too short", m_slot->getSlotID());
		return false;
	}

	aes_xcbc_mac_init(&ctx, m_sak);
	aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1); /* header len */
	aes_xcbc_mac_process(&ctx, data, len - 16);
	aes_xcbc_mac_done(&ctx, calced_signature);

	if (memcmp(&data[len - 16], calced_signature, 16))
	{
		eWarning("[CI%d RCC] signature wrong", m_slot->getSlotID());
		return false;
	}

	// eDebug("[CI RCC] auth ok!");

	return true;
}

int eDVBCICcSession::sac_gen_auth(uint8_t *out, uint8_t *in, unsigned int len)
{
	struct aes_xcbc_mac_ctx ctx = {};

	aes_xcbc_mac_init(&ctx, m_sak);
	aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1); /* header len */
	aes_xcbc_mac_process(&ctx, in, len);
	aes_xcbc_mac_done(&ctx, out);

	return 16;
}

int eDVBCICcSession::sac_crypt(uint8_t *dst, const uint8_t *src, unsigned int len, int encrypt)
{
	AES_KEY key;
	uint8_t iv[16];
	memcpy(iv, m_iv, 16); // use copy as iv is changed by AES_cbc_encrypt

	if (encrypt)
		AES_set_encrypt_key(m_sek, 128, &key);
	else
		AES_set_decrypt_key(m_sek, 128, &key);

	AES_cbc_encrypt(src, dst, len, &key, iv, encrypt);

	return 0;
}

X509 *eDVBCICcSession::import_ci_certificates(unsigned int id)
{
	X509 *cert;

	if (!m_ci_elements.valid(id))
	{
		eWarning("[CI%d RCC] %u not valid", m_slot->getSlotID(), id);
		return NULL;
	}

	cert = certificate_import_and_check(m_root_ca_store, m_ci_elements.get_ptr(id), m_ci_elements.get_buf(NULL, id));
	if (!cert)
	{
		eWarning("[CI%d RCC] can not verify certificate %u", m_slot->getSlotID(), id);
		return NULL;
	}

	return cert;
}

int eDVBCICcSession::check_ci_certificates()
{
	if (!m_ci_elements.valid(CICAM_BRAND_CERT))
		return -1;

	if (!m_ci_elements.valid(CICAM_DEV_CERT))
		return -1;

	if ((m_ci_cust_cert = import_ci_certificates(CICAM_BRAND_CERT)) == NULL)
	{
		eWarning("[CI%d RCC] can not import CICAM brand certificate", m_slot->getSlotID());
		return -1;
	}

	if ((m_ci_device_cert = import_ci_certificates(CICAM_DEV_CERT)) == NULL)
	{
		eWarning("[CI%d RCC] can not import CICAM device certificate", m_slot->getSlotID());
		return -1;
	}

	if (!ci_element_set_hostid_from_certificate(CICAM_ID, m_ci_device_cert))
	{
		eWarning("[CI%d RCC] can not store CICAM_ID", m_slot->getSlotID());
		return -1;
	}

	return 0;
}

bool eDVBCICcSession::ci_element_set_certificate(unsigned int id, X509 *cert)
{
	unsigned char *cert_der = NULL;
	int cert_len;

	cert_len = i2d_X509(cert, &cert_der);
	if (cert_len <= 0)
	{
		eWarning("[CI%d RCC] can not encode certificate", m_slot->getSlotID());
		return false;
	}

	if (!m_ci_elements.set(id, cert_der, cert_len))
	{
		eWarning("[CI%d RCC] can not store certificate id %u", m_slot->getSlotID(), id);
		return false;
	}

	OPENSSL_free(cert_der);

	return true;
}

bool eDVBCICcSession::ci_element_set_hostid_from_certificate(unsigned int id, X509 *cert)
{
	X509_NAME *subject;
	char hostid[16 + 1];
	uint8_t bin_hostid[8];

	if ((id != 5) && (id != 6))
	{
		eWarning("[CI%d RCC] wrong datatype_id %u for device id", m_slot->getSlotID(), id);
		return false;
	}

	subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subject, NID_commonName, hostid, sizeof(hostid));

	if (strlen(hostid) != 16)
	{
		eWarning("[CI%d RCC] bad device id", m_slot->getSlotID());
		return false;
	}

	// eDebug("[CI%d RCC] DEVICE_ID: %s", m_slot->getSlotID(), hostid);

	str2bin(bin_hostid, hostid, 16);

	if (!m_ci_elements.set(id, bin_hostid, sizeof(bin_hostid)))
	{
		eWarning("[CI%d RCC] can not store device id %u", m_slot->getSlotID(), id);
		return false;
	}

	return true;
}
