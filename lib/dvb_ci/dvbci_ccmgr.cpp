/* DVB CI Content Control Manager */

#include <lib/dvb_ci/dvbci_ccmgr.h>

#include <lib/dvb_ci/dvbci.h>
#include <lib/dvb_ci/aes_xcbc_mac.h>
#include <lib/dvb_ci/descrambler.h>
#include <lib/dvb_ci/dvbci_ccmgr_helper.h>
#include <openssl/aes.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <cstring> // Per memset
#include "eDVBCISlot.h" // Includi il file della classe
#include "eDVBCICcSession.h" // Includi il file header della classe

eDVBCICcSession::eDVBCICcSession(eDVBCISlot *slot, int version)
    : m_slot(slot), m_akh_index(0),
      m_root_ca_store(nullptr), m_cust_cert(nullptr), m_device_cert(nullptr),
      m_ci_cust_cert(nullptr), m_ci_device_cert(nullptr),
      m_rsa_device_key(nullptr), m_dh_key(nullptr) // Usando EVP_PKEY al posto di DH*
{
    uint8_t buf[32], host_id[8];

    m_slot->setCCManager(this);
    m_descrambler_fd = -1;
    m_current_ca_demux_id = 0;
    m_descrambler_new_key = false;

    // Funzione per inizializzare i parametri
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
    m_slot->setCCManager(nullptr);

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
    if (m_rsa_device_key)
        RSA_free(m_rsa_device_key);
    if (m_dh_key)
        EVP_PKEY_free(m_dh_key); // Libera la chiave DH usando la nuova API

    m_ci_elements.init();
}

// Metodo per generare la chiave DH utilizzando la nuova API
void eDVBCICcSession::generate_dh_key()
{
    // Usa EVP_PKEY per generare una chiave DH
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (!ctx)
    {
        eError("Error creating EVP_PKEY_CTX for DH key generation.");
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        eError("Error initializing DH keygen.");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_keygen(ctx, &m_dh_key) <= 0)
    {
        eError("Error generating DH key.");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    EVP_PKEY_CTX_free(ctx);
}

// Metodo per calcolare la chiave condivisa DH
int eDVBCICcSession::compute_dh_key()
{
    if (!m_dh_key)
    {
        eError("DH key not initialized.");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(m_dh_key, nullptr);
    if (!ctx)
    {
        eError("Error creating EVP_PKEY_CTX for DH key computation.");
        return -1;
    }

    uint8_t shared_key[256];
    size_t shared_key_len = sizeof(shared_key);

    if (EVP_PKEY_derive(ctx, shared_key, &shared_key_len) <= 0)
    {
        eError("Error deriving DH shared key.");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// Modifica delle funzioni di hashing con SHA256
void eDVBCICcSession::generate_sign_A()
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    if (!md_ctx)
    {
        eError("Error creating EVP_MD_CTX for SHA256.");
        return;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) <= 0)
    {
        eError("Error initializing SHA256.");
        EVP_MD_CTX_free(md_ctx);
        return;
    }

    if (EVP_DigestUpdate(md_ctx, m_s_key, sizeof(m_s_key)) <= 0)
    {
        eError("Error updating SHA256.");
        EVP_MD_CTX_free(md_ctx);
        return;
    }

    if (EVP_DigestFinal_ex(md_ctx, hash, nullptr) <= 0)
    {
        eError("Error finalizing SHA256.");
        EVP_MD_CTX_free(md_ctx);
        return;
    }

    EVP_MD_CTX_free(md_ctx);

    // Usa RSA per la firma
    if (RSA_padding_add_PKCS1_PSS(m_rsa_device_key, hash, EVP_sha256(), 32) <= 0)
    {
        eError("Error padding RSA PSS.");
        return;
    }

    uint8_t signature[256];
    if (RSA_private_encrypt(sizeof(hash), hash, signature, m_rsa_device_key, RSA_NO_PADDING) <= 0)
    {
        eError("Error encrypting with RSA.");
        return;
    }

    // Aggiungi la firma al campo appropriato
    // ...
}

void eDVBCICcSession::check_new_key()
{
    AES_KEY aes_ctx;
    if (AES_set_encrypt_key(m_s_key, 128, &aes_ctx) != 0)
    {
        eError("Error setting AES encryption key.");
        return;
    }

    uint8_t enc_data[128]; // Dati cifrati
    AES_ecb_encrypt(m_key_data, enc_data, &aes_ctx, AES_ENCRYPT);
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

	memcpy(tmp, data, 8);
	sac_crypt(&tmp[8], &data[8], len - 8, AES_DECRYPT);
	data = tmp;

	if (!sac_check_auth(data, len))
	{
		eWarning("[CI%d RCC] cc_sac_data_req check_auth of message failed", m_slot->getSlotID());
		return;
	}

	serial = UINT32(&data[rp], 4);
	eDebug("[CI%d RCC] cc_sac_data_req serial %u\n", m_slot->getSlotID(), serial);

	/* skip serial & header */
	rp += 8;

	id_bitmask = data[rp++];

	/* handle data loop */
	dt_nr = data[rp++];
	rp += data_get_loop(&data[rp], len - rp, dt_nr);

	if (len < rp + 1)
	{
		eWarning("[CI%d RCC] cc_sac_data_req check_auth of message too short", m_slot->getSlotID());
		return;
	}

	dt_nr = data[rp++];

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

	answ_len = data_req_loop(&dest[pos], dest_len - 10, &data[rp], len - rp, dt_nr);
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

	serial = UINT32(data, 4);
	eTrace("[CI%d RCC] serial %u\n", m_slot->getSlotID(), serial);

	pos += BYTE32(&dest[pos], serial);
	pos += BYTE32(&dest[pos], 0x01000000);

	/* status OK */
	dest[pos++] = 0;

	set_descrambler_key();

	cc_sac_send(sync_cnf_tag, dest, pos);
}

void eDVBCICcSession::cc_sac_send(const uint8_t *tag, uint8_t *data, unsigned int pos)
{
	if (pos < 8)
	{
		eWarning("[CI%d RCC] cc_sac_send too short data", m_slot->getSlotID());
		return;
	}

	pos += add_padding(&data[pos], pos - 8, 16);
	BYTE16(&data[6], pos - 8); /* len in header */

	pos += sac_gen_auth(&data[pos], data, pos);
	sac_crypt(&data[8], &data[8], pos - 8, AES_ENCRYPT);

	send(tag, data, pos);

	return;
}

int eDVBCICcSession::data_get_loop(const uint8_t *data, unsigned int datalen, unsigned int items)
{
	unsigned int i;
	int dt_id, dt_len;
	unsigned int pos = 0;

	for (i = 0; i < items; i++)
	{
		if (pos + 3 > datalen)
			return 0;

		dt_id = data[pos++];
		dt_len = data[pos++] << 8;
		dt_len |= data[pos++];

		if (pos + dt_len > datalen)
			return 0;

		eTraceNoNewLineStart("[CI%d RCC] set element %d: ", m_slot->getSlotID(), dt_id);
		traceHexdump(&data[pos], dt_len);

		m_ci_elements.set(dt_id, &data[pos], dt_len);

		data_get_handle_new(dt_id);

		pos += dt_len;
	}

	return pos;
}

int eDVBCICcSession::data_req_loop(uint8_t *dest, unsigned int dest_len, const uint8_t *data, unsigned int data_len, unsigned int items)
{
	int dt_id;
	unsigned int i;
	int pos = 0;
	unsigned int len;

	if (items > data_len)
		return -1;

	for (i = 0; i < items; i++)
	{
		dt_id = data[i];
		data_req_handle_new(dt_id); /* check if there is any action needed before we answer */

		len = m_ci_elements.get_buf(NULL, dt_id);
		if ((len + 3) > dest_len)
		{
			eWarning("[CI%d RCC] req element %d: not enough space", m_slot->getSlotID(), dt_id);
			return -1;
		}

		len = m_ci_elements.get_req(dest, dt_id);
		if (len > 0)
		{
			eTraceNoNewLineStart("[CI%d RCC] req element %d: ", m_slot->getSlotID(), dt_id);
			traceHexdump(&dest[3], len - 3);
		}

		pos += len;
		dest += len;
		dest_len -= len;
	}

	return pos;
}

int eDVBCICcSession::data_get_handle_new(unsigned int id)
{
	switch (id)
	{
	case CICAM_BRAND_CERT:
	case DHPM:
	case CICAM_DEV_CERT:
		//		case CICAM_ID:
	case SIGNATURE_B:
		if (check_ci_certificates())
			break;

		check_dh_challenge();
		break;

	case AUTH_NONCE:
		restart_dh_challenge();
		break;

	case NS_MODULE:
		generate_ns_host();
		generate_key_seed();
		generate_SAK_SEK();
		break;

	case CICAM_ID:
	case KP:
	case KEY_REGISTER:
		check_new_key();
		break;

	case PROGRAM_NUMBER:
	case URI_MESSAGE:
		generate_uri_confirm();
		break;

	default:
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
    uint8_t akh[32];  // Array per memorizzare l'AKH
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Crea un contesto per l'hash

    if (mdctx == NULL) {
        // Gestisci l'errore se non è stato possibile creare il contesto
        return -1;
    }

    // Inizializza il contesto con SHA-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);  // Libera il contesto in caso di errore
        return -1;
    }

    // Aggiungi i dati al digest
    EVP_DigestUpdate(mdctx, m_ci_elements.get_ptr(CICAM_ID), m_ci_elements.get_buf(NULL, CICAM_ID));
    EVP_DigestUpdate(mdctx, m_ci_elements.get_ptr(HOST_ID), m_ci_elements.get_buf(NULL, HOST_ID));
    EVP_DigestUpdate(mdctx, m_dhsk, 256);

    // Calcola il risultato e memorizzalo in `akh`
    unsigned int len;
    if (EVP_DigestFinal_ex(mdctx, akh, &len) != 1) {
        EVP_MD_CTX_free(mdctx);  // Libera il contesto in caso di errore
        return -1;
    }

    // Libera il contesto
    EVP_MD_CTX_free(mdctx);

    // Memorizza l'AKH
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
    uint8_t hash[32];  // SHA256 produces a 32-byte hash
    unsigned char dbuf[256];
    unsigned char sign_A[256];

    // Check if required elements are valid
    if (!m_ci_elements.valid(AUTH_NONCE))
        return -1;

    if (!m_ci_elements.valid(DHPH))
        return -1;

    // Fill the destination buffer with data
    dest[0x00] = 0x00;  /* version */
    dest[0x01] = 0x00;
    dest[0x02] = 0x08;  /* len (bits) */
    dest[0x03] = 0x01;  /* version data */

    dest[0x04] = 0x01;  /* msg_label */
    dest[0x05] = 0x00;
    dest[0x06] = 0x08;  /* len (bits) */
    dest[0x07] = 0x02;  /* message data */

    dest[0x08] = 0x02;  /* auth_nonce */
    dest[0x09] = 0x01;
    dest[0x0a] = 0x00;  /* len (bits) */
    memcpy(&dest[0x0b], m_ci_elements.get_ptr(AUTH_NONCE), 32);

    dest[0x2b] = 0x04;  /* DHPH */
    dest[0x2c] = 0x08;
    dest[0x2d] = 0x00;  /* len (bits) */
    memcpy(&dest[0x2e], m_ci_elements.get_ptr(DHPH), 256);

    // SHA256 hashing
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, dest, sizeof(dest));
    SHA256_Final(hash, &sha);

    // Open the RSA private key
    m_rsa_device_key = rsa_privatekey_open("/etc/ciplus/device.pem");
    if (!m_rsa_device_key)
    {
        eWarning("[CI%d RCC] can not read private key", m_slot->getSlotID());
        return -1;
    }

    // RSA padding and signing
    RSA_padding_add_PKCS1_PSS(m_rsa_device_key, dbuf, hash, EVP_sha256(), 32);
    RSA_private_encrypt(sizeof(dbuf), dbuf, sign_A, m_rsa_device_key, RSA_NO_PADDING);

    // Set the signature
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
    uint8_t uck[32];
    uint8_t uri_confirm[32];

    EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new(); // Crea un contesto per SHA256
    if (sha_ctx == nullptr) {
        // Gestisci l'errore in caso di fallimento della creazione del contesto
        return -1;
    }

    // Calcolo UCK
    if (EVP_DigestInit_ex(sha_ctx, EVP_sha256(), nullptr) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -2;
    }
    if (EVP_DigestUpdate(sha_ctx, m_sak, 16) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -3;
    }
    if (EVP_DigestFinal_ex(sha_ctx, uck, nullptr) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -4;
    }

    // Calcolo uri_confirm
    if (EVP_DigestInit_ex(sha_ctx, EVP_sha256(), nullptr) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -5;
    }
    if (EVP_DigestUpdate(sha_ctx, m_ci_elements.get_ptr(URI_MESSAGE), m_ci_elements.get_buf(nullptr, URI_MESSAGE)) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -6;
    }
    if (EVP_DigestUpdate(sha_ctx, uck, 32) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -7;
    }
    if (EVP_DigestFinal_ex(sha_ctx, uri_confirm, nullptr) != 1) {
        // Gestisci l'errore
        EVP_MD_CTX_free(sha_ctx);
        return -8;
    }

    EVP_MD_CTX_free(sha_ctx);

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
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Crea un contesto per l'hash

    if (mdctx == NULL) {
        // Gestisci l'errore se non è stato possibile creare il contesto
        return;
    }

    // Inizializza il contesto con SHA-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);  // Libera il contesto in caso di errore
        return;
    }

    // Aggiungi i dati al digest
    EVP_DigestUpdate(mdctx, &m_dhsk[240], 16);
    EVP_DigestUpdate(mdctx, m_ci_elements.get_ptr(AKH), m_ci_elements.get_buf(NULL, AKH));
    EVP_DigestUpdate(mdctx, m_ci_elements.get_ptr(NS_HOST), m_ci_elements.get_buf(NULL, NS_HOST));
    EVP_DigestUpdate(mdctx, m_ci_elements.get_ptr(NS_MODULE), m_ci_elements.get_buf(NULL, NS_MODULE));

    // Calcola il risultato e memorizzalo in `m_ks_host`
    unsigned int len;
    if (EVP_DigestFinal_ex(mdctx, m_ks_host, &len) != 1) {
        EVP_MD_CTX_free(mdctx);  // Libera il contesto in caso di errore
        return;
    }

    // Libera il contesto
    EVP_MD_CTX_free(mdctx);
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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Crea un contesto di cifratura
    if (ctx == nullptr)
    {
        eWarning("[CI%d RCC] Failed to create cipher context", m_slot->getSlotID());
        return -1;
    }

    // Inizializza il contesto di cifratura con AES-128 CBC
    if (encrypt)
    {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, m_sek, m_iv) != 1)
        {
            eWarning("[CI%d RCC] Encryption init failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
    else
    {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, m_sek, m_iv) != 1)
        {
            eWarning("[CI%d RCC] Decryption init failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Buffer temporaneo per i dati cifrati
    int outlen;
    if (encrypt)
    {
        // Esegui la cifratura
        if (EVP_EncryptUpdate(ctx, dst, &outlen, src, len) != 1)
        {
            eWarning("[CI%d RCC] Encryption failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
    else
    {
        // Esegui la decrittazione
        if (EVP_DecryptUpdate(ctx, dst, &outlen, src, len) != 1)
        {
            eWarning("[CI%d RCC] Decryption failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Finalizza la cifratura/decrittazione
    int tmplen;
    if (encrypt)
    {
        if (EVP_EncryptFinal_ex(ctx, dst + outlen, &tmplen) != 1)
        {
            eWarning("[CI%d RCC] Final encryption failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
    else
    {
        if (EVP_DecryptFinal_ex(ctx, dst + outlen, &tmplen) != 1)
        {
            eWarning("[CI%d RCC] Final decryption failed", m_slot->getSlotID());
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Libera il contesto
    EVP_CIPHER_CTX_free(ctx);

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
