/*
 *  sso.h
 *
 *  Isabel SSO - Header file
 *
 *  Copyright 2010 Isabel NV/SA. All rights reserved.
 *
 * 27/11/2014 SECU-2057 As Multiline, I want to warn the user that the Luxtrust certificate will expire
 * 28/01/2015 SECU-2209 Implementation of Mobile SSO flows
 * 11/08/2016 SECU-2671 BISC login
*/


#ifndef _SSO_H_
#define _SSO_H_

#define RSA MY_RSA
#define DSA MY_DSA
#include "trdsec.h"
#include "trdtypes.h"
#undef RSA
#undef DSA

#include <stdint.h>

#define USE_SSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>

/////hhn  #define OS_LINUX
#ifdef WIN32
#define OS_WIN32
#else
#define OS_LINUX
#endif

#include "cryptoki.h"

#if OPENSSL_VERSION_NUMBER >= 0x00908000
#define CUC (const unsigned char **)
#define MOD_EXP_BN_CTX , BN_CTX * bn_ctx
#else
#define CUC /* (unsigned char **) */
#define MOD_EXP_BN_CTX /* no BN_CTX */
#endif

#define CRL_LIFETIME 600 /* 10 minutes */
#define MASTER_COOKIE_LIFETIME 3600 /* one hour */
#define SESSION_COOKIE_LIFETIME 1800

#define MASTER_COOKIE_NAME "SSO-Master"
#define SESSION_COOKIE_NAME "SSO-Session"
#define MAX_COOKIE_NAME 40
#define MAX_LOGOUT_COOKIE 256   // SECU-2134 SSO logout: the domain is truncated

#define ORIGIN_HEADER_NAME "SSO-Origin"
#define CREDENTIALS_HEADER_NAME "SSO-Credentials"
#define APPLICATION_DOMAIN_HEADER_NAME "SSO-ApplicationDomain"
#define ADM_HEADER_NAME "SSO-IsAdmin"
#define ELECTRA_HEADER_NAME "PKI-Userid"
#define USER_TYPE_HEADER_NAME "SSO-UserType"
#define CIS_HEADER_NAME "CIS-Timeout"  /* 1st time master ticket lifetime in minutes */
#define ISA_AUTHORITY_KEYID_NAME "SSO-AuthorityKeyId"
#define OTU_HEADER_NAME "SSO-OTU"    // SECU-2123 Unique Url Authentication Mode for SSO; new header name
#define CERTEXPDATE_HEADER_NAME "SSO-NMLCertExpDate"   // SECU-2057 As Multiline, I want to warn the user that the Luxtrust certificate will expire

// SECU-2209 Implementation of Mobile SSO flows: new http header to be sent to application
#define MOBILE_ACTIVATION_CODE_HEADER_NAME      "SSO-Activation-Code"
#define MOBILE_REGISTRATIONID_HEADER_NAME       "SSO-Registration-ID"
#define MOBILE_AUTENTICATION_METHOD_HEADER_NAME "SSO-Authentication-Method"

#define MASTERID_HEADER_NAME "SSO-MasterId"   // SECU-2209 add unique id (hash of the master ticket)
#define MASTER_COOKIE_LIFETIME_HEADER_NAME "SSO-MasterCookieLifetime" // SECU-2278 add master cookie lifetime HTTP Header

// SECU-2595 Add the header of the contractType
#define CONTRACTTYPE_HEADER_NAME "SSO-ContractType"

#define MAX_CIS_TIMEOUT (10 * 3600)

#define EBANKID_ATTRIBUTE "isaBankId"
#define ALLOWED_ATTRIBUTE "isaAllowed"
#define ELECTRA_ATTRIBUTE "isElectra"
#define WEBSERV_ATTRIBUTE "isWebservice"
#define TOKENSIGNER_ATTRIBUTE "isTokenSigner"
#define INDIRECT_ATTRIBUTE "isaIndirect"
#define ADMIN_ATTRIBUTE "isaIsAdmin"
#define USER_TYPE_ATTRIBUTE "isaUserType"
#define VHOST_NAME_ATTRIBUTE "isaAllowedVHost"

//  SECU-2209 Implementation of Mobile SSO flows: Mobile attribute
#define ATT_MOB_RETRY_LOG "retryCountLogon"
#define ATT_MOB_RETRY_REG "retryCountRegistration"
#define ATT_MOB_BLOCKED "blocked"
#define ATT_MOB_PASSWORD "userPassword"
#define ATT_MOB_ACVTIVATIONID "activationId"
#define ATT_MOB_REGISTRATIONID "registrationId"
#define ATT_MOB_EXPIRED "timeStamp"
#define ATT_MOB_SHARED_SECRET "sharedSecret"
#define ATT_MOB_SDUSPENDED "suspended"

#define ATT_MODTS  "modifyTimestamp"
#define ATT_CACERT "cACertificate"
#define ATT_CROSS  "crossCertificatePair"
#define ATT_ARL    "authorityRevocationList"
#define ATT_CRL    "certificateRevocationList"
#define ATT_CERT   "userCertificate"

/* for slapd */
#define BIN_CACERT "cACertificate;binary"
#define BIN_CROSS  "crossCertificatePair;binary"
#define BIN_ARL    "authorityRevocationList;binary"
#define BIN_CRL    "certificateRevocationList;binary"
#define BIN_CERT   "userCertificate;binary"

/* mod due to firewall dropping packets:
   do every ldap_search with timeout */
#define ldap_timeout 5

#define UPDOWN_TOKEN "token"

#define PDG_ENC "enc="
#define PDG_KEY "&key="
#define PDG_SIG "&sign="
#define PDG_UID "&isauid="

#define MASTER_DATA_OFFSET (uint64_t)&((master_cookie *)0)->data
#define MAX_MASTER_SIZE (sizeof (master_cookie) + 5 * 256)
#define MAX_MASTER_B64  (((MAX_MASTER_SIZE + 2) / 3) * 4 + 1)

#define PATH_LEN 256
#define ADM_LEN 256
#define USER_TYPE_LEN 256
#define VHOST_NAME_LEN 256
#define IP_ADRESS_LEN 60

#define SESSION_DATA_OFFSET (uint64_t)&((session_cookie *)0)->data
#define MAX_SESSION_SIZE (sizeof (session_cookie) + PATH_LEN + VHOST_NAME_LEN + ADM_LEN + USER_TYPE_LEN + IP_ADRESS_LEN)
#define MAX_SESSION_B64  (((MAX_SESSION_SIZE + 2) / 3) * 4 + 1)

#define TRACE_SSO                /* undef for production */
#define LOG_SSO(x,y,z,...) log_sso(x,y,"%s(%d),%s: " z,__FILE__,__LINE__,__FUNCTION__,##__VA_ARGS__);

#ifdef SSO_TESTING
#define NOCACHE_SSO              /* set "Cache-Control: no-cache" for testing; undef for production */
#define SSO_SECURE ""
#else
#undef NOCACHE_SSO
#define SSO_SECURE " secure; httponly;"
#endif

#define USE_UID /* if not defined, use tokenid */

#define SSO_MODE_EBANKING    1
#define SSO_MODE_ELECTRA     2
#define SSO_MODE_UPLOAD      3
#define SSO_MODE_DOWNLOAD    4
#define SSO_MODE_WEBSERVICE  5
#define SSO_MODE_PKIOPERATOR 6
#define SSO_MODE_SECOFF      7
#define SSO_MODE_IDENTIFIED  8
#define SSO_MODE_PDG         9
#define SSO_MODE_CIS         10
#define SSO_MODE_EID         11
#define SSO_MODE_OTU         12         // SECU-2123 Unique Url Authentication Mode for SSO
#define SSO_MODE_MOBILE_ACT  13         // SECU-2209 Mobile activation mode
#define SSO_MODE_MOBILE_LOG  14         // SECU-2209 Mobile logon mode
#define SSO_MODE_LOGIN       15         // SECU-2671 logon mode
#define SSO_MODE_AUTH        16         // SECU-2671 logon mode


#define OTU_URL  "uuid="     // SECU-2123 Unique Url Authentication Mode for SSO; tag of the url
                             // SECU-2273 As Service Hub, I want the OTU Parameter to be changed to uuid

/*
 * Error codes:
 * 1  forbidden path
 * 2  no CRL or CAPK available
 * 3  CRL too old
 * 4  LDAP not available
 * 5  no such object (entry) in LDAP
 * 6  other LDAP error
 * 7  cannot sign cookie (no trd)
 * 8  peer certificate is revoked
 * 9  invalid peer certificate or credentials
 * 10 general failure (internal error, malloc error)
 * 11 certificate is not yet or no longer valid
 * 12 malformed token
 * 13 expired token
 * 14 verification of token signature failed
 * 15 no token
 *
 * The strings sso_ctx.erroraction define which error should redirect to the error page
 * by 200 + html redirect ('0') or a 301 ('1') or 302 ('2') or 303 ('3') with substitution of %d by the error code
 * 'p' simply returns a text/plain page containing NOK=%d
 * anything else or the absence of sso_ctx.errorpage or sso_ctx.erroraction returns FORBIDDEN
 */

#define SSO_ERR_FORBIDDEN  "\001"
#define SSO_ERR_NOCRLORCA  "\002"
#define SSO_ERR_OLDCRL     "\003"
#define SSO_ERR_NOLDAP     "\004"
#define SSO_ERR_NOENTRY    "\005"
#define SSO_ERR_LDAPERR    "\006"
#define SSO_ERR_CANTSIGN   "\007"
#define SSO_ERR_REVOKED    "\010"
#define SSO_ERR_INVALID    "\011"
#define SSO_ERR_FAILURE    "\012"
#define SSO_ERR_EXPIRED    "\013"
#define SSO_ERR_MALFORMED  "\014"
#define SSO_ERR_EXPTOKEN   "\015"
#define SSO_ERR_INVTOKEN   "\016"
#define SSO_ERR_NOTOKEN    "\017"

#define SSO_ERR_MAX          017

#define sso_clear(x) \
memset(&x->sso, 0, sizeof (sso_ctx)); \
x->sso.log_level = -1;

// login_type		SECU-2671 logon mode type of the login page
// login_file		SECU-2671 logon mode local file path to make login
// loginURL)		SECU-2671 logon mode URL for redirect when login is ok
// loginLifetime,0)	SECU-2671 logon mode Max time for login in secondes


#define sso_merge(x) \
cfgMergeString(x.ssl_cid); \
cfgMergeString(x.master_cid); \
cfgMergeString(x.session_cid); \
cfgMergeString(x.ca_dn); \
cfgMerge(x.cas_number,0); \
cfgMerge(x.nb_ldap_ca,0); \
cfgMergeString(x.ldap_ca); \
cfgMergeString(x.ldap_base); \
cfgMergeString(x.ldap_vpn_base); \
cfgMergeString(x.ldap_lux); \
cfgMergeString(x.lux_akids); \
cfgMergeString(x.ssl_pk); \
cfgMergeString(x.master_pk); \
cfgMergeString(x.session_pk); \
cfgMergeString(x.master_cookie); \
cfgMergeString(x.session_cookie); \
cfgMerge(x.master_cookie_lifetime, 0); \
cfgMerge(x.session_cookie_lifetime, 0); \
cfgMergeString(x.domain); \
cfgMergeString(x.path); \
cfgMergeString(x.origin); \
cfgMergeString(x.errorpage); \
cfgMergeString(x.erroraction); \
cfgMergeString(x.ocsp); \
cfgMerge(x.nb_ocsp,0); \
cfgMerge(x.ocspFallback, 0); \
cfgMerge(x.fallbackTimeout, 0); \
cfgMergeString(x.log_path);\
mrg->x.log_file = NULL;\
cfgMergeString(x.xml_path);\
mrg->x.xml_file = NULL;\
cfgMerge(x.log_level, -1);\
cfgMergeString(x.logoff_type);\
cfgMergeString(x.logoff_file);\
cfgMergeString(x.login_type);\
cfgMergeString(x.login_file);\
cfgMergeString(x.loginURL);\
cfgMergeString(x.loginMODE);\
cfgMergeString(x.loginOriginUrl);\
cfgMergeString(x.serverCert);\
cfgMerge(x.serverCertLen, 0);\
cfgMergeString(x.serverSSLCertHash);\
cfgMerge(x.serverSSLCertHashLen, 0);\
cfgMerge(x.loginLifetime,0); \
cfgMergeString(x.cp_oids);\
cfgMerge(x.adm_header, 0);\
cfgMergeString(x.application_domain);\
cfgMerge(x.check_ip_client, 1);

typedef struct res_handle_st
{
	void *res_handle;
	int res_free;
} res_handle_st;

#define MAX_INSTANCE 100

typedef struct sso_ctx_st {
  char *ssl_cid;
  char *master_cid;
  char *session_cid;
  int cas_number;
  char *ca_dn[MAX_INSTANCE];
  int nb_ldap_ca;
  char *ldap_ca[MAX_INSTANCE];
  char *ldap_base;
  char *ldap_vpn_base;
  char *ldap_otu_base;
  char *ldap_lux;
  char *lux_akids;
  EVP_PKEY *ssl_pk;
  EVP_PKEY *master_pk;
  EVP_PKEY *session_pk;
  int master_cookie_lifetime;
  int session_cookie_lifetime;
  char *master_cookie;
  char *session_cookie;
  char *domain;
  char *path;
  char *origin;
  char *errorpage;
  char *erroraction;
  char *ocsp[MAX_INSTANCE];
  int nb_ocsp;
  int  ocspFallback;   // SECU-2056 As Multiline, I want to configure the automatic fallback from OCSP to CRL  int  fallbackTimeout; // SECU-2193 Newml SSO: cannot connect to ebanking in fallback mode
  int  fallbackTimeout; // SECU-2193 Newml SSO: cannot connect to ebanking in fallback mode
  char *hsm_pin;       // SECU-2209 HSM pin to be use to decrypt shared secret and user pin
  char *hsm_mobileKey; // SECU-2209 HSM key name to use for mobile
  int maxMobileErrLog; // SECU-2209 Error count maximum allowed for mobile activation
  int maxMobileErrAct; // SECU-2209 Error count maximum allowed for mobile logon
  int totp_retry;      // SECU-2209 Number maxi of TOTP retry (default value is 0)
  char *log_path;
  void *log_file;
  char *xml_path;
  void *xml_file;
  int log_level;
  char *logoff_type;
  char *logoff_file;
  char *cp_oids;
  int adm_header;
  char *application_domain;
  int check_ip_client;
  char *ldap_user;
  char *ldap_host;
  int ldap_port;
  int ldap_binary;
  char *ldap_pwd;
  int crl_lifetime;
  int crl_gracetime;
  char *login_type;  // SECU-2671 BISC login type
  char *login_file;  // SECU-2671 BISC login html file
  char *serverCert;  // SECU-2671 BISC login: server cert for token generation & verification
  int serverCertLen; // SECU-2671 BISC logon
  char *serverSSLCertHash;
  int serverSSLCertHashLen;
  int loginLifetime; // SECU-2671 BISC logon: lifetime in sec of the authentication token
  char *loginURL;    // SECU-2671 BISC logon: URL for the redirection when user is authenticated
  char *loginMODE;    // SECU-2671 BISC logon: EID or EBANKING
  char *loginOriginUrl;
} sso_ctx;

typedef struct master_st {
  int lifetime;
  char mode;
  char data[1];
  /* origin */
  /* credentials */
  /* path */
  /* ip_client */
  /* signature */
} master_cookie;

typedef struct session_st {
  int lifetime;
  unsigned char master_hash[32];
  char data[1];
  /* path */
  /* host */
  /* adm */
  /* user type */
  /* IP client */
  /* signature */
} session_cookie;

typedef struct {
  char *origin;
  char *credentials;
  char *path;
  char *ip_client;
  /*add new field for identifying client certificate issuer */
  char *cakeyid;
  char *certExpDate;          // SECU-2057 add expiration date of the user certificate in the master cookie
  char *MobileRegistrationId; // SECU-2209 add mobile registration Id in master cookie
  char *contractType;         // SECU-2595 add contractType to the cookie
  char *signature;
  short size;
  short flags;
  unsigned char hash[32];
  master_cookie m;
  unsigned char pad[MAX_MASTER_SIZE - sizeof (master_cookie)];
  char name[MAX_COOKIE_NAME];
  char b[MAX_SESSION_B64 + 256 + 256];
} MASTER_COOKIE;

typedef struct {
  char *path;
  char *host;
  char *adm;
  char *user_type;
  char *ip_client;
  char *signature;
  short size; 
  short flags;
  session_cookie s;
  unsigned char pad[MAX_SESSION_SIZE - sizeof (session_cookie)];
  char name[MAX_COOKIE_NAME];
  char b[MAX_SESSION_B64 + 256];
} SESSION_COOKIE;

typedef struct {
  int ok; /* 1 for self-signed, 2 for verified, 4 for virifier */
  char *dn;
  char *cn;
  EVP_PKEY *ca_pk;
  X509 *ca;
  X509_CRL *crl;
  ASN1_OCTET_STRING *ski; /* subject key id */
  ASN1_OCTET_STRING *aki; /* authority key id */
  time_t last_crl;
  time_t This, next;
  char zthis[16], znext[16];
} LUX_CA;

typedef struct{
  char *dn;
  EVP_PKEY *ca_pk;
  X509_CRL *crl;
  time_t last_crl;
  time_t This, next;
  char zthis[16], znext[16];
} LDAP_CA;


typedef enum {
	RES_TRD,
	RES_LDAP,
	RES_CRL,
	RES_CAPK,
	RES_MULTI_CAPK,
	RES_COOKIEPK
} sso_res_type_t;

typedef struct varchar {
	size_t length;
	unsigned char *buffer;
} varchar;

typedef struct bisc_response {
	struct varchar *server_sig;
	char *protocol;
	char *reference;
	struct varchar *chain;
	struct varchar *sn;
	char *ocsp;
	char *c_time;
	char *s_time;
	char *hash_algo;
	struct varchar *client_sig;
	
} bisc_response;


char *get_tokenid(X509 *cert, char *tokenid);

char *get_EID_RNN(X509 *cert, char *tokenid, sso_ctx *sso, int i_len);

char *get_EID_serial(X509 *cert, char *serial, sso_ctx *sso, int i_len);

char *get_uid(X509 *cert, char *uid);

char *get_serial(X509 *cert, char *serial,sso_ctx* ctx );

int check_luxtrust_ssl(X509 *cert);

char *get_cn(X509_NAME *subject);

ASN1_OCTET_STRING *get_aki(X509 *cert);

ASN1_OCTET_STRING *get_ski(X509 *cert);

int check_digital_signature(X509 *cert);

int check_cp(X509 *cert, sso_ctx *sso);

void log_cp(X509 *cert, sso_ctx *sso, const char *tid);

int check_eku(X509 *cert, int mode);

void time2ztime(time_t t, char *buf);

time_t ztime2time(const ASN1_TIME *a, char *ztime);

int decode_base64(unsigned char *t, unsigned char *f, int l);

int check_pdg_url(sso_ctx *sso, char *url);

int check_otu_url(sso_ctx *sso, char *url, char *cn, int cnLen);    // SECU-2123 Unique Url Authentication Mode for SSO

int debase(unsigned char *b, int *bl);

int rsa_set_callback(EVP_PKEY *pk, void *arg);

void sso_set_trd(char *ip, int port);

void log_sso(sso_ctx *sso, int log_level, const char *format, ...);

void sso_log_open(sso_ctx *sso, apr_pool_t *p, server_rec *s);

void sso_log_close(sso_ctx *sso);

void sso_locks_init_log(sso_ctx *sso);

void sso_locks_init(server_rec *s, apr_pool_t *p);

int sso_trd_lock();

int sso_trd_release(int trd_slot);

int sso_get_trd_handle(int trd_slot, void **trd_handle);

int sso_set_trd_handle(int trd_slot, void *trd_handle);

int sso_ldap_lock();

int sso_ldap_release(int ldap_slot);

int sso_get_ldap_handle(int ldap_slot, void **ldap_handle);

int sso_set_ldap_handle(int ldap_slot, void *ldap_handle);

int sso_crl_lock();

int sso_crl_release(int crl_slot);

int sso_capk_lock();

int sso_capk_release(int capk_slot);

int sso_multi_capk_lock();

int sso_multi_capk_release(int multi_capk_slot);

int sso_cookiepk_lock();

int sso_cookiepk_release(int cookiepk_slot);

char *ldap_get_cert(void **ldap_handle, sso_ctx *sso, char *tid, X509 **cert);

char *ldap_verify(void **ldap_handle, sso_ctx *sso, X509 *cert, const char *tid, char *bid, int mode);

char *ldap_verify_mobileActivation (void **ldap_handle, sso_ctx *sso, const char *i_uid, const char *i_actHex, const char *i_pinHex); //  SECU-2209 verify mobile activation with the ldap

char *ldap_verify_mobileLogin (void **ldap_handle, sso_ctx *sso, const char *i_uid, const char *i_authCodeHex, const char *i_regIdHex); //  SECU-2209 verify mobile logon with the ldap

char *lux_verify(void **ldap_handle, sso_ctx *sso, X509 *cert, char *tid, char *bid, int mode);

char *ldap_verify_otu (void **ldap_handle, sso_ctx *sso, const char *tid, char *bid);  // SECU-2123 Unique Url Authentication Mode for SSO

char *ldap_get_permission(void **ldap_handle, sso_ctx *sso, char *uid, char *host_port, char *url,
						  char *path, char *adm, char *user_type, char *vhost_ldap, int mode);

char *check_ocsp(sso_ctx *sso, X509 *cert, X509 *ca);

char *sso_init(server_rec *s, char *params, sso_ctx *sso, EVP_PKEY *pk, unsigned char **i_cert, int i_certLen, unsigned char *i_certHash, int i_certHashLen);

char *make_cookie_pk(sso_ctx *sso, int master);

char *sign_master_cookie(int mode, int master_lifetime, sso_ctx *sso, char *ip_client, MASTER_COOKIE *master,
						 X509 *cert, X509 *ca, const char *cn, const char *mobileRegistrationId);

char *verify_master_cookie(int mode, sso_ctx *sso, char *ip_client, MASTER_COOKIE *master,
						   char *url, int *pIPMismatch);

char *sign_session_cookie(int mode, sso_ctx *sso, char *ip_client, MASTER_COOKIE *master, SESSION_COOKIE *session,
						  char *host, int port, char *url);

char *verify_session_cookie(sso_ctx *sso, char *ip_client, MASTER_COOKIE *master, SESSION_COOKIE *session,
							char *host, int port, char *url, int *pIPMismatch);

char *make_up_down_cookie(int mode, sso_ctx *sso, char *ip_cient, MASTER_COOKIE *master, char *token);

char *make_pdg_cookie(sso_ctx *sso, char* ip_client, char *args, int *args_len, MASTER_COOKIE *master);

char *sso_get_pk(sso_ctx *sso, int master, VarByteStruct *mod, VarByteStruct *exp);

char *call_ocsp(sso_ctx *sso, X509 *ca, X509 *subject, X509 *requestor, EVP_PKEY *pk,
		char *url, int options,
		unsigned char **response, int *response_length,
		int (*verify_responder_cb)(X509 *responder, void *arg),
		int (*verify_response_cb)(OCSP_SINGLERESP *single, void *arg),
		void *cb_arg,
                int i_timeout);

extern void* p11handle;
extern CK_FUNCTION_LIST* p11functions;
extern apr_thread_mutex_t* p11mutex;

/* BISC login */
#define LOGINREFLEN 40            // 20 bytes in hexadecimal
#define MAX_REDIRECT_LOCATION_SIZE 1024 // original location path maximum size
int p_make_authentication_challenge ( sso_ctx *sso, char *io_msg, int *i_msg_len, char *io_reference );
int p_verify_authentication ( sso_ctx *sso, const unsigned char *i_msg, X509 **io_X509user, X509 **io_X509issuer, char *io_reference,  SSL *i_ssl );

#endif
