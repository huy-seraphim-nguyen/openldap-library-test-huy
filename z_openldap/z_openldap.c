/* z_openldap.cpp : This file contains the 'main' function. Program execution begins and ends there.

This program uses OpenLdap lib on Windows, not WinLdap lib.
- OpenLdap lib uses Openssl
- WinLdap lib does not use Openssl

gcc -o  z_openldap  z_openldap.c   -lldap -llber

*/

//#include "ssl_private.h"
//#include "IsaProtectedParam.h"


#ifdef WIN32
#include <stdio.h>
#include <stdlib.h>
//#include <windows.h>
#include <ldap.h> //from D:\Program32bit\openldap-2.4.47
#include <lber.h>

//#undef X509_NAME    //this one cause problem. It comes from wincrypt.h, conflict with openssl
#else
#include <ldap.h>
#include <lber.h>
#include <unistd.h>
#include <pthread.h>
#endif

#define MAX_INSTANCE 10
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
   //EVP_PKEY *ssl_pk;
   //EVP_PKEY *master_pk;
   //EVP_PKEY *session_pk;
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
   int ldap_type;
} sso_ctx;


#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>

//=====================================
static int ldap_version = LDAP_VERSION3;

// Apache Directory Studio
char ldap_host[32] = "localhost"; //char ldap_host[32] = sso dev pki 10.63.1.35
static char *ldap_user = "cn=huy,l=isabelbeta,c=be"; 
static char *ldap_psw  = "huy";

int p_ldap   (LDAP **ldap, char *ldap_host, int ldap_port);
int p_ldapTLS(LDAP **ldap, char *ldap_host, int ldap_port);
int p_ldapEx2(int ldap_type, LDAP **ldap, char *ldap_host, int ldap_port);
int p_ldapEx(LDAP **ldap, sso_ctx *sso);
//int p_ldapEx( LDAP **ldap, char *ldap_host, sso_ctx *sso);


/********************************************************************************************/
void p_perr(int line, char *msg, int err)
{
   printf("Error:%s (L %d). %s : %s (%d) \n", __FILE__,
      line, msg, ldap_err2string(err), err);
   return;
}
/********************************************************************************************/
int p_ldap(LDAP **ldap, char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   
   LDAP *pLdap = NULL;
   LDAPURLDesc url;
   char* ldap_uri = NULL;
   memset(&url, 0, sizeof(url));

   printf("Connect with NO SSL \n");

   //* ldap_open deprecated
   
   url.lud_scheme = "ldap";
   url.lud_host = ldap_host;
   url.lud_port = ldap_port;
   url.lud_scope = LDAP_SCOPE_DEFAULT;
   ldap_uri = (char *)ldap_url_desc2str(&url);
   ret = ldap_initialize(&pLdap, ldap_uri);
   if (ret) {
      printf("FAILED ldap_initialize : %s:%d \n", ldap_host, ldap_port);
      printf("FAILED ldap_initialize : %s \n", ldap_uri);
      return ret;
   }

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION");
      printf("Error:%s (L %d). %s : %s\n", __FILE__, __LINE__, 
      "ldap_set_option LDAP_OPT_PROTOCOL_VERSION", ldap_err2string(ret));
      return ret;
   }

   if ((ret = ldap_simple_bind_s(pLdap, ldap_user, ldap_psw))) {
      printf("FAILED ldap_simple_bind_s : %s:%d   %s \n", ldap_host, ldap_port, ldap_uri);
      return ret;
   }

   *ldap = pLdap;
   return ret;
}

/********************************************************************************************/
int p_ldapTLS(LDAP **ldap, char *ldap_host, int ldap_port)
{
   LDAP *pLdap = NULL;
   LDAPURLDesc url;
   //char* ldap_uri = "ldaps://localhost:10636";
   char* ldap_uri = NULL;

   int ret = 0;
   long lv = 0;

   memset(&url, 0, sizeof(url));


   printf("Connect over TLS \n");
   url.lud_scheme = "ldaps";
   url.lud_host = ldap_host;
   url.lud_port = ldap_port;
   //url.lud_scope = LDAP_SCOPE_DEFAULT;
   ldap_uri = (char *)ldap_url_desc2str(&url);

   ret = ldap_initialize(&pLdap, ldap_uri);
   if (ret) {
      printf("FAILED ldap_initialize : %s:%d \n", ldap_host, ldap_port);
      printf("FAILED ldap_initialize : %s \n", ldap_uri);
      return ret;
   }
   printf("LDAPS connection initialized to %s\n", ldap_uri);

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION \n");
      return ret;
   }

   //unsigned long requireCert = LDAP_OPT_X_TLS_NEVER;
   int requireCert = LDAP_OPT_X_TLS_NEVER;
   ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &requireCert);
   if (ret != LDAP_SUCCESS) {
      printf("FAILED ldap_set_option LDAP_OPT_X_TLS_NEVER : %s \n", ldap_err2string(ret));
      return ret;
   }

   // Do not call ldap_start_tls_s(). Not work.
   /*
   The ldap_start_tls_s function is called on an existing LDAP (not LDAPS) session to initiate the use of TLS (SSL) encryption. 
   The connection must not already have TLS (SSL) encryption enabled
   */
  
   if ((ret = ldap_simple_bind_s(pLdap, ldap_user, ldap_psw))) {
      p_perr(__LINE__, "ldap_start_tls_s", ret);
      ldap_unbind_ext_s(pLdap, NULL, NULL);
      return ret;
   }
   printf("TLS session started successfully & bind successfully.\n");

   *ldap = pLdap;
   return ret;
}

/********************************************************************************************/
int p_ldapEx2(int ldap_type, LDAP **ldap, char *ldap_host, int ldap_port)
{
   LDAP *pLdap = NULL;
   LDAPURLDesc url;
   char* ldap_uri = NULL;

   int ret = 0;
   long lv = 0;

   memset(&url, 0, sizeof(url));
   if (ldap_type) {
      printf("Connect over TLS \n");
      int requireCert = LDAP_OPT_X_TLS_NEVER;
      ldap_port = 10636;
      url.lud_scheme = "ldaps";

      ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &requireCert);
      if (ret != LDAP_SUCCESS) {
         printf("FAILED ldap_set_option LDAP_OPT_X_TLS_NEVER : %s \n", ldap_err2string(ret));
         return ret;
      }
   }
   else {
      printf("Connect with NO SSL \n");
      ldap_port = 10389;
      //ret = p_ldap(&ldap, ldap_host, ldap_port);
      url.lud_scheme = "ldap";
   }
   url.lud_host = ldap_host;
   url.lud_port = ldap_port;
   //url.lud_scope = LDAP_SCOPE_DEFAULT;
   ldap_uri = ldap_url_desc2str(&url);

   ret = ldap_initialize(&pLdap, ldap_uri);
   if (ret) {
      printf("FAILED ldap_initialize : %s \n", ldap_uri);
      p_perr(__LINE__, "ldap_initialize", ret);
      return ret;
   }
   printf("LDAP connection initialized to %s\n", ldap_uri);

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION \n");
      return ret;
   }

   // Do not call ldap_start_tls_s(). Not work.
   /*
   The ldap_start_tls_s function is called on an existing LDAP (not LDAPS) session to initiate the use of TLS (SSL) encryption.
   The connection must not already have TLS (SSL) encryption enabled
   */

   if ((ret = ldap_simple_bind_s(pLdap, ldap_user, ldap_psw))) {
      p_perr(__LINE__, "ldap_start_tls_s", ret);
      ldap_unbind_ext_s(pLdap, NULL, NULL);
      return ret;
   }
   printf("LDAP session started successfully & bind successfully.\n");

   *ldap = pLdap;
   return ret;
}

/********************************************************************************************/
int p_ldapEx(  LDAP **ldap, sso_ctx *sso)
{
   LDAP *pLdap = NULL;
   LDAPURLDesc url;
   char* ldap_uri = NULL;
   int ldap_type = 0;
   int ldap_port = 389;
   //char ldap_pwd[128] = "";


   int ret = 0;
   long lv = 0;

   memset(&url, 0, sizeof(url));
   ldap_type = sso->ldap_type;
   if (ldap_type) {
      printf("Connect over TLS \n");
      int requireCert = LDAP_OPT_X_TLS_NEVER;
      ldap_port = 10636;
      url.lud_scheme = "ldaps";

      ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &requireCert);
      if (ret != LDAP_SUCCESS) {
         printf("FAILED ldap_set_option LDAP_OPT_X_TLS_NEVER : %s \n", ldap_err2string(ret));
         return ret;
      }
   }
   else {
      printf("Connect with NO SSL \n");
      ldap_port = 10389;
      //ret = p_ldap(&ldap, ldap_host, ldap_port);
      url.lud_scheme = "ldap";
   }
   url.lud_host = sso->ldap_host;
   url.lud_port = ldap_port;
   //url.lud_scope = LDAP_SCOPE_DEFAULT;
   ldap_uri = ldap_url_desc2str(&url);

   ret = ldap_initialize(&pLdap, ldap_uri);
   if (ret) {
      printf("FAILED ldap_initialize : %s \n", ldap_uri);
      p_perr(__LINE__, "ldap_initialize", ret);
      return ret;
   }
   printf("LDAP connection initialized to %s\n", ldap_uri);

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION \n");
      return ret;
   }

   // Do not call ldap_start_tls_s(). Not work.
   /*
   The ldap_start_tls_s function is called on an existing LDAP (not LDAPS) session to initiate the use of TLS (SSL) encryption.
   The connection must not already have TLS (SSL) encryption enabled
   */

   if ((ret = ldap_simple_bind_s(pLdap, sso->ldap_user, sso->ldap_pwd))) {
      p_perr(__LINE__, "ldap_start_tls_s", ret);
      ldap_unbind_ext_s(pLdap, NULL, NULL);
      return ret;
   }
   printf("LDAP session started successfully & bind successfully.\n");

   *ldap = pLdap;
   return ret;
}

/********************************************************************************************/
void main(int argc, char **argv)
{
   LDAP *ldap = NULL;
   sso_ctx *sso = NULL;

   int ret = 0;
   int ldap_port = 10636;     //389 or 636
   int ldap_type = 1;         //0 or 1


   printf("ldap_host : %s:%d   %d \n", ldap_host, ldap_port, ldap_type);
   printf("Enter ldap type (0=NO SSL,  1=SSL) : ");
   scanf_s("%d", &ldap_type);

   sso = malloc(sizeof (struct sso_ctx_st));
   sso->ldap_host = ldap_host;
   sso->ldap_port = ldap_port;
   sso->ldap_type = ldap_type;
   sso->ldap_user = ldap_user;
   sso->ldap_pwd = ldap_psw;


   /*
   if (ldap_type) {
      ldap_port = 10636;
      ret = p_ldapTLS(&ldap, ldap_host, ldap_port);
   }
   else {
      ldap_port = 10389;
      ret = p_ldap(&ldap, ldap_host, ldap_port);
   }
   */
   //ret = p_ldapEx2(ldap_type, &ldap, ldap_host, ldap_port);
   ret = p_ldapEx(&ldap, sso);
   printf("Main return : %d \n", ret);


   // Perform a search
   LDAPMessage *result_msg;
   const char *search_base = "l=isabelbeta,c=be";         // Replace with your search base
 
   //openldap code
   const char *search_filter = "cn=huy";         // Replace with your search filter
   //ret = ldap_search_ext_s(ldap, search_base, LDAP_SCOPE_SUBTREE, search_filter, NULL, 0, NULL, NULL, NULL, 0, &result_msg);

   //isabel code
#define BIN_CERT   "userCertificate;binary"
   const char *entry = "cn=huy,l=isabelbeta,c=be";         // Replace with your search filter
   char *bin_attr_cert[] = { BIN_CERT, NULL, };
   char **attr = bin_attr_cert;

   //ret = ldap_search_st(ldap, entry, LDAP_SCOPE_BASE, "objectclass=*", NULL, 0,  LDAP_NO_LIMIT, &result_msg);
   ret = ldap_search_st(ldap, entry, LDAP_SCOPE_BASE, "objectclass=*", attr, 0,  LDAP_NO_LIMIT, &result_msg);
   if (ret != LDAP_SUCCESS) {
      fprintf(stderr, "ldap_search_ext_s failed: %s\n", ldap_err2string(ret));
      ldap_unbind_ext_s(ldap, NULL, NULL);
      return EXIT_FAILURE;
   }

   printf("Search successful.\n");
   return;
}

/********************************************************************************************/
