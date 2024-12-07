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
int p_ldapEx (int ldap_type, LDAP **ldap, char *ldap_host, int ldap_port);


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
int p_ldapEx(int ldap_type, LDAP **ldap, char *ldap_host, int ldap_port)
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
void main(int argc, char **argv)
{
   LDAP *ldap = NULL;

   int ret = 0;
   int ldap_port = 10636;     //389 or 636
   int ldap_type = 1;         //0 or 1


   printf("ldap_host : %s:%d   %d \n", ldap_host, ldap_port, ldap_type);
   printf("Enter ldap type (0=NO SSL,  1=SSL) : ");
   scanf_s("%d", &ldap_type);

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
   ret = p_ldapEx(ldap_type, &ldap, ldap_host, ldap_port);
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
