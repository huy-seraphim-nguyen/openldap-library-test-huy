/* z_winldap.cpp : 

This program uses OpenLdap lib on Windows, not WinLdap lib.
- OpenLdap lib uses Openssl
- WinLdap lib does not use Openssl

NB: In VS2017, Must compile with 
      Configuration Properties > General > Character Set : Not Set  
      
      Do not use UTF8 ==> ERROR when running in ldap_connect !!!
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winldap.h>  //include wincrypt.h ==> define X509_NAME (((LPCSTR) 7))
//#include <Winber.h>
//#include <time.h> /* for struct timeval definition */
#undef X509_NAME    //this one cause problem. It comes from wincrypt.h, conflict with openssl
 
/*
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
*/
 
static int p_ldap(char *ldap_host, int ldap_port);
static int p_ldapTLS(char *ldap_host, int ldap_port);

static int ldap_version = LDAP_VERSION3;

//Data for testing
// Apache Directory Studio
char ldap_host[32] = "localhost"; //char ldap_host[32] = sso dev pki 10.63.1.35
static char *ldap_user = "cn=huy,l=isabelbeta,c=be"; 
static char *ldap_psw  = "huy";

/********************************************************************************************/
//static int VerifyCert(void/*LDAP* ld, PCCERT_CONTEXT pServerCert*/)
//static int VerifyCert(void* ld, PCCERT_CONTEXT pServerCert)
void VerifyCert(void* ld, PCCERT_CONTEXT pServerCert)
{
   printf("VerifyCert server cert  OK \n");
   return 1;
}

/********************************************************************************************/
static int p_ldapTLS(char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   LDAP *pLdap = NULL;

   printf("Connect over TLS \n");
   pLdap = ldap_sslinit(ldap_host, ldap_port, 1);
   if (pLdap == NULL) {
      printf("FAILED ldap_sslinit LDAP %s:%d \n", ldap_host, ldap_port);
      return LDAP_CONNECT_ERROR;
   }
   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION \n");
      return ret;
   }
   ret = ldap_set_option(pLdap, LDAP_OPT_SSL, LDAP_OPT_ON);
   if (ret != LDAP_SUCCESS) {
      printf("FAILED ldap_set_option LDAP_OPT_SSL  \n");
      return ret;
   }
   if ((ret = ldap_set_option(pLdap, LDAP_OPT_SERVER_CERTIFICATE, &VerifyCert))) {
      printf("FAILED ldap_set_option LDAP_OPT_SERVER_CERTIFICATE \n");
      return ret;
   }

   //Here, handshake starts !!!  (see Wireshark)
   if ((ret = ldap_connect(pLdap, NULL))) {
      printf("FAILED ldap_connect : %s:%d \n", ldap_host, ldap_port);
      printf("Error Ox%0x    %d \n", ret, ret);
      return ret;
   }

   //OpenSSL_add_all_algorithms();
   /*
   if (1 != ISA_PARAM_AES_decrypt_param(sso->ldap_pwd, strlen(sso->ldap_pwd), ldap_pwd, sizeof ldap_pwd))
   {
      LOG_SSO(sso, 0, "ldap_password decrypt error.'");
      return -1;
   }
   //*/

   if ((ret = ldap_simple_bind_s(pLdap, ldap_user, ldap_psw))) {
      printf("FAILED ldap_simple_bind_s : %s:%d", ldap_host, ldap_port);
      return ret;
   }

   //*ld = pLdap;
   return ret;
}

/********************************************************************************************/
static int p_ldap(char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   LDAP *pLdap = NULL;

   printf("Connect with NO SSL \n");   
   pLdap = ldap_init(ldap_host, ldap_port); //replace ldap_open (deprecated)
   if (pLdap == NULL) {
      printf("FAILED ldap_init :  %s:%d \n", ldap_host, ldap_port);
      return LDAP_CONNECT_ERROR;
   }
   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION");
      return ret;
   }

   //ldap_set_option(pLdap, LDAP_OPT_SERVER_CERTIFICATE, &VerifyCert); //not used in non-TLS

   if ((ret = ldap_connect(pLdap, NULL))) {
      printf("FAILED ldap_connect : %s:%d \n", ldap_host, ldap_port);
      printf("Error Ox%0x    %d \n", ret, ret);
      return ret;
   }
   
   //OpenSSL_add_all_algorithms();
   /*
   if (1 != ISA_PARAM_AES_decrypt_param(sso->ldap_pwd, strlen(sso->ldap_pwd), ldap_pwd, sizeof ldap_pwd))
   {
      LOG_SSO(sso, 0, "ldap_password decrypt error.'");
      return -1;
   }
   //*/

   if ((ret = ldap_simple_bind_s(pLdap, ldap_user, ldap_psw))) {
      printf("FAILED ldap_simple_bind_s : %s:%d", ldap_host, ldap_port);
      return ret;
   }

   //*ld = pLdap;
   return ret;
}

/********************************************************************************************/
void main(int argc, char **argv)
{
   int ret = 0;
   int ldap_port = 10389;     //389 or 636
   int ldap_type = 0;         //0 or 1

   printf("ldap_host : %s:%d   %d \n", ldap_host, ldap_port, ldap_type);
   printf("Enter ldap type (0=NO SSL,  1=SSL) : ");
   //scanf_s("%d", &ldap_type);
   //ldap_type = 1; //TLS
   if (ldap_type) {
      ret = p_ldapTLS(ldap_host, ldap_port);
   }
   else {
      ret = p_ldap(ldap_host, ldap_port);
   }
   printf("Main return : %d \n", ret);

   return;
}

/********************************************************************************************/



 