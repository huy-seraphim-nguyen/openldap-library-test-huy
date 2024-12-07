/* z_ldap.cpp : This file contains the 'main' function. Program execution begins and ends there.

NB: Must compile with 
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
 
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>

static int p_ldap_open(int ldaps, char *ldap_host, int ldap_port);
static int p_ldap_bind(LDAP *ldap, char *ldap_user, char *ldap_psw);

//=====================================
static int ldap_version = LDAP_VERSION3;


/*
// OK
char ldap_host[32] = "dbibsldap301.isagrp.local"; //char ldap_host[32] = "10.63.2.28";
int  ldap_port = 389;   //389 or 636
int  ldaps = 0;         //0 or 1
static char *ldap_user = "cn=Manager,l=isabelbeta,c=be";
static char *ldap_psw  = "secret";
*/

/* 
// OK
char ldap_host[32] = "10.63.1.36"; //char ldap_host[32] = sso-dev2
int  ldap_port = 389;   //389 or 636
int  ldaps = 0;         //0 or 1
static char *ldap_user = "cn=reader,l=isabelbeta,c=be";
static char *ldap_psw  = "pwd";
*/

// OK
/*
char ldap_host[32] = "10.63.1.36"; //char ldap_host[32] = sso-dev2
int  ldap_port = 389;   //389 or 636
int  ldaps = 0;         //0 or 1
static char *ldap_user = "cn=Directory Manager";
static char *ldap_psw  = "isabelgroup";
*/  


// OK
/*
char ldap_host[32] = "dbibspki310.isagrp.local"; //char ldap_host[32] = sso dev pki 10.63.1.35
int  ldap_port = 389;   //389 or 636
int  ldaps = 0;         //0 or 1
static char *ldap_user = "cn=Directory Manager";
static char *ldap_psw = "isabelgroup";
*/


// Apache Directory Studio
char ldap_host[32] = "localhost"; //char ldap_host[32] = sso dev pki 10.63.1.35
int  ldap_port = 10636;   //389 or 636
int  ldaps = 0;         //0 or 1
static char *ldap_user = "cn=huy,l=isabelbeta,c=be"; 
static char *ldap_psw  = "huy";


/********************************************************************************************/
void main(int argc, char **argv)
{
   int ret = 0;
   int ldap_type = 0;

   printf("ldap_host : %s:%d\n", ldap_host, ldap_port);
   printf("Enter ldap type (0=NO SSL,  1=SSL) : ");
   scanf_s("%d", &ldap_type);
   ret = p_ldap_open(ldap_type, ldap_host, ldap_port);
   printf("Main Return %d \n", ret);

   return;
}

/********************************************************************************************/
static int p_ldap_open(int ldaps, char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   LDAP *pLdap = NULL;

   if (ldaps) {
      //printf("Connect over SSL");
      //if (ldapssl_client_init(sso->serverCert"/local/examples/alias/", NULL) < 0) {
      /*
      if (ldapssl_client_init("D:/Program32bit/Apache2441/httpd-2.4.41/Debug/conf_www_isabel_be/ca2K_and_4K_acc.pem", NULL) < 0) {
         printf("FAILED ldapssl_client_init LDAP %s:%d", ldap_host, ldap_port);
         return LDAP_CONNECT_ERROR;
      }
      */
      if (ldap_port == 389) {
         ldap_port = 636;
      }

      pLdap = ldap_sslinit(ldap_host, ldap_port, 1);
      if (pLdap == NULL) {
         printf("FAILED ldap_sslinit LDAP %s:%d \n", ldap_host, ldap_port);
         return LDAP_CONNECT_ERROR;
      }

      ret = ldap_get_option(pLdap, LDAP_OPT_SSL, (void*)&lv);
      if (ret != LDAP_SUCCESS) {
         printf("FAILED LDAP SSL ldap_get_option \n");
         return ret;
      }
      ret = ldap_set_option(pLdap, LDAP_OPT_SSL, LDAP_OPT_ON);
      if (ret != LDAP_SUCCESS) {
         printf("FAILED ldap_set_option LDAP_OPT_SSL  \n");
         return ret;
      }
   }
   else {
      printf("Connect with NO SSL \n");
      pLdap = ldap_init(ldap_host, ldap_port);
      if (pLdap == NULL) {
         printf("FAILED ldap_sslinit LDAP %s:%d \n", ldap_host, ldap_port);
         return LDAP_CONNECT_ERROR;
      }
   }

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION");
      return ret;
   }

  if ((ret = ldap_connect(pLdap, NULL))) {
      printf("FAILED ldap_connect LDAP %s:%d \n", ldap_host, ldap_port);
      printf("Error Ox%0x    %d \n", ret, ret);
      return ret;
   }

   if ((ret = p_ldap_bind(pLdap, ldap_user, ldap_psw))) {
      printf("FAILED p_ldap_bind LDAP %s:%d", ldap_host, ldap_port);
      return ret;
   }

   //*ld = pLdap;
   return ret;
}


static int p_ldap_openBAK(int ldaps, char *ldap_host, int ldap_port)
{
   int ret = 0;
   LDAP *pLdap = NULL;


   if ((pLdap = ldap_open(ldap_host, ldap_port)) == NULL) {
      printf("p_ldap_open failed: Cannot connect to LDAP %s:%d", ldap_host, ldap_port);
      return LDAP_CONNECT_ERROR;
   }
   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("p_ldap_open :Failed to set LDAP_OPT_PROTOCOL_VERSION");
      return ret;
   }
   if ((ret = p_ldap_bind(pLdap, ldap_host, ldap_port))) {
      printf("p_ldap_open: Failed to bind LDAP");
      return ret;
   }

   //*ld = pLdap;
   return ret;
}

/*******************************************************************************************
   Bind to ldap after decrypting the password
*******************************************************************************************/
static int p_ldap_bind(LDAP *ldap, char *ldap_user, char *ldap_psw)
{
   // Decrypted pin
   int ret = 0;

   //OpenSSL_add_all_algorithms();
   /*
   if( 1 != ISA_PARAM_AES_decrypt_param(sso->ldap_pwd,strlen(sso->ldap_pwd), ldap_pwd, sizeof ldap_pwd))
     {
     LOG_SSO (sso, 0, "ldap_password decrypt error.'" );
     return -1;
     }
   return (ldap_simple_bind_s(ld, sso->ldap_user, ldap_pwd));
     */

   ret = ldap_simple_bind_s(ldap,  ldap_user, ldap_psw);
   printf("ldap_simple_bind_s  Return %d \n", ret);

   return ret;

}




 