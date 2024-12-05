/* z_ldap.cpp : This file contains the 'main' function. Program execution begins and ends there.

NB: Must compile with 
      Configuration Properties > General > Character Set : Not Set  
      
      Do not use UTF8 ==> ERROR when running in ldap_connect !!!
*/

//#include "ssl_private.h"
//#include "IsaProtectedParam.h"

#ifdef WIN32
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winldap.h>  //include wincrypt.h ==> define X509_NAME (((LPCSTR) 7))
//#include <Winber.h>
//#include <time.h> /* for struct timeval definition */
#undef X509_NAME    //this one cause problem. It comes from wincrypt.h, conflict with openssl
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


static int p_ldap_open(char *ldap_host, int ldap_port);
static int p_ldap_openTLS(char *ldap_host, int ldap_port);
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

//static int VerifyCert(void/*LDAP* ld, PCCERT_CONTEXT pServerCert*/)
static int VerifyCert(void  /* ld, PCCERT_CONTEXT pServerCert */)
{
   printf("VerifyCert \n");
   return 1;
}
//


/********************************************************************************************/
static int p_ldap_openTLS(char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   LDAP *pLdap = NULL;

   //printf("Connect over SSL");
   if (ldap_port == 389) {
      ldap_port = 636;
   }

   pLdap = ldap_open(ldap_host, ldap_port);
   if (pLdap == NULL) {
      printf("FAILED ldap_sslinit LDAP %s:%d \n", ldap_host, ldap_port);
      return LDAP_CONNECT_ERROR;
   }
   /*
      //add ca cert (for clients)
    result = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, "/etc/certs/Cert.pem");
    if (result != LDAP_OPT_SUCCESS ) {
        ldap_perror(ldap, "ldap_set_option - cert file - failed!");
        return(EXIT_FAILURE);
    }

    */

   /*
   ret = ldap_get_option(pLdap, LDAP_OPT_SSL, (void*)&lv);
   if (ret == LDAP_SUCCESS) {
      printf("LDAP_OPT_SSL is %d \n", (void *)lv);
   }
   else {
      printf("FAILED LDAP SSL ldap_get_option \n");
      return ret;
   }
   */

   /*
   ret = ldap_set_option(pLdap, LDAP_OPT_SSL, LDAP_OPT_ON);
   if (ret != LDAP_SUCCESS) {
      printf("FAILED ldap_set_option LDAP_OPT_SSL  \n");
      return ret;
   }
*/
   /*
   ret = ldap_get_option(pLdap, LDAP_OPT_SSL, (void*)&lv);
   if (ret == LDAP_SUCCESS) {
      printf("LDAP_OPT_SSL is %d \n", (void *)lv);
   }
   else {
      printf("FAILED LDAP SSL ldap_get_option \n");
      return ret;
   }
   */

   //set debug --> only for debug purpose
   /*
   int debug = 7;
   ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
   */

   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION");
      return ret;
   }

   //set the connect call back
   //ret = ldap_set_option(pLdap, LDAP_OPT_SERVER_CERTIFICATE, &VerifyCert);
   ret = ldap_set_option(pLdap, LDAP_OPT_X_TLS_CONNECT_CB, (void *)VerifyCert);
   if (ret != LDAP_SUCCESS) {
           fprintf(stderr, "ldap_set_option(LDAP_OPT_X_TLS_CONNECT_CB): %s\n", ldap_err2string(ret));
           return ret;
   }

   int msgidp = 0;
     ret = ldap_start_tls(pLdap,NULL,NULL,&msgidp);
     if (ret != LDAP_OPT_SUCCESS ) {
         ldap_perror(pLdap, "start tls failed!");
         return ret;
     }


     /*
   if ((ret = ldap_connect(pLdap, NULL))) {
      printf("FAILED ldap_connect LDAP %s:%d \n", ldap_host, ldap_port);
      printf("Error Ox%0x    %d \n", ret, ret);
      return ret;
   }

   if ((ret = p_ldap_bind(pLdap, ldap_user, ldap_psw))) {
      printf("FAILED p_ldap_bind LDAP %s:%d", ldap_host, ldap_port);
      return ret;
   }
   */

   //*ld = pLdap;
   return ret;
}
/********************************************************************************************/
static int p_ldap_open(char *ldap_host, int ldap_port)
{
   int ret = 0;
   long lv = 0;
   LDAP *pLdap = NULL;



      printf("Connect with NO SSL \n");
      pLdap = ldap_init(ldap_host, ldap_port);
      if (pLdap == NULL) {
         printf("FAILED ldap_init LDAP %s:%d \n", ldap_host, ldap_port);
         return LDAP_CONNECT_ERROR;
      }


   if ((ret = ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version))) {
      printf("FAILED ldap_set_option LDAP_OPT_PROTOCOL_VERSION");
      return ret;
   }

   ret = ldap_set_option(pLdap, LDAP_OPT_X_TLS_CONNECT_CB, (void *)VerifyCert);
   if (ret != LDAP_SUCCESS) {
           fprintf(stderr, "ldap_set_option(LDAP_OPT_X_TLS_CONNECT_CB): %s\n", ldap_err2string(ret));
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
/*******************************************************************************************

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

 

/********************************************************************************************/
void main(int argc, char **argv)
{
   int ret = 0;
   int ldap_type = 0;

   printf("ldap_host : %s:%d\n", ldap_host, ldap_port);
   //printf("Enter ldap type (0=NO SSL,  1=SSL) : ");
   //scanf_s("%d", &ldap_type);
   ldap_type = 1; //TLS
   if (ldap_type) {
      ret = p_ldap_openTLS(ldap_host, ldap_port);
   }
   else {
      ret = p_ldap_open(ldap_host, ldap_port);
   }
   printf("Main Return %d \n", ret);

   return;
}

/********************************************************************************************/




 
