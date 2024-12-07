/* For RCS */
/* $Log: x509fcer.h,v $
 * Revision 1.1  2007/02/06 08:02:38  fhe
 * Initial revision
 *
 * Revision 1.3  2002/07/03 12:08:04  fhe
 * For ACF: encode/decode CardId
 *
 * Revision 1.2  2002/02/04  11:01:32  fhe
 * Qualified certificates
 *
 * Revision 1.1  2000/03/28  10:37:05  fhe
 * New world...
 * */
#if !defined ( _X509FCER_H )
#define _X509FCER_H

/************************************************************************/
/*                                                                      */
/* X509FCER.H                                                           */
/*                                                                      */
/* X509 flat certificate structure                                      */
/*                                                                      */
/* Requires basic types UINT8/UINT16 (8/16 bits storage) defined        */
/************************************************************************/

/* addition ms 23-6-97: On PC under Microsoft C, add a pragma to force the 
   byte alignment of the structures. It is not necessary to do it for Borland 
   C, cf the structures are aligned on the byte by default. It is not
   necessary to do it for UNIX, because the compiler aligns the structures
   on the element requiring the biggest alignment; and there is no compilation
   option to modify this alignment */

#if defined ( WIN ) || defined ( _WINDOWS ) || defined ( _Windows ) || defined ( _MSC_VER ) || defined ( __BORLANDC__ )
#pragma pack(1)
#endif


/***********************/
/* Configuration flags */
/***********************/

/* Indicates signature algorithm (from macro SIGNED) absence/presence in 
   certificate (0/1) */
#define X509_DUP_SIG_ALGO_IN_FLAT 1


/*************/
/* Constants */
/*************/

/* Maximum lengths */
/*******************/

/* UTC time: YYYYMMDDhhmm(ss)Z (always expressed in GMT) */
#define X509_UTC_LEN            20 

/* Octet value: maximum key or signature length: 256 to allow keys and 
   signature of 2048 bits  */
#define X509_OCTET_VAL_LEN      256

/* Public key name: align on other naming attributes => 64 */
#define X509_PK_NAME_LEN        80

/* Unique Identifier: maximum length = 13 (defined by IsaBel) */
#define X509_UID_LEN            80

/* Distinguished Name: maximum length deduced from the length of all its 
   components if they are all present */
/* C->2, L->128, ST->128, O->64, OU->64 (X5), CN->64 => 611 */
#if defined (_MSC_VER) || defined (__BORLANDC__)
#define X509_DN_LEN             1000
#else
#define X509_DN_LEN             2048
#endif

/* Max length of certificate serial number */
#define X509_CID_LEN           80

/* Algorithm parameter length (for IsaBel) */
#define X509_ALGO_PARAM_LEN    X509_UTC_LEN+X509_PK_NAME_LEN+80

/* Optional data length (for IsaBel) */
/* max is X509_ALGO_PARAM_LEN - "R:00:19970115115600Z:C:U:R:" */
#define X509_OPT_DATA_LENGTH (X509_ALGO_PARAM_LEN - 28)

/* Reason code */
#define X509_REV_REASON         2


/* Values */
/**********/

/* Version of certificate: v1=88, v2=93 */

#define v1 0
#define v2 1

/*********/
/* Types */
/*********/

/* X509 flat certificate */
/*************************/

typedef UINT8 t_algorithm;

typedef UINT8 t_version;

/* Certificate IDentifier (serial number) */

typedef char t_cid[X509_CID_LEN+1];

/* Public key name */

typedef char t_public_key_name[X509_PK_NAME_LEN+1];

/* Distinguished Name: NULL-terminated string in the form 
   "/C=.../O=.../CN=.../..." */

typedef char t_name[X509_DN_LEN+1];


/* UTC time: NULL-terminated string in the form YYYYMMDDhhmm(ss)Z (it is 
   always expressed in GMT time) */

typedef char t_UTC_time[X509_UTC_LEN+1];

/* Validity period */

typedef struct 
{
	t_UTC_time      beg_val;
	t_UTC_time      end_val;
} t_validity_period;


/* Algorithm parameter */
/* For valid certificate V:<type_certif>:<type_user>:<type_RA>:<opt_data> */
/* For revoked certificate R:<reason>:<timestamp>:<type_certif>:<type_user>:
   <type_RA>:<opt_data> */

typedef char t_algorithm_parameter[X509_ALGO_PARAM_LEN+1];

/* Octet string */

typedef struct
{
	UINT16          len;
	UINT8           value[X509_OCTET_VAL_LEN];
} t_octet_string;


/* RSA public key */

typedef struct        
{
	t_octet_string   mod;         
	t_octet_string   exp;
} t_rsa_public_key;


/* Unique IDentifier: NULL-terminated string */

typedef char t_unique_identifier[X509_UID_LEN+1];


/* Signature: octet string */

typedef t_octet_string  t_signature;


/* Flat Certificate */

typedef struct        
{
	t_version               ver;
	t_cid                   cid;
	t_algorithm             ca_sig_algo;
	t_public_key_name       ca_pk_name;
	t_name                  ca_name;
	t_validity_period       valid_period;
	t_name                  owner_name;
	t_algorithm             owner_key_type;
	t_algorithm_parameter   owner_algo_param;
	t_rsa_public_key        owner_pk;
	t_unique_identifier     ca_uid;
	t_unique_identifier     owner_uid;
#if X509_DUP_SIG_ALGO_IN_FLAT
	t_algorithm             signat_algo;
	t_public_key_name       signat_algo_param;
#endif
	t_signature             signat;
#ifdef CA
#define X509_EMAIL_LEN 255
        char                    email[X509_EMAIL_LEN+1];
        t_cid                   cardid;
#endif
} t_x509_certificate;


/* X509 flat certificate pair */
/******************************/

/* Pair */
typedef struct {
  int cer_present;  /* states if certificate was present in pair */
  INT32 pos;          /* start of certificate ber in cross */
  INT32 len;          /* len of certificate ber in cross */
  INT32 tbs_pos;      /* start of to be signed in cer - relative to start of cer */
  INT32 tbs_len;      /* len of to be signed in cer */
  unsigned char hash[64];
  int hash_len;
} t_x509_cer_pair_att;

typedef struct
{
  t_x509_certificate forward;
  t_x509_cer_pair_att forward_att;
  t_x509_certificate reverse;
  t_x509_cer_pair_att reverse_att;
} t_x509_pair;

#if defined ( WIN ) || defined ( _WINDOWS ) || defined ( _Windows ) || defined ( _MSC_VER ) || defined ( __BORLANDC__ )
#pragma pack()
#endif

#endif /** _X509FCER_H **/
