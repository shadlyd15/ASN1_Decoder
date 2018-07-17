#ifndef COSEM_ASSOCIATION_H
#define COSEM_ASSOCIATION_H

#include <stdint.h>
// Name Referencing
// #define NO_REF_NO_CYPHERING 					(0x00)
// #define LN_REF_NO_CYPHERING 					(0x01)
// #define SN_REF_NO_CYPHERING 					(0x02)
// #define LN_REF_WITH_CYPHERING 				(0x03)
// #define SN_REF_WITH_CYPHERING 				(0x04)

typedef struct conformance_block conformance_block_t;
typedef struct cosem_asso_info cosem_asso_info_t;
typedef struct xDLMS_initiate_request xDLMS_initiate_request_t;

enum name_referencing{
    NO_REF_NO_CYPHERING 	= 0U,
    LN_REF_NO_CYPHERING 	= 1U,  // Logical Name
    SN_REF_NO_CYPHERING 	= 2U,  // Short Name
    LN_REF_WITH_CYPHERING 	= 3U,
    SN_REF_WITH_CYPHERING 	= 4U
};

enum oid_names{
	APP_CONTEXT_NAME 			= 0x01,
	SECURITY_MECHANISM_NAME 	= 0x02
};

enum csm_auth_level{
    AUTH_LOWEST_LEVEL       = 0U,
    AUTH_LOW_LEVEL          = 1U,
    AUTH_HIGH_LEVEL         = 2U,
    AUTH_HIGH_LEVEL_MD5     = 3U,
    AUTH_HIGH_LEVEL_SHA1    = 4U,
    AUTH_HIGH_LEVEL_GMAC    = 5U,
    AUTH_HIGH_LEVEL_SHA256  = 6U
};

struct conf_block_tlv{

};

struct conformance_block{
	uint8_t placeholder_1 : 1;
	uint8_t general_protection : 1;
	uint8_t general_block_transfer : 1;
	uint8_t read : 1;
	uint8_t write : 1;
	uint8_t unconfirmed_write : 1;
	uint8_t placeholder_2 : 1;
	uint8_t placeholder_3 : 1;
	uint8_t attr_0_supported_with_set : 1;
	uint8_t priority_mgmt_supported : 1;
	uint8_t attr_0_supported_with_get : 1;
	uint8_t block_transfer_with_get_or_read : 1;
	uint8_t block_transfer_with_set_or_write : 1;
	uint8_t block_transfer_with_action : 1;
	uint8_t multiple_reference : 1;
	uint8_t placeholder_4 : 1;
	uint8_t data_notification : 1;
	uint8_t access : 1;
	uint8_t parameterized_access : 1;
	uint8_t get : 1;
	uint8_t set : 1;
	uint8_t selective_access : 1;
	uint8_t event_notification : 1;
	uint8_t action : 1;
};

struct xDLMS_initiate_request{
	uint8_t * dedicated_key;
	uint8_t response_allowed;
	uint8_t proposed_qos;
    uint8_t proposed_dlms_version;
	conformance_block_t proposed_conf_block;
	uint16_t proposed_max_pdu_size;
};

struct xDLMS_initiate_response{
	uint8_t negotiated_qos;
    uint8_t negotiated_dlms_version;
    uint32_t placeholder_1;
    uint16_t placeholder_2;
    uint8_t placeholder_3;
	conformance_block_t negotiated_conf_block;
	uint16_t negotiated_max_pdu_size;
	uint16_t vaa_name;
};

#endif // COSEM_ASSOCIATION_H