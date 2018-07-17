#include "asn1.h"
#include "data_types.h"
#include "platform_invariance.h"
#include "cosem_association.h"
#include "apdu_types.h"
#include "debug.h"
#include "xDLMS.h"
#include <stdio.h>

uint8_t decode_asn_triplet(tlv_triplet_t * triplet, uint8_t * packet, uint32_t size) {
	if(0 == packet) return FALSE;

	triplet->tag_octet = *(asn_tag_octet_t*)&packet[triplet->offset];
	if(triplet->tag_octet.data_type == 0x1F){
		triplet->ext = 0x1F;
		triplet->offset = triplet->offset + 1;
	}

	triplet->length = (uint8_t)packet[triplet->offset + 1];

	if(triplet->length < ASN_BUFFER_SIZE){
		memory_set(triplet->value, 0x00, ASN_BUFFER_SIZE);
		memory_copy(triplet->value, (packet + triplet->offset + 2), triplet->length);
		return TRUE;	
	}
	return FALSE;
}

uint8_t decode_asn_tree(tlv_triplet_t * triplet, uint8_t * packet, uint32_t size){
	int count = 0;
	do{
		if(decode_asn_triplet(triplet, packet, size)){
			DEBUG_ALERT("Iteration : %d", count);
			display_ber_triplet(triplet);

			triplet->context = *(asn_octet_t *)&triplet->tag_octet;
			if(triplet->tag_octet.tag_nesting){
				triplet->offset = triplet->offset + 2;
			}

			if(!triplet->tag_octet.tag_nesting){
				triplet->offset = triplet->offset + *(asn_octet_t *)&triplet->length + 2;	
			}
		}
		count++;
	}
	while(triplet->offset < size);
	return count;
}

uint8_t decode_ber_oid(tlv_triplet_t * triplet, asn_ber_t * ber){
	*ber = *(asn_ber_t*)&triplet->value;
	return TRUE;
}

uint8_t display_conformance_block(conformance_block_t * block){
	DEBUG_OK("Conforfance Block :");
	DEBUG_OK("Block[1] :: placeholder_1 : %d", block->placeholder_1);
	DEBUG_OK("Block[2] :: general_protection : %d", block->general_protection);
	DEBUG_OK("Block[3] :: general_block_transfer : %d", block->general_block_transfer);
	DEBUG_OK("Block[4] :: read : %d", block->read);
	DEBUG_OK("Block[5] :: write : %d", block->write);
	DEBUG_OK("Block[6] :: unconfirmed_write : %d", block->unconfirmed_write);
	DEBUG_OK("Block[7] :: placeholder_2 : %d", block->placeholder_2);
	DEBUG_OK("Block[8] :: placeholder_3 : %d", block->placeholder_3);
	DEBUG_OK("Block[9] :: attr_0_supported_with_set : %d", block->attr_0_supported_with_set);
	DEBUG_OK("Block[10] :: priority_mgmt_supported : %d", block->priority_mgmt_supported);
	DEBUG_OK("Block[11] :: attr_0_supported_with_get : %d", block->attr_0_supported_with_get);
	DEBUG_OK("Block[12] :: block_transfer_with_get_or_read : %d", block->block_transfer_with_get_or_read);
	DEBUG_OK("Block[13] :: block_transfer_with_set_or_write : %d", block->block_transfer_with_set_or_write);
	DEBUG_OK("Block[14] :: block_transfer_with_action : %d", block->block_transfer_with_action);
	DEBUG_OK("Block[15] :: multiple_reference : %d", block->multiple_reference);
	DEBUG_OK("Block[16] :: data_notification : %d", block->data_notification);
	DEBUG_OK("Block[17] :: access : %d", block->access);
	DEBUG_OK("Block[18] :: parameterized_access : %d", block->parameterized_access);
	DEBUG_OK("Block[19] :: get : %d", block->get);
	DEBUG_OK("Block[20] :: set : %d", block->set);
	DEBUG_OK("Block[21] :: selective_access : %d", block->selective_access);
	DEBUG_OK("Block[22] :: event_notification : %d", block->event_notification);
	DEBUG_OK("Block[23] :: action : %d", block->action);
}

uint8_t decode_axdr_initiate_request(tlv_triplet_t * triplet, xDLMS_initiate_request_t * proposed_init_req){
	if(proposed_init_req && triplet){
		uint8_t octet_string_length = 0;
		if(!triplet->value[1]) proposed_init_req->dedicated_key = NULL;
		proposed_init_req->response_allowed = triplet->value[2];
		proposed_init_req->proposed_qos = triplet->value[3];
		proposed_init_req->proposed_dlms_version = triplet->value[4];
		if(triplet->value[5] & 0x1F == 0x1F){
			octet_string_length = triplet->value[7];
			proposed_init_req->proposed_conf_block = *(conformance_block_t*)&triplet->value[9];
			proposed_init_req->proposed_max_pdu_size = ((uint16_t)triplet->value[13] << 8) | triplet->value[12];
		}
		else{
			octet_string_length = triplet->value[6];
			proposed_init_req->proposed_conf_block = *(conformance_block_t*)&triplet->value[8];
			proposed_init_req->proposed_max_pdu_size = ((uint16_t)triplet->value[12] << 8) | triplet->value[11];
		}
		return TRUE;
	}
	return FALSE;
}

uint8_t axdr_decoder(tlv_triplet_t * triplet){
	if(triplet->value[0] == AXDR_BAD_TAG)
		{DEBUG_OK("xDLMS Tag : AXDR_BAD_TAG (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_INITIATE_REQUEST){
		DEBUG_OK("xDLMS Tag : AXDR_INITIATE_REQUEST (0x%02X)", triplet->value[0]);
		xDLMS_initiate_request_t proposed_init_req = {0};
		if(decode_axdr_initiate_request(triplet, &proposed_init_req)){
			DEBUG_OK("Proposed DLMS Version No : %d", proposed_init_req.proposed_dlms_version);
			DEBUG_OK("Proposed Max PDU Size : %d", proposed_init_req.proposed_max_pdu_size);
			DEBUG_OK("Proposed Conformance : %d", proposed_init_req.proposed_conf_block);
			display_conformance_block(&proposed_init_req.proposed_conf_block);
		}
	}
	else if(triplet->value[0] == AXDR_INITIATE_RESPONSE){
		DEBUG_OK("xDLMS Tag : AXDR_INITIATE_RESPONSE (0x%02X)", triplet->value[0]);
	}
	else if(triplet->value[0] == AXDR_GET_REQUEST)
		{DEBUG_OK("TxDLMS Tag : AXDR_GET_REQUEST (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_SET_REQUEST)
		{DEBUG_OK("xDLMS Tag : AXDR_SET_REQUEST (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_ACTION_REQUEST)
		{DEBUG_OK("xDLMS Tag : AXDR_ACTION_REQUEST (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_GET_RESPONSE)
		{DEBUG_OK("xDLMS Tag : AXDR_GET_RESPONSE (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_SET_RESPONSE)
		{DEBUG_OK("xDLMS Tag : AXDR_SET_RESPONSE (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_ACTION_RESPONSE)
		{DEBUG_OK("xDLMS Tag : AXDR_ACTION_RESPONSE (0x%02X)", triplet->value[0]);}
	else if(triplet->value[0] == AXDR_EXCEPTION_RESPONSE)
		{DEBUG_OK("xDLMS Tag : AXDR_EXCEPTION_RESPONSE (0x%02X)", triplet->value[0]);}
	else 
		{DEBUG_ERROR("Tag Class : Unidentified (0x%02X)", triplet->value[0]);}
}

void display_ber_triplet(tlv_triplet_t * triplet){
	DEBUG_OK("Octet Tag : 0x%02X", triplet->tag_octet);
	
	if(triplet->tag_octet.tag_class == TAG_UNIVERSAL_MASK)	
		{DEBUG_OK("Tag Class : Universal (0x%02X)", triplet->tag_octet.tag_class);}
	else if(triplet->tag_octet.tag_class == TAG_APPLICATION_MASK) 
		{DEBUG_OK("Tag Class : Application (0x%02X)", triplet->tag_octet.tag_class);}
	else if(triplet->tag_octet.tag_class == TAG_CONTEXT_SPECIFIC_MASK) 
		{DEBUG_OK("Tag Class : Context Specific (0x%02X)", triplet->tag_octet.tag_class);}
	else if(triplet->tag_octet.tag_class == TAG_PRIVATE_MASK) 
		{DEBUG_OK("Tag Class : Private (0x%02X)", triplet->tag_octet.tag_class);}

	if(triplet->tag_octet.tag_nesting == TAG_PRIMITIVE_MASK)	
		{DEBUG_OK("Is Nested : No (0x%02X)", triplet->tag_octet.tag_nesting);}
	else if(triplet->tag_octet.tag_nesting == TAG_CONSTRUCTED_MASK) 
		{DEBUG_OK("Is Nested : Yes (0x%02X)", triplet->tag_octet.tag_nesting);}

	if(triplet->tag_octet.tag_class == TAG_UNIVERSAL_MASK){
		if(triplet->tag_octet.data_type == BER_TYPE_BOOLEAN) 			
			{DEBUG_OK("Triplet Data Type : Boolean (0x%02X)", triplet->tag_octet.data_type);}
		else if(triplet->tag_octet.data_type == BER_TYPE_INTEGER) 		
			{DEBUG_OK("Triplet Data Type : Integer (0x%02X)", triplet->tag_octet.data_type);}
		else if(triplet->tag_octet.data_type == BER_TYPE_BIT_STRING) 
			{DEBUG_OK("Triplet Data Type : Bit String (0x%02X)", triplet->tag_octet.data_type);}
		else if(triplet->tag_octet.data_type == BER_TYPE_OCTET_STRING) {
			DEBUG_OK("Triplet Data Type : Octet String (0x%02X)", triplet->tag_octet.data_type);
			DEBUG_WARNING("xDLMS Component");
			axdr_decoder(triplet);
		}
		else if(triplet->tag_octet.data_type == BER_TYPE_NULL) 
			{DEBUG_OK("Triplet Data Type : NULL (0x%02X)", triplet->tag_octet.data_type);}
		else if(triplet->tag_octet.data_type == BER_TYPE_OBJECT_IDENTIFIER) {
			DEBUG_OK("Triplet Data Type : OID (0x%02X)", triplet->tag_octet.data_type);
			asn_ber_t ber;
			decode_ber_oid(triplet, &ber);
			if(ber.name == APP_CONTEXT_NAME) {
				DEBUG_OK("OID Name : APP_CONTEXT_NAME (0x%02X)", ber.name);
				if(ber.id == NO_REF_NO_CYPHERING) {DEBUG_OK("OID Name : NO_REF_NO_CYPHERING (0x%02X)", ber.id);}
				else if(ber.id == LN_REF_NO_CYPHERING) {DEBUG_OK("OID Name : LN_REF_NO_CYPHERING (0x%02X)", ber.id);}
				else if(ber.id == SN_REF_NO_CYPHERING) {DEBUG_OK("OID Name : SN_REF_NO_CYPHERING (0x%02X)", ber.id);}
				else if(ber.id == LN_REF_WITH_CYPHERING) {DEBUG_OK("OID Name : LN_REF_WITH_CYPHERING (0x%02X)", ber.id);}
				else if(ber.id == SN_REF_WITH_CYPHERING) {DEBUG_OK("OID Name : SN_REF_WITH_CYPHERING (0x%02X)", ber.id);}
				else {DEBUG_ERROR("OID Name : SN_REF_WITH_CYPHERING (0x%02X)", ber.id);}
			}
			else if(ber.name == SECURITY_MECHANISM_NAME) {
				DEBUG_OK("OID Name : SECURITY_MECHANISM_NAME (0x%02X)", ber.name);
				if(ber.id == AUTH_LOWEST_LEVEL) {DEBUG_OK("OID Name : AUTH_LOWEST_LEVEL (0x%02X)", ber.id);}
				else if(ber.id == AUTH_LOW_LEVEL) {DEBUG_OK("OID Name : AUTH_LOW_LEVEL (0x%02X)", ber.id);}
				else if(ber.id == AUTH_HIGH_LEVEL) {DEBUG_OK("OID Name : AUTH_HIGH_LEVEL (0x%02X)", ber.id);}
				else if(ber.id == AUTH_HIGH_LEVEL_MD5) {DEBUG_OK("OID Name : AUTH_HIGH_LEVEL_MD5 (0x%02X)", ber.id);}
				else if(ber.id == AUTH_HIGH_LEVEL_SHA1) {DEBUG_OK("OID Name : AUTH_HIGH_LEVEL_SHA1 (0x%02X)", ber.id);}
				else if(ber.id == AUTH_HIGH_LEVEL_GMAC) {DEBUG_OK("OID Name : AUTH_HIGH_LEVEL_GMAC (0x%02X)", ber.id);}
				else if(ber.id == AUTH_HIGH_LEVEL_SHA256) {DEBUG_OK("OID Name : AUTH_HIGH_LEVEL_SHA256 (0x%02X)", ber.id);}
				else {DEBUG_ERROR("OID Name : AUTH_HIGH_LEVEL_SHA256 (0x%02X)", ber.id);}
			}
		}
	}
	else{
		int decoded_tag = *(asn_octet_t *)&triplet->tag_octet;

		if(decoded_tag == ASCE_AARQ) 			
			{DEBUG_OK("Triplet Data Type : ASCE_AARQ (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLED_AP_TITLE) 	
			{DEBUG_OK("Triplet Data Type : AARQ_CALLED_AP_TITLE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLED_AE_QUALIFIER) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLED_AE_QUALIFIER (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLED_AP_INVOC_ID) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLED_AP_INVOC_ID (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLED_AE_INVOC_ID) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLED_AE_INVOC_ID (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLING_AP_TITLE) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLING_AP_TITLE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLING_AE_QUALIFIER) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLING_AE_QUALIFIER (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLING_AP_INVOC_ID) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLING_AP_INVOC_ID (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLING_AE_INVOC_ID) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLING_AE_INVOC_ID (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_SENDER_ACSE_REQU) 
			{DEBUG_OK("Triplet Data Type : AARQ_SENDER_ACSE_REQU (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_REQ_MECHANISM_NAME) 
			{DEBUG_OK("Triplet Data Type : AARQ_REQ_MECHANISM_NAME (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_CALLING_AUTH_VALUE) 
			{DEBUG_OK("Triplet Data Type : AARQ_CALLING_AUTH_VALUE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_IMPLEMENTATION_INFO) 
			{DEBUG_OK("Triplet Data Type : AARQ_IMPLEMENTATION_INFO (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARQ_USER_INFORMATION) 
			{DEBUG_OK("Triplet Data Type : AARQ_USER_INFORMATION (0x%02X)", triplet->tag_octet.data_type);}

		else if(decoded_tag == ASCE_AARE) 
			{DEBUG_OK("Triplet Data Type : ASCE_AARE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESP_AUTH_VALUE) 
			{DEBUG_OK("Triplet Data Type : AARE_RESP_AUTH_VALUE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESP_MECHANISM_NAME) 
			{DEBUG_OK("Triplet Data Type : AARE_RESP_MECHANISM_NAME (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESPONDER_ACSE_REQ) 
			{DEBUG_OK("Triplet Data Type : AARE_RESPONDER_ACSE_REQ (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESP_AP_TITLE) 
			{DEBUG_OK("Triplet Data Type : AARE_RESP_AP_TITLE (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESULT_FIELD) 
			{DEBUG_OK("Triplet Data Type : AARE_RESULT_FIELD (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESULT_SRC_DIAG) 
			{DEBUG_OK("Triplet Data Type : AARE_RESULT_SRC_DIAG (0x%02X)", triplet->tag_octet.data_type);}
		else if(decoded_tag == AARE_RESULT_SERVICE_USER) 
			{DEBUG_OK("Triplet Data Type : AARE_RESULT_SERVICE_USER (0x%02X)", triplet->tag_octet.data_type);}
		else 
			{DEBUG_ERROR("Triplet Data Type : Unidentified Tag (0x%02X)", triplet->tag_octet.data_type);}

	}

	DEBUG_OK("Triplet Length : %d", triplet->length);
	DEBUG_ARRAY("Triplet Value", triplet->value, triplet->length, "%02X ");
	DEBUG("\r\n");
}

// decode_object_id(){

// }