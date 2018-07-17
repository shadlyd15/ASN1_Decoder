#include "cosem_association.h"

uint8_t parse_asso_aarq(){

}

uint32_t create_aare_packet(){

}

conformance_block_t generate_conformance_block(){
	conformance_block_t conformance_block = {0};
	conformance_block.general_protection = GENERAL_PROTECTION;
	conformance_block.general_block_transfer = GENERAL_BLOCK_TRANSFER;
	conformance_block.read = READ;
	conformance_block.write = WRITE;
	conformance_block.unconfirmed_write = UNCONFIREMED_WRITE;
	conformance_block.attr_0_supported_with_set = ATTR_0_SUPPORTED_WITH_SET;
	conformance_block.priority_mgmt_supported = PRIORITY_MGMGT_SUPPORTED;
	conformance_block.attr_0_supported_with_get = ATTR_0_SUPPORTED_WITH_GET;
	conformance_block.block_transfer_with_get_or_read = BLOCK_TRANSFER_WITH_GET_OR_READ;
	conformance_block.block_transfer_with_set_or_write = BLOCK_TRANSFER_WITH_SET_OR_WRITE;
	conformance_block.block_transfer_with_action = BLOCK_TRANSFER_WITH_ACTION;
	conformance_block.multiple_reference = MULTIPLE_REFERENCE;
	conformance_block.data_notification = DATA_NOTIFICATION;
	conformance_block.access = ACCESS;
	conformance_block.parameterized_access = PARAMETERIZED_ACCESS;
	conformance_block.get = GET;
	conformance_block.set = SET;
	conformance_block.selective_access = SELECTIVE_ACCESS;
	conformance_block.event_notification = EVENT_NOTIFICATION;
	conformance_block.action = ACTION;
	return conformance_block;
}

uint32_t create_initate_request_packet(uint8_t * packet){
	packet[0] = AXDR_INITIATE_RESPONSE;
}