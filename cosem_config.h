#ifndef COSEM_CONFIG_H
#define COSEM_CONFIG_H

// INIT RESPONSE ELEMENTS
#define QUALITY_OF_SERVICE 					(0x00)
#define DLMS_VERSION_NUMBER					(0x06)
#define MAX_PDU_SIZE 						(0x0400)
// CONFORMANCE BLOCK ELEMENTS
#define GENERAL_PROTECTION					(0)
#define GENERAL_BLOCK_TRANSFER 				(0)
#define READ 								(0)
#define WRITE 								(0)
#define UNCONFIREMED_WRITE					(0)
#define ATTR_0_SUPPORTED_WITH_SET 			(0)
#define PRIORITY_MGMGT_SUPPORTED			(1)
#define ATTR_0_SUPPORTED_WITH_GET 			(1)
#define BLOCK_TRANSFER_WITH_GET_OR_READ		(1)
#define BLOCK_TRANSFER_WITH_SET_OR_WRITE	(1)
#define BLOCK_TRANSFER_WITH_ACTION 			(0)
#define MULTIPLE_REFERENCE					(0)
#define DATA_NOTIFICATION 					(1)
#define ACCESS 								(0)
#define PARAMETERIZED_ACCESS 				(1)
#define GET 								(1)
#define SET 								(1)
#define SELECTIVE_ACCESS 					(0)
#define EVENT_NOTIFICATION 					(0)
#define ACTION 								(0)

#endif // COSEM_CONFIG_H