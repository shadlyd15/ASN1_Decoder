#ifndef xDLMS_H
#define xDLMS_H

#include "asn1.h"

#define CONFORMANCE_TAG     (0x31)

enum axdr_tag{
    AXDR_TAG_NULL           = 0U,
    AXDR_TAG_ARRAY          = 1U,
    AXDR_TAG_STRUCTURE      = 2U,
    AXDR_TAG_BOOLEAN        = 3U,
    AXDR_TAG_BITSTRING      = 4U,
    AXDR_TAG_INTEGER32      = 5U,
    AXDR_TAG_UNSIGNED32     = 6U,
    AXDR_TAG_OCTETSTRING    = 9U,
    AXDR_TAG_VISIBLESTRING  = 10U,
    AXDR_TAG_UTF8_STRING    = 12U,
    AXDR_TAG_BCD            = 13U,
    AXDR_TAG_INTEGER8       = 15U,
    AXDR_TAG_INTEGER16      = 16U,
    AXDR_TAG_UNSIGNED8      = 17U,
    AXDR_TAG_UNSIGNED16     = 18U,
    AXDR_TAG_INTEGER64      = 20U,
    AXDR_TAG_UNSIGNED64     = 21U,
    AXDR_TAG_ENUM           = 22U,
    AXDR_TAG_UNKNOWN        = 255U
};

enum xdlms_tag{
    AXDR_BAD_TAG            = 0U,
    AXDR_INITIATE_REQUEST   = 1U,
    AXDR_INITIATE_RESPONSE  = 8U,
    AXDR_GET_REQUEST        = 192U,
    AXDR_SET_REQUEST        = 193U,
    AXDR_ACTION_REQUEST     = 195U,
    AXDR_GET_RESPONSE       = 196U,
    AXDR_SET_RESPONSE       = 197U,
    AXDR_ACTION_RESPONSE    = 199U,
    AXDR_EXCEPTION_RESPONSE = 216U
};

// struct xDLMS_initiate_request{
//     asn_octet_t * dedicated_key;
//     asn_octet_t response_allowed;
//     asn_octet_t proposed_qos;
//     asn_octet_t proposed_dlms_version;
//     proposed-conformance Conformance,
//     client-max-received-pdu-size
// };

#endif // xDLMS_H