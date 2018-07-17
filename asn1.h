#ifndef ASN1_H
#define ASN1_H

#include <stdint.h>

#define ASN_BUFFER_SIZE		256

typedef uint16_t asn_tag_t;
typedef uint32_t asn_length_t;
typedef uint8_t asn_octet_t;
typedef uint8_t asn_flag_t;

typedef struct asn_ber asn_ber_t;
typedef struct asn_tag_octet asn_tag_octet_t;
typedef struct tlv_triplet tlv_triplet_t;

enum class_tag{
    TAG_UNIVERSAL           = 0x00,
    TAG_APPLICATION         = 0x40,
    TAG_CONTEXT_SPECIFIC    = 0x80,
    TAG_PRIVATE             = 0xC0,
};

enum class_tag_bit_mask{
    TAG_UNIVERSAL_MASK           = 0b00,
    TAG_APPLICATION_MASK         = 0b01,
    TAG_CONTEXT_SPECIFIC_MASK    = 0b10,
    TAG_PRIVATE_MASK             = 0b11,
};

enum nesting_tag{
    TAG_PRIMITIVE = 0x00,
    TAG_CONSTRUCTED	= 0x20,
};

enum nesting_tag_bit_mask{
    TAG_PRIMITIVE_MASK 		= 0b00,
    TAG_CONSTRUCTED_MASK	= 0b01,
};

enum asn_data_types{
    BER_TYPE_EOC                = 0x00,
    BER_TYPE_BOOLEAN            = 0x01,
    BER_TYPE_INTEGER            = 0x02,
    BER_TYPE_BIT_STRING         = 0x03,
    BER_TYPE_OCTET_STRING       = 0x04,
    BER_TYPE_NULL               = 0x05,
    BER_TYPE_OBJECT_IDENTIFIER  = 0x06,
};

struct asn_tag_octet{
	uint8_t data_type 		: 5;
	uint8_t tag_nesting     : 1;
	uint8_t tag_class 	    : 2;
};

struct tlv_triplet{
	asn_tag_octet_t			tag_octet;
	asn_length_t 			length;
	asn_octet_t   	        value[ASN_BUFFER_SIZE];
    asn_octet_t             context;
    asn_octet_t             ext;
    asn_octet_t             offset;
};

struct asn_ber{
    uint8_t header[5];   //< 5 bytes values representing the Organisation ID, always  60 85 74 05 08 for Cosem (see chapter 11.4 page 398)
    uint8_t name;       //< name object
    uint8_t id;         //< id object
};

// uint8_t decode_asn_triplet(tlv_triplet_t * triplet, uint8_t * packet, uint32_t size);
uint8_t decode_asn_triplet( tlv_triplet_t * triplet, uint8_t * packet, uint32_t size );

#endif // ASN1_H
