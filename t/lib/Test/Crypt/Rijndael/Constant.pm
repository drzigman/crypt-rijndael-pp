package Test::Crypt::Rijndael::Constant;

use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = qw(
    $DEFAULT_IV

    $ONE_BLOCK_INPUT $TWO_BLOCK_INPUT $THREE_BLOCK_INPUT
    $INPUT_BLOCKS

    $KEY_128_BIT $KEY_192_BIT $KEY_256_BIT
    $KEYS

    $CIPHER_TEXT
    $CBC_CIPHER_TEXT
);

use Readonly;

Readonly our $DEFAULT_IV => 'a' x 16;

Readonly our $ONE_BLOCK_INPUT =>
    [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, ];
Readonly our $TWO_BLOCK_INPUT =>
    [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0xab, 0xcd, 0xef, 0x98, 0x76, 0x54, 0x32, 0x10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, ];
Readonly our $THREE_BLOCK_INPUT =>
    [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0xab, 0xcd, 0xef, 0x98, 0x76, 0x54, 0x32, 0x10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
      0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0x41, 0x52, 0x63, 0x74, ];

Readonly our $INPUT_BLOCKS => {
    1 => $ONE_BLOCK_INPUT,
    2 => $TWO_BLOCK_INPUT,
    3 => $THREE_BLOCK_INPUT,
};

Readonly our $KEY_128_BIT =>
    [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ];
Readonly our $KEY_192_BIT =>
    [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, ];
Readonly our $KEY_256_BIT =>
    [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, ];

Readonly our $KEYS => {
    128 => $KEY_128_BIT,
    192 => $KEY_192_BIT,
    256 => $KEY_256_BIT,
};

Readonly our $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_ECB =>
    [ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_ECB =>
    [ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
      0xe3, 0x73, 0xd1, 0x26, 0xc8, 0xb1, 0xaa, 0x0a, 0xc0, 0xa6, 0xd4, 0xb2, 0x08, 0x5a, 0x6d, 0xeb, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_ECB =>
    [ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
      0xe3, 0x73, 0xd1, 0x26, 0xc8, 0xb1, 0xaa, 0x0a, 0xc0, 0xa6, 0xd4, 0xb2, 0x08, 0x5a, 0x6d, 0xeb,
      0xc8, 0x10, 0x46, 0x51, 0xa2, 0x01, 0x76, 0x6c, 0xf1, 0xd2, 0xb4, 0xa4, 0xad, 0x1d, 0x73, 0xee, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_ECB =>
    [ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_ECB =>
    [ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
      0xd5, 0x8b, 0x73, 0x49, 0x14, 0x72, 0x63, 0x07, 0x7b, 0x29, 0x55, 0xbd, 0x91, 0xef, 0xd1, 0xb2 ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_ECB =>
    [ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
      0xd5, 0x8b, 0x73, 0x49, 0x14, 0x72, 0x63, 0x07, 0x7b, 0x29, 0x55, 0xbd, 0x91, 0xef, 0xd1, 0xb2,
      0x56, 0xfa, 0x2a, 0x25, 0x97, 0x39, 0xf8, 0xa1, 0x9f, 0x87, 0x17, 0x25, 0xbb, 0x94, 0x67, 0x9b, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_ECB =>
    [ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_ECB =>
    [ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
      0xdf, 0xbd, 0xe6, 0xa2, 0xaa, 0x5e, 0xfe, 0xa0, 0xd7, 0xac, 0x0d, 0xc7, 0x6b, 0x72, 0x6e, 0x38, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_ECB =>
    [ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
      0xdf, 0xbd, 0xe6, 0xa2, 0xaa, 0x5e, 0xfe, 0xa0, 0xd7, 0xac, 0x0d, 0xc7, 0x6b, 0x72, 0x6e, 0x38,
      0x76, 0x05, 0xe8, 0x70, 0x7d, 0xae, 0x76, 0xa1, 0x55, 0x29, 0x37, 0xd4, 0x5c, 0xb7, 0x41, 0x58, ];

Readonly our $ECB_CIPHER_TEXT => {
    1 => {
        128 => $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_ECB,
        192 => $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_ECB,
        256 => $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_ECB,
    },
    2 => {
        128 => $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_ECB,
        192 => $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_ECB,
        256 => $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_ECB,
    },
    3 => {
        128 => $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_ECB,
        192 => $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_ECB,
        256 => $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_ECB,
    },
};

Readonly our $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CBC =>
    [ 0x41, 0x6b, 0xd0, 0xb3, 0x7b, 0x2e, 0xb6, 0x7b, 0xce, 0x2c, 0xd9, 0x98, 0x89, 0xa7, 0x72, 0xef, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CBC =>
    [ 0x41, 0x6b, 0xd0, 0xb3, 0x7b, 0x2e, 0xb6, 0x7b, 0xce, 0x2c, 0xd9, 0x98, 0x89, 0xa7, 0x72, 0xef,
      0x9b, 0x85, 0x31, 0x41, 0x26, 0x81, 0xd5, 0x72, 0xda, 0x0c, 0xb3, 0xb8, 0x25, 0xdc, 0x35, 0xaf, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CBC =>
    [ 0x41, 0x6b, 0xd0, 0xb3, 0x7b, 0x2e, 0xb6, 0x7b, 0xce, 0x2c, 0xd9, 0x98, 0x89, 0xa7, 0x72, 0xef,
      0x9b, 0x85, 0x31, 0x41, 0x26, 0x81, 0xd5, 0x72, 0xda, 0x0c, 0xb3, 0xb8, 0x25, 0xdc, 0x35, 0xaf,
      0x15, 0xc2, 0x35, 0x51, 0xe7, 0x2d, 0x3f, 0x10, 0xf3, 0x8e, 0x88, 0x65, 0x2b, 0xc5, 0xfe, 0x8e, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CBC =>
    [ 0x36, 0x67, 0xa8, 0xcc, 0x0d, 0x29, 0xfd, 0xae, 0x7f, 0x79, 0x83, 0xcf, 0x87, 0x17, 0xc5, 0xe4, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CBC =>
    [ 0x36, 0x67, 0xa8, 0xcc, 0x0d, 0x29, 0xfd, 0xae, 0x7f, 0x79, 0x83, 0xcf, 0x87, 0x17, 0xc5, 0xe4,
      0x90, 0x1e, 0x97, 0x81, 0x41, 0x79, 0x7c, 0xae, 0x03, 0x6c, 0x9e, 0x2a, 0x69, 0x9c, 0x39, 0x59, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CBC =>
    [ 0x36, 0x67, 0xa8, 0xcc, 0x0d, 0x29, 0xfd, 0xae, 0x7f, 0x79, 0x83, 0xcf, 0x87, 0x17, 0xc5, 0xe4,
      0x90, 0x1e, 0x97, 0x81, 0x41, 0x79, 0x7c, 0xae, 0x03, 0x6c, 0x9e, 0x2a, 0x69, 0x9c, 0x39, 0x59,
      0x89, 0xd7, 0xc5, 0x30, 0x60, 0xe0, 0xaa, 0xcd, 0xce, 0xbd, 0x7e, 0xc8, 0x94, 0x93, 0xca, 0x1d, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CBC =>
    [ 0xc8, 0x30, 0x5a, 0xff, 0xaa, 0xef, 0x80, 0x30, 0x11, 0xe8, 0xab, 0x78, 0xb3, 0x29, 0xa3, 0x8d, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CBC =>
    [ 0xc8, 0x30, 0x5a, 0xff, 0xaa, 0xef, 0x80, 0x30, 0x11, 0xe8, 0xab, 0x78, 0xb3, 0x29, 0xa3, 0x8d,
      0x5d, 0x7c, 0x5b, 0xe0, 0x3c, 0xea, 0x60, 0xc1, 0x42, 0x5c, 0x6d, 0x5c, 0x9c, 0x76, 0x55, 0xec, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CBC =>
    [ 0xc8, 0x30, 0x5a, 0xff, 0xaa, 0xef, 0x80, 0x30, 0x11, 0xe8, 0xab, 0x78, 0xb3, 0x29, 0xa3, 0x8d,
      0x5d, 0x7c, 0x5b, 0xe0, 0x3c, 0xea, 0x60, 0xc1, 0x42, 0x5c, 0x6d, 0x5c, 0x9c, 0x76, 0x55, 0xec,
      0x0d, 0xee, 0xd7, 0x56, 0xd6, 0x36, 0x7b, 0xc8, 0xe2, 0x4c, 0x29, 0xce, 0xd8, 0x84, 0x2d, 0x32, ];

Readonly our $CBC_CIPHER_TEXT => {
    1 => {
        128 => $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CBC,
        192 => $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CBC,
        256 => $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CBC,
    },
    2 => {
        128 => $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CBC,
        192 => $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CBC,
        256 => $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CBC,
    },
    3 => {
        128 => $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CBC,
        192 => $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CBC,
        256 => $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CBC,
    },
};

Readonly our $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CTR =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CTR =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0xb2, 0x3c, 0xa5, 0x32, 0xaf, 0x6a, 0x7c, 0x15, 0x90, 0x3e, 0xb0, 0x0f, 0x7b, 0xe6, 0x51, 0xf3, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CTR =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0xb2, 0x3c, 0xa5, 0x32, 0xaf, 0x6a, 0x7c, 0x15, 0x90, 0x3e, 0xb0, 0x0f, 0x7b, 0xe6, 0x51, 0xf3,
      0xd4, 0x49, 0xdc, 0x74, 0xce, 0x14, 0x60, 0x74, 0x6f, 0x90, 0x05, 0x96, 0x47, 0xbe, 0x12, 0xc5, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CTR =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CTR =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x81, 0x23, 0x5a, 0x4d, 0x04, 0xb1, 0xcd, 0xf2, 0x65, 0xd6, 0xff, 0x04, 0xf9, 0xb6, 0x60, 0xde, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CTR =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x81, 0x23, 0x5a, 0x4d, 0x04, 0xb1, 0xcd, 0xf2, 0x65, 0xd6, 0xff, 0x04, 0xf9, 0xb6, 0x60, 0xde,
      0xd5, 0x6b, 0x57, 0x69, 0x7a, 0x81, 0xed, 0x43, 0xb3, 0x37, 0x6d, 0x4b, 0xea, 0x2d, 0x5d, 0x79, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CTR =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CTR =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x18, 0x6f, 0x6b, 0x0e, 0xcd, 0x7a, 0x6a, 0x33, 0xde, 0x5f, 0x72, 0x35, 0xf8, 0xcf, 0x88, 0xfe, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CTR =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x18, 0x6f, 0x6b, 0x0e, 0xcd, 0x7a, 0x6a, 0x33, 0xde, 0x5f, 0x72, 0x35, 0xf8, 0xcf, 0x88, 0xfe,
      0xd2, 0xcf, 0x68, 0x19, 0xcc, 0xa0, 0x7f, 0x3b, 0x40, 0x77, 0xb8, 0x41, 0x86, 0x2d, 0xc8, 0x4f, ];

Readonly our $CTR_CIPHER_TEXT => {
    1 => {
        128 => $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CTR,
        192 => $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CTR,
        256 => $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CTR,
    },
    2 => {
        128 => $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CTR,
        192 => $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CTR,
        256 => $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CTR,
    },
    3 => {
        128 => $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CTR,
        192 => $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CTR,
        256 => $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CTR,
    },
};

Readonly our $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0xc4, 0x9e, 0x6e, 0x7e, 0x24, 0xc7, 0xa6, 0x19, 0xfc, 0xef, 0x1f, 0x68, 0x73, 0x09, 0x2c, 0xc2, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0xc4, 0x9e, 0x6e, 0x7e, 0x24, 0xc7, 0xa6, 0x19, 0xfc, 0xef, 0x1f, 0x68, 0x73, 0x09, 0x2c, 0xc2,
      0x42, 0x1d, 0xf5, 0x55, 0x2a, 0x7f, 0x5d, 0xb9, 0x3b, 0x39, 0x9a, 0xa2, 0x24, 0xf5, 0x33, 0xb5, ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x4f, 0x40, 0x94, 0x1c, 0x5a, 0x74, 0x41, 0xa9, 0xc0, 0xd2, 0x73, 0x6b, 0x90, 0xd1, 0x5d, 0x76, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x4f, 0x40, 0x94, 0x1c, 0x5a, 0x74, 0x41, 0xa9, 0xc0, 0xd2, 0x73, 0x6b, 0x90, 0xd1, 0x5d, 0x76,
      0x43, 0xa5, 0x78, 0x21, 0xfa, 0xc7, 0xbd, 0xf8, 0x60, 0x13, 0x47, 0xaa, 0x5f, 0x26, 0x3f, 0x78 ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x38, 0xda, 0x54, 0x13, 0xd8, 0x4c, 0xbc, 0x49, 0xeb, 0x26, 0xee, 0xcf, 0x91, 0x3a, 0xe4, 0x7b, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x38, 0xda, 0x54, 0x13, 0xd8, 0x4c, 0xbc, 0x49, 0xeb, 0x26, 0xee, 0xcf, 0x91, 0x3a, 0xe4, 0x7b,
      0x46, 0x81, 0x1f, 0x14, 0x6e, 0xe5, 0x02, 0xa3, 0xbc, 0xb7, 0x9d, 0x0b, 0xde, 0xe7, 0xb3, 0x3f ];

Readonly our $CFB_CIPHER_TEXT => {
    1 => {
        128 => $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_CFB,
        192 => $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_CFB,
        256 => $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_CFB,
    },
    2 => {
        128 => $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_CFB,
        192 => $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_CFB,
        256 => $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_CFB,
    },
    3 => {
        128 => $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_CFB,
        192 => $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_CFB,
        256 => $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_CFB,
    },
};

Readonly our $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_OFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_OFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0x84, 0x94, 0x5f, 0x69, 0x14, 0xed, 0x92, 0x16, 0x99, 0xc7, 0x99, 0xd3, 0x0b, 0xf6, 0xa1, 0x3f, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_OFB =>
    [ 0xb8, 0x51, 0xd9, 0x93, 0x81, 0x06, 0x2d, 0x0b, 0x9b, 0xa2, 0x46, 0x40, 0xd7, 0xba, 0xa3, 0x0c,
      0x84, 0x94, 0x5f, 0x69, 0x14, 0xed, 0x92, 0x16, 0x99, 0xc7, 0x99, 0xd3, 0x0b, 0xf6, 0xa1, 0x3f,
      0x6e, 0xcb, 0x03, 0xbf, 0xa8, 0xe8, 0x9b, 0x04, 0x9c, 0x65, 0xdc, 0x36, 0x3a, 0x73, 0xe8, 0x95 ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_OFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_OFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x30, 0x79, 0xa1, 0x4b, 0x25, 0x40, 0x38, 0x67, 0x5f, 0x56, 0xf0, 0x80, 0x4b, 0x92, 0x1a, 0xdc, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_OFB =>
    [ 0x18, 0x05, 0xc5, 0x30, 0xae, 0x30, 0x82, 0x51, 0x8a, 0xaa, 0xc7, 0xd4, 0xcb, 0xa5, 0xdf, 0x23,
      0x30, 0x79, 0xa1, 0x4b, 0x25, 0x40, 0x38, 0x67, 0x5f, 0x56, 0xf0, 0x80, 0x4b, 0x92, 0x1a, 0xdc,
      0x98, 0x48, 0xe2, 0xc9, 0xb1, 0x5f, 0x03, 0x11, 0x9b, 0x17, 0xfe, 0x8d, 0x57, 0x56, 0xf9, 0x77 ];

Readonly our $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_OFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57, ];
Readonly our $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_OFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x36, 0xa1, 0x39, 0x9b, 0x1a, 0x0e, 0xff, 0xe0, 0x66, 0xfe, 0x53, 0x3f, 0x5b, 0x95, 0x1a, 0xff, ];
Readonly our $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_OFB =>
    [ 0xe7, 0x42, 0xe6, 0xb8, 0xfa, 0xf7, 0x52, 0x57, 0x2a, 0xb2, 0xb4, 0xda, 0xec, 0x1b, 0xa7, 0x57,
      0x36, 0xa1, 0x39, 0x9b, 0x1a, 0x0e, 0xff, 0xe0, 0x66, 0xfe, 0x53, 0x3f, 0x5b, 0x95, 0x1a, 0xff,
      0x5f, 0x57, 0xee, 0xfe, 0x68, 0xa5, 0xdc, 0x68, 0x13, 0xb8, 0x67, 0x5f, 0xc9, 0xfd, 0x25, 0xbb ];

Readonly our $OFB_CIPHER_TEXT => {
    1 => {
        128 => $CIPHER_TEXT_ONE_BLOCK_128_BIT_KEY_OFB,
        192 => $CIPHER_TEXT_ONE_BLOCK_192_BIT_KEY_OFB,
        256 => $CIPHER_TEXT_ONE_BLOCK_256_BIT_KEY_OFB,
    },
    2 => {
        128 => $CIPHER_TEXT_TWO_BLOCK_128_BIT_KEY_OFB,
        192 => $CIPHER_TEXT_TWO_BLOCK_192_BIT_KEY_OFB,
        256 => $CIPHER_TEXT_TWO_BLOCK_256_BIT_KEY_OFB,
    },
    3 => {
        128 => $CIPHER_TEXT_THREE_BLOCK_128_BIT_KEY_OFB,
        192 => $CIPHER_TEXT_THREE_BLOCK_192_BIT_KEY_OFB,
        256 => $CIPHER_TEXT_THREE_BLOCK_256_BIT_KEY_OFB,
    },
};

Readonly our $CIPHER_TEXT => {
    ECB => $ECB_CIPHER_TEXT,
    CBC => $CBC_CIPHER_TEXT,
    CTR => $CTR_CIPHER_TEXT,
    CFB => $CFB_CIPHER_TEXT,
    OFB => $OFB_CIPHER_TEXT,
};

1;
