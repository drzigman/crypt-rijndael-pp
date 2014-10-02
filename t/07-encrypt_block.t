#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use Crypt::Rijndael::PP;

use Readonly;
Readonly my @INPUT => (
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
);

Readonly my @CIPHER_KEY => (
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
);

Readonly my @EXPECTED_CIPHER_TEXT => (
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
);

subtest "Encryption with 128 Bit Key" => sub {
    my $packed_input       = pack( "C*", @INPUT );
    my $packed_cipher_key  = pack( "C*", @CIPHER_KEY );
    my $packed_expected_cipher_text = pack( "C*", @EXPECTED_CIPHER_TEXT );

    my $cipher_text;
    lives_ok {
        $cipher_text = Crypt::Rijndael::PP->encrypt_block(
            $packed_input, $packed_cipher_key
        );
    } "Lives through encryption of a block";

    cmp_ok( unpack( "H*", $packed_expected_cipher_text ), 'eq',
        unpack( "H*", $cipher_text ), "Correct Cipher Text" );
};

done_testing;
