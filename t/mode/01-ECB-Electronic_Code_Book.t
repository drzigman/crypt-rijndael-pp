#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use MooseX::Params::Validate;

use Crypt::Rijndael;
use Crypt::Rijndael::PP;

use Readonly;
Readonly my $TEST_VALUES => {
    128 => {
        input       => [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, ],
        key         => [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ],
        cipher_text => [ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, ],
    },
    192 => {
        input       => [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, ],
        key         => [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, ],
        cipher_text => [ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, ],
    },
    256 => {
        input       => [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, ],
        key         => [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, ],
        cipher_text => [ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, ],
    },
};

subtest 'Encryption with 128 Bit Key' => sub {
    test_rijndael_xs_encryption( $TEST_VALUES->{128} );
    test_rijndael_pp_encryption( $TEST_VALUES->{128} );
};

subtest 'Encryption with 192 Bit Key' => sub {
    test_rijndael_xs_encryption( $TEST_VALUES->{192} );
    test_rijndael_pp_encryption( $TEST_VALUES->{192} );
};

subtest 'Encryption with 256 Bit Key' => sub {
    test_rijndael_xs_encryption( $TEST_VALUES->{256} );
    test_rijndael_pp_encryption( $TEST_VALUES->{256} );
};

done_testing;

sub test_rijndael_xs_encryption {
    my ( $case ) = pos_validated_list( \@_, { isa => 'HashRef' } );

    my $packed_input       = pack( "C*", @{ $case->{input} } );
    my $packed_cipher_key  = pack( "C*", @{ $case->{key} } );
    my $packed_expected_cipher_text = pack( "C*", @{ $case->{cipher_text} } );

    my $cipher;
    lives_ok {
        $cipher = Crypt::Rijndael->new(
            $packed_cipher_key, Crypt::Rijndael::MODE_ECB()
        );
    } 'Lives through construction of Cipher';

    my $cipher_text;
    lives_ok {
        $cipher_text = $cipher->encrypt( $packed_input );
    } 'Lives through encryption';

    cmp_ok( unpack( "H*", $cipher_text ), 'eq',
        unpack( "H*", $packed_expected_cipher_text ), "Correct Cipher Text" );

    return;
}

sub test_rijndael_pp_encryption {
    my ( $case ) = pos_validated_list( \@_, { isa => 'HashRef' } );

    my $packed_input       = pack( "C*", @{ $case->{input} } );
    my $packed_cipher_key  = pack( "C*", @{ $case->{key} } );
    my $packed_expected_cipher_text = pack( "C*", @{ $case->{cipher_text} } );

    my $cipher;
    lives_ok {
        $cipher = Crypt::Rijndael::PP->new(
            $packed_cipher_key, Crypt::Rijndael::PP::MODE_ECB()
        );
    } 'Lives through construction of Cipher';

    my $cipher_text;
    lives_ok {
        $cipher_text = $cipher->encrypt( $packed_input );
    } 'Lives through encryption';

    cmp_ok( unpack( "H*", $cipher_text ), 'eq',
        unpack( "H*", $packed_expected_cipher_text ), "Correct Cipher Text" );

    return;
}
