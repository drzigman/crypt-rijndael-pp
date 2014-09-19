#!/usr/bin/env perl

use strict;
use warnings;

use Data::Dumper;
use Test::Exception;
use Test::More;

use Storable qw( dclone );

use Crypt::Rijndael::PP;

use Readonly;
Readonly my @INPUT => (
    0xd4, 0xbf, 0x5d, 0x30,
    0xe0, 0xb4, 0x52, 0xae,
    0xb8, 0x41, 0x11, 0xf1,
    0x1e, 0x27, 0x98, 0xe5,
);

Readonly my @EXPECTED_OUTPUT => (
    0x04, 0x66, 0x81, 0xe5,
    0xe0, 0xcb, 0x19, 0x9a,
    0x48, 0xf8, 0xd3, 0x7a,
    0x28, 0x06, 0x26, 0x4c,
);

Readonly my $LEFT_FACTOR  => 0x57;
Readonly my $RIGHT_FACTOR => 0x83;
Readonly my $GF_PRODUCT   => 0xc1;

Readonly my @COLUMN       => ( 0xd4, 0xbf, 0x5d, 0x30 );
Readonly my @MIXED_COLUMN => ( 0x04, 0x66, 0x81, 0xe5 );

subtest "Multiple Values in GF(2^8)" => sub {
    my $left_factor  = pack( "C*", $LEFT_FACTOR );
    my $right_factor = pack( "C*", $RIGHT_FACTOR );
    my $expected_gf_product = pack( "C*", $GF_PRODUCT );

    my $gf_product;
    lives_ok {
        $gf_product = Crypt::Rijndael::PP->_gf_multiplication(
            $left_factor, $right_factor
        );
    } "Lives through GF Multiplication";

    is_deeply( $gf_product, $expected_gf_product,
        "Correct gf multiplication product" );
};

done_testing;
exit;

subtest "Mix Individual Column" => sub {
    my $packed_column       = pack( "C*", @COLUMN );
    my $packed_mixed_column = pack( "C*", @MIXED_COLUMN );

    my $unmixed_column = [
        unpack("x0a", $packed_column),
        unpack("x1a", $packed_column),
        unpack("x2a", $packed_column),
        unpack("x3a", $packed_column),
    ];

    my $column = $unmixed_column;

    lives_ok {
        Crypt::Rijndael::PP->_mix_column( $column );
    } "Lives through column mixing";

    is_deeply( $column, [
        unpack("x0a", $packed_mixed_column),
        unpack("x1a", $packed_mixed_column),
        unpack("x2a", $packed_mixed_column),
        unpack("x3a", $packed_mixed_column),
    ], "Correct Resultant Column" );
};

done_testing;
exit;

subtest "Perform Mix Columns on Input State" => sub {
    my $packed_input = pack( "C*", @INPUT );
    my $state = Crypt::Rijndael::PP->_input_to_state( $packed_input );

    my $packed_expected_output = pack( "C*", @EXPECTED_OUTPUT );
    my $expected_state = Crypt::Rijndael::PP->_input_to_state(
        $packed_expected_output
    );

    my $updated_state;
    lives_ok {
        $updated_state = Crypt::Rijndael::PP->_MixColumns( $state );
    } "Lives through ShiftRows";

    note("Original State:\n");
    note( Crypt::Rijndael::PP->_print_formatted_state( $state ) );

    note("Updated State:\n");
    note( Crypt::Rijndael::PP->_print_formatted_state( $updated_state ) );

    note("Expected State:\n");
    note( Crypt::Rijndael::PP->_print_formatted_state( $expected_state ) );

    my $byte_index = 0;
    for ( my $row_index = 0; $row_index < 4; $row_index++ ) {
        for ( my $column_index = 0; $column_index < 4; $column_index++ ) {

            my $state_byte = unpack( "H2",
                $updated_state->[$row_index][$column_index]
            );

            my $expected_state_byte = unpack( "H2",
                $expected_state->[$row_index][$column_index]
            );

            cmp_ok( $state_byte, 'eq', $expected_state_byte,
                "Correct SubByte State Byte at $row_index x $column_index" );
        }
    }
};

done_testing;
