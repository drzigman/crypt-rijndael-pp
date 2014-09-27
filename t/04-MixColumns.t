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

Readonly my $DIVIDEND => "0010101101111001";
Readonly my $DIVISOR  => "0000000100011011";
Readonly my $MODULO   => "0000000011000001";

Readonly my $GF_MULTIPLICATION_TEST_VALUES => [
    { arg1 => 0x57, arg2 => 0x83, result => 0xc1 },
    { arg1 => 0x02, arg2 => 0xd4, result => 0xb3 },
    { arg1 => 0x02, arg2 => 0x03, result => 0x06 },
    { arg1 => 0x03, arg2 => 0xf1, result => 0x08 },
];

Readonly my $LEFT_FACTOR  => 0x57;
Readonly my $RIGHT_FACTOR => 0x83;
Readonly my $GF_PRODUCT   => 0xc1;

Readonly my @COLUMN       => ( 0xd4, 0xbf, 0x5d, 0x30 );
Readonly my @MIXED_COLUMN => ( 0x04, 0x66, 0x81, 0xe5 );

subtest "Polynomial Modulus" => sub {
    my $dividend = pack( "B16", $DIVIDEND );
    my $divisor  = pack( "B16", $DIVISOR );

    my $result_modulo;
    lives_ok {
        $result_modulo = Crypt::Rijndael::PP->_pmod( $dividend, $divisor );
    } "Lives through polynomial modulus operation";

    cmp_ok(
        unpack( "H2", $result_modulo ), 'eq',
        unpack( "x1H2", pack( "B16", $MODULO ) ),
        "Correct result");
};

subtest "Multiple Values in GF(2^8)" => sub {
    for my $test_values (@{ $GF_MULTIPLICATION_TEST_VALUES }) {
        my $arg1   = $test_values->{'arg1'};
        my $arg2   = $test_values->{'arg2'};
        my $result = $test_values->{'result'};

        my $subtest_name = sprintf("GF(2^8) - %#04x * %#04x = %#04x",
            $arg1, $arg2, $result );

        subtest $subtest_name => sub {
            my $gf_product;
            lives_ok {
                $gf_product = Crypt::Rijndael::PP->_gf_multiplication(
                    pack( "n", $arg1 ), pack( "n", $arg2 )
                );
            } "Lives through GF Multiplication";

            cmp_ok(
                unpack( "H2", $gf_product ), 'eq',
                unpack( "x1H2", pack( "n", $result ) ),
                "Correct gf multiplication product" );
        }
    }
};

subtest "Mix Individual Column" => sub {
    my $initial_column = [
        pack( "n", $COLUMN[0] ),
        pack( "n", $COLUMN[1] ),
        pack( "n", $COLUMN[2] ),
        pack( "n", $COLUMN[3] ),
    ];

    my $mixed_column;
    lives_ok {
        $mixed_column = Crypt::Rijndael::PP->_mix_column( $initial_column );
    } "Lives through column mixing";

    is_deeply( $mixed_column, [
        pack( "C", $MIXED_COLUMN[0] ),
        pack( "C", $MIXED_COLUMN[1] ),
        pack( "C", $MIXED_COLUMN[2] ),
        pack( "C", $MIXED_COLUMN[3] ),
    ], "Correct Resultant Column" );
};

subtest "Perform Mix Columns on Input State" => sub {
    my $packed_input = pack( "C*", @INPUT );
    my $state = Crypt::Rijndael::PP->_input_to_state( $packed_input );

    note("Original State:\n");
    note( Crypt::Rijndael::PP->_print_formatted_state( $state ) );


    my $packed_expected_output = pack( "C*", @EXPECTED_OUTPUT );
    my $expected_state = Crypt::Rijndael::PP->_input_to_state(
        $packed_expected_output
    );

    my $updated_state;
    lives_ok {
        $updated_state = Crypt::Rijndael::PP->_MixColumns( $state );
    } "Lives through ShiftRows";

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
