#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use Crypt::Rijndael::PP::GF qw( gf_multiply );

use Readonly;
Readonly my $GF_MULTIPLICATION_TEST_VALUES => {
    0x02 => {
        0xd4 => 0xb3,
        0x03 => 0x06,
    },
    0x03 => {
        0xf1 => 0x08,
    },
};

subtest "Attempt to gf_multiply a left_factor that has not been precomputed" => sub {
    throws_ok {
        gf_multiply( 0xFF, 0x00 );
    } qr/Left Factor not precomputed/, "Croaks on left factor not precomputed";
};

subtest "gf_multiply gives correct value" => sub {
    for my $left_factor ( keys $GF_MULTIPLICATION_TEST_VALUES ) {
        subtest "Left Factor - 0x" . unpack("x3H2", pack("N", $left_factor ) ) => sub {
            for my $right_factor ( keys $GF_MULTIPLICATION_TEST_VALUES->{ $left_factor } ) {

                my $product;
                lives_ok {
                    $product = gf_multiply($left_factor, $right_factor);
                } "Lives through gf_multiply";

                cmp_ok( $product, '==', $GF_MULTIPLICATION_TEST_VALUES->{$left_factor}{$right_factor},
                    "Correct Value for 0x" . unpack("x3H2", pack("N", $right_factor ) ) );
            }
        };
    }
};

done_testing;
