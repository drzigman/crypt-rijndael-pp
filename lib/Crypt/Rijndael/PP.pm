package Crypt::Rijndael::PP;

use strict;
use warnings;

use bytes;

use Smart::Comments -ENV;
use Data::Dumper;
use Carp;

use Readonly;
#<<< Don't Tidy S Box's
Readonly my @SBOX => (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
);
#>>>

Readonly my $IRREDUCIBLE_POLYNOMIAL => pack("B*", "0000000100011011" );

=cut
sub encrypt_block {
    my $state = shift;
    my $key   = shift;

    my $num_rounds = 0;

    AddRoundKey($state);

    for( my $round = 1; $round < $num_rounds; $round++ ) {
        SubBytes( $state );
        ShiftRows( $state );
        MixColumns( $tate );
        AddRoundKey( $state, );
    }

    SubBytes( $state );
    ShiftRows( $state );
    AddRoundKey( $state, );

    return $state;
}
=cut

sub _SubBytes {
    my $self  = shift;
    my $state = shift;

    for( my $column_index = 0; $column_index < 4; $column_index++ ) {
        for( my $row_index = 0; $row_index < 4; $row_index++ ) {
            my $original_byte = $state->[$row_index][$column_index];

            my $xy = unpack( "h2", $original_byte );
            my $x  = substr( $xy, 0, 1 );
            my $y  = substr( $xy, 1, 1 );

            my $substituted_byte = pack( "C", $SBOX[
                ( hex($y) * 16 ) + hex($x)
            ]);

            ### Row Index        : ( $row_index )
            ### Column Index     : ( $column_index )
            ### X Coordinate     : ( $x )
            ### Y Coordinate     : ( $y )
            ### Original Byte    : ( unpack "H2", $original_byte )
            ### Substituted Byte : ( unpack "H2", $substituted_byte )

            $state->[$row_index][$column_index] = $substituted_byte;
        }
    }

    return $state;
}

sub _ShiftRows {
    my $self  = shift;
    my $state = shift;

    # Row 0 does not shift
    for( my $row_index = 1; $row_index < 4; $row_index++ ) {
        $self->_shift_row( $state->[$row_index], $row_index );
    }

    return $state;
}

sub _shift_row {
    my $self      = shift;
    my $row       = shift;
    my $num_bytes = shift;

    for( my $shift_round = 0; $shift_round < $num_bytes; $shift_round++ ) {
        push ($row, shift $row);
    }

    return $row;
}

sub _MixColumns {
    my $self  = shift;
    my $state = shift;

    for( my $column = 0; $column < 4; $column++ ) {
        my $mixed_column = $self->_mix_column([
            pack("n", unpack( "C", $state->[0][$column] ) ),
            pack("n", unpack( "C", $state->[1][$column] ) ),
            pack("n", unpack( "C", $state->[2][$column] ) ),
            pack("n", unpack( "C", $state->[3][$column] ) ),
        ]);

        $state->[0][$column] = $mixed_column->[0];
        $state->[1][$column] = $mixed_column->[1];
        $state->[2][$column] = $mixed_column->[2];
        $state->[3][$column] = $mixed_column->[3];
    }

    return $state;
}

sub _mix_column {
    my $self   = shift;
    my $column = shift;

    my $s0 = $column->[0];
    my $s1 = $column->[1];
    my $s2 = $column->[2];
    my $s3 = $column->[3];

    my $s0_prime =
          $self->_gf_multiplication( pack( "n", 0x02 ), $s0 )
        ^ $self->_gf_multiplication( pack( "n", 0x03 ), $s1 )
        ^ pack( "C", unpack( "n", $s2 ) )
        ^ pack( "C", unpack( "n", $s3 ) );

    ### S0 => S0_Prime : ( unpack( "H2", $s0 ) . " => " . unpack( "H2", $s0_prime ) )

    my $s1_prime =
          pack( "C", unpack( "n", $s0 ) )
        ^ $self->_gf_multiplication( pack( "n", 0x02 ), $s1 )
        ^ $self->_gf_multiplication( pack( "n", 0x03 ), $s2 )
        ^ pack( "C", unpack( "n", $s3 ) );

    ### S1 => S1_Prime : ( unpack( "H2", $s1 ) . " => " . unpack( "H2", $s1_prime ) )

    my $s2_prime =
          pack( "C", unpack( "n", $s0 ) )
        ^ pack( "C", unpack( "n", $s1 ) )
        ^ $self->_gf_multiplication( pack( "n", 0x02 ), $s2 )
        ^ $self->_gf_multiplication( pack( "n", 0x03 ), $s3 );

    ### S2 => S2_Prime : ( unpack( "H2", $s2 ) . " => " . unpack( "H2", $s2_prime ) )

    my $s3_prime =
          $self->_gf_multiplication( pack( "n", 0x03 ), $s0 )
        ^ pack( "C", unpack( "n", $s1 ) )
        ^ pack( "C", unpack( "n", $s2 ) )
        ^ $self->_gf_multiplication( pack( "n", 0x02 ), $s3 );

    ### S3 => S3_Prime : ( unpack( "H2", $s3 ) . " => " . unpack( "H2", $s3_prime ) )

    return [ $s0_prime, $s1_prime, $s2_prime, $s3_prime ];
}

sub _gf_multiplication {
    my $self = shift;
    my $left_factor  = shift;
    my $right_factor = shift;

    my $left_factor_bits          = unpack( "B16", $left_factor );
    my $reversed_left_factor_bits = reverse $left_factor_bits;

    my $right_factor_bits          = unpack( "B16", $right_factor );
    my $reversed_right_factor_bits = reverse $right_factor_bits;

    ### Left Factor Bits           : ( $left_factor_bits )
    ### Reversed Left Factor Bits  : ( $reversed_left_factor_bits )
    ### Left Factor Expression     : ( $self->_generate_formatted_expression( $left_factor_bits ) )
    ### Right Factor Bits          : ( $right_factor_bits )
    ### Reversed Right Factor Bits : ( $reversed_right_factor_bits )
    ### Right Factor Expression    : ( $self->_generate_formatted_expression( $right_factor_bits ) )

    my @resultant_terms;
    for( my $left_factor_bit_index = 0;
        $left_factor_bit_index < 16;
        $left_factor_bit_index++ ) {

        my $left_factor_bit = substr( $reversed_left_factor_bits, $left_factor_bit_index, 1 );

        if( $left_factor_bit eq "0" ) {
            next;
        }

        for( my $right_factor_bit_index = 0;
            $right_factor_bit_index < 16;
            $right_factor_bit_index++ ) {

            my $right_factor_bit = substr( $reversed_right_factor_bits, $right_factor_bit_index, 1 );

            if( $right_factor_bit eq "0" ) {
                next;
            }

            my $result =
                ("0" x (15 - ( $left_factor_bit_index + $right_factor_bit_index ) ) )
                . "1" . ( "0" x ($left_factor_bit_index + $right_factor_bit_index) );

            push @resultant_terms, $result;
        }

    }

    ### Raw Resultant Terms      : ( map { $_ } sort @resultant_terms )
    ### Formatted Resultant Terms: ( map { $self->_generate_formatted_expression( $_ ) } sort @resultant_terms )

    # Simply the expression
    my %orders = ();
    for my $term ( @resultant_terms ) {
        if( !exists $orders{$term} ) {
            $orders{$term} = 0;
        }

        $orders{$term}++;
    }

    my @simplified_terms;
    for my $term ( keys %orders ) {
        if( $orders{$term} % 2 == 0 ) {
            next;
        }

        push @simplified_terms, $term;
    }

    ### Raw Simplified Terms       : ( map { $_ } sort @simplified_terms )
    ### Formatted Simplified Terms : ( map { $self->_generate_formatted_expression( $_ ) } sort @simplified_terms )

    my $resultant_expression = pack( "B16", "0" x 14 );
    for my $simplified_term ( @simplified_terms ) {
        my $binary_term       = pack( "B16", $simplified_term );
        $resultant_expression = $resultant_expression ^ $binary_term;

        ### Binary Term          : ( unpack( "B16", $binary_term ) )
        ### Resultant Expression : ( unpack( "B16", $resultant_expression ) )
    }

    ### Raw Resultant Expression       : ( unpack( "B*", $resultant_expression ) )
    ### Formatted Resultant Expression : ( $self->_generate_formatted_expression( unpack( "B*", $resultant_expression ) ) )

    # Mod the result
    my $resultant_bits = $self->_pmod( $resultant_expression, $IRREDUCIBLE_POLYNOMIAL );

    ### Raw Resultant Bits       : ( unpack( "B*", $resultant_bits ) )
    ### Formatted Resultant Bits : ( $self->_generate_formatted_expression( unpack( "B*", $resultant_bits ) ) )

    return $resultant_bits;
}

# left_arg <  $right_arg = -1
# left_arg == $right_arg = 0
# left_arg >  $right_arg = 1
sub _p_order_compare {
    my $self = shift;
    my $left_arg  = shift;
    my $right_arg = shift;

    ### Left Argument  : ( $left_arg )
    ### Right Argument : ( $right_arg )

    my $position_of_msb_in_left_arg  = 16 - index( $left_arg,  "1" );
    my $position_of_msb_in_right_arg = 16 - index( $right_arg, "1" );

    if( $position_of_msb_in_left_arg < $position_of_msb_in_right_arg ) {
        return -1;
    }
    elsif( $position_of_msb_in_left_arg > $position_of_msb_in_right_arg ) {
        return 1;
    }
    else {
        return 0;
    }
}

sub _pmod {
    my $self = shift;

    my $dividend = shift;
    my $divisor  = shift;

    ### Solving  : ( unpack("B*", $dividend ) . " mod " . unpack("B*", $divisor ) )

    my $int_dividend = unpack("n", $dividend );
    my $int_divisor  = unpack("n", $divisor );

    my $long_division_result = $int_dividend;
    my $aligned_divisor      = $int_divisor;

    ### Initial Dividend : ( $long_division_result )
    ### Initial Divisor  : ( $int_divisor )

    while( $self->_p_order_compare(
        unpack( "B16", pack( "n", $long_division_result) ),
        unpack( "B16", pack( "n", $int_divisor ) ),
        ) >= 0 ) {
        ### Dividend : ( unpack("B*", pack("n", $long_division_result ) ) )
        ### Divisor  : ( unpack("B*", pack("n", $int_divisor ) ) )

        my $position_of_msb_in_dividend = 16 - index( unpack( "B*", pack("n", $long_division_result ) ), "1" );
        my $position_of_msb_in_divisor  = 16 - index( unpack( "B*", pack("n", $int_divisor ) ), "1" );
        my $num_shifts = $position_of_msb_in_dividend - $position_of_msb_in_divisor;

        ### Position of MSB in Dividend: ( $position_of_msb_in_dividend )
        ### Position of MSB in Divisor:  ( $position_of_msb_in_divisor )
        ### Num Shifts: ( $num_shifts )

        $aligned_divisor = $int_divisor << $num_shifts;

        ### Aligned Divisor : ( unpack("B*", pack("n", $aligned_divisor ) ) )

        $long_division_result ^= $aligned_divisor;

        ### Remaining : ( unpack("B*", pack("n", $long_division_result ) ) )
        ### Formated Remaining : ( $self->_generate_formatted_expression( unpack("B*", pack("n", $long_division_result ) ) ) )
    }

    my $modulus = pack("C", $long_division_result );

    ### Resulting Modulus: ( unpack("H*", $modulus ) )
    return $modulus;
}

sub _generate_formatted_expression {
    my $self       = shift;
    my $expression = shift;

    my $reversed_expression  = reverse $expression;
    my $formatted_expression = "";

    for( my $bit_index = 0; $bit_index < length( $reversed_expression ); $bit_index++ ) {
        my $bit = substr( $reversed_expression, $bit_index, 1 );

        if( $bit eq '0' ) {
            next;
        }

        $formatted_expression = "x^" . ( $bit_index ) . " " . $formatted_expression;
    }

    chop $formatted_expression; # Remove the trailing space
    return $formatted_expression;
}

sub _AddRoundKey {

}

sub _input_to_state {
    my $self  = shift;
    my $input = shift;

    ### Length of Input: ( length $input )

    if( length $input != 16 ) {
        croak "Invalid Input Length, Must be 128 Bits";
    }

    my $state;

    my $byte_index = 0;
    for( my $column_index = 0; $column_index < 4; $column_index++ ) {
        for( my $row_index = 0; $row_index < 4; $row_index++ ) {
            my $byte = unpack("x" . ( $byte_index++ ) . "a", $input );

            ### Row Index    : ( $row_index )
            ### Column Index : ( $column_index )
            ### Byte Index   : ( $byte_index )
            ### Raw Byte     : ( $byte )
            ### Byte         : ( unpack "H2", $byte )

            $state->[$row_index][$column_index] = $byte;
        }
    }

    return $state;
}

sub _print_formatted_state {
    my $self  = shift;
    my $state = shift;

    my $byte_index = 0;
    for( my $row_index = 0; $row_index < 4; $row_index++ ) {
        for( my $column_index = 0; $column_index < 4; $column_index++ ) {
            my $state_byte = unpack("H2", $state->[$row_index][$column_index] );
            print "0x" . $state_byte . "\t";
        }
        print "\n";
    }

    return;
}

1;
