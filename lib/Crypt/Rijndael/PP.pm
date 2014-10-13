package Crypt::Rijndael::PP;

use strict;
use warnings;

use bytes;

use Smart::Comments -ENV;
use Data::Dumper;
use Carp;

use Crypt::Rijndael::PP::GF qw( gf_multiply );
use Crypt::Rijndael::PP::Debug qw( generate_printable_state );

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

#<<< Don't Tidy the Round Constansts
Readonly my @RCONST => (
    0x8d000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000, 0x9a000000,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
);
#>>>

Readonly my $NUM_ROUNDS => {
    128 => 10,
    192 => 12,
    256 => 14,
};

sub encrypt_block {
    my $self  = shift;
    my $input = shift;
    my $key   = shift;

    my $num_rounds = 10;

    my $state        = $self->_input_to_state( $input );
    ### Inital State: ( generate_printable_state( $state ) )

    my $key_schedule = $self->_ExpandKey( $key );
    ### Key Schedule: ( unpack("H*", $key_schedule ) )

    $self->_AddRoundKey($state, $key_schedule, 0);
    ### State After Round 0 AddRoundKey: ( generate_printable_state( $state ) )

    for( my $round = 1; $round < $num_rounds; $round++ ) {
        ### Processing Round Number: ( $round )

        $self->_SubBytes( $state );
        ### State after SubBytes: ( generate_printable_state( $state ) )

        $self->_ShiftRows( $state );
        ### State after ShiftRows: ( generate_printable_state( $state ) )

        $self->_MixColumns( $state );
        ### State after MixColumns: ( generate_printable_state( $state ) )

        $self->_AddRoundKey( $state, $key_schedule, $round );
        ### State after AddRoundKey: ( generate_printable_state( $state ) )
    }

    ### Performing final transforms...

    $self->_SubBytes( $state );
    ### State after SubBytes: ( generate_printable_state( $state ) )

    $self->_ShiftRows( $state );
    ### State after ShiftRows: ( generate_printable_state( $state ) )

    $self->_AddRoundKey( $state, $key_schedule, $num_rounds );
    ### State after AddRoundKey: ( generate_printable_state( $state ) )

    return $self->_state_to_output( $state );
}

sub _SubBytes {
    my $self  = shift;
    my $state = shift;

    for( my $column_index = 0; $column_index < 4; $column_index++ ) {
        for( my $row_index = 0; $row_index < 4; $row_index++ ) {
            my $original_byte = $state->[$row_index][$column_index];

            my $xy = unpack( "H2", $original_byte );
            my $x  = substr( $xy, 0, 1 );
            my $y  = substr( $xy, 1, 1 );

            my $substituted_byte = pack( "C", $SBOX[
                ( hex($x) * 16 ) + hex($y)
            ]);

            #### Row Index        : ( $row_index )
            #### Column Index     : ( $column_index )
            #### X Coordinate     : ( $x )
            #### Y Coordinate     : ( $y )
            #### Original Byte    : ( unpack "H2", $original_byte )
            #### Substituted Byte : ( unpack "H2", $substituted_byte )

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
            unpack( "C", $state->[0][$column] ),
            unpack( "C", $state->[1][$column] ),
            unpack( "C", $state->[2][$column] ),
            unpack( "C", $state->[3][$column] ),
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
          pack( "C", gf_multiply( 0x02, $s0 ) )
        ^ pack( "C", gf_multiply( 0x03, $s1 ) )
        ^ pack( "C", $s2 )
        ^ pack( "C", $s3 );

    #### S0 => S0_Prime : ( unpack( "H2", $s0 ) . " => " . unpack( "H2", $s0_prime ) )

    my $s1_prime =
          pack( "C", $s0 )
        ^ pack( "C", gf_multiply( 0x02, $s1 ) )
        ^ pack( "C", gf_multiply( 0x03, $s2 ) )
        ^ pack( "C", $s3 );

    #### S1 => S1_Prime : ( unpack( "H2", $s1 ) . " => " . unpack( "H2", $s1_prime ) )

    my $s2_prime =
          pack( "C", $s0 )
        ^ pack( "C", $s1 )
        ^ pack( "C", gf_multiply( 0x02, $s2 ) )
        ^ pack( "C", gf_multiply( 0x03, $s3 ) );

    #### S2 => S2_Prime : ( unpack( "H2", $s2 ) . " => " . unpack( "H2", $s2_prime ) )

    my $s3_prime =
          pack( "C", gf_multiply( 0x03, $s0 ) )
        ^ pack( "C", $s1 )
        ^ pack( "C", $s2 )
        ^ pack( "C", gf_multiply( 0x02, $s3 ) );

    #### S3 => S3_Prime : ( unpack( "H2", $s3 ) . " => " . unpack( "H2", $s3_prime ) )

    return [ $s0_prime, $s1_prime, $s2_prime, $s3_prime ];
}

sub _AddRoundKey {
    my $self         = shift;
    my $state        = shift;
    my $key_schedule = shift;
    my $round        = shift;

    my $relevant_key_schedule = substr( $key_schedule, ($round * 16), 16 );
    #### Full Key Schedule : ( unpack("H*", $key_schedule ) )
    #### Relevant Portion of Key Schedule : ( unpack("H*", $relevant_key_schedule ) )

    for( my $column = 0; $column < 4; $column++ ) {
        #### Processing Column : ( $column )

        my $key_word     = substr( $relevant_key_schedule, ($column * 4 ), 4 );
        my $state_column = pack( "C4", (
            unpack( "C", $state->[0][$column] ),
            unpack( "C", $state->[1][$column] ),
            unpack( "C", $state->[2][$column] ),
            unpack( "C", $state->[3][$column] ),
        ) );
        #### Key Word     : ( unpack("B*", $key_word ) . " - " . unpack("H*", $key_word ) )
        #### State Column : ( unpack("B*", $state_column ) . " - " . unpack("H*", $state_column ) )

        my $int_key_word     = unpack( "N1", $key_word );
        my $int_state_column = unpack( "N1", $state_column );
        my $xored_column     = $int_key_word ^ $int_state_column;
        #### Int Key Word     : ( unpack("B*", pack( "N", $int_key_word ) ) . " - " . unpack("H*", pack( "N", $int_key_word ) ) )
        #### Int State Column : ( unpack("B*", pack( "N", $int_state_column ) ) . " - " . unpack("H*", pack( "N", $int_state_column ) ) )
        #### XOR'ed Column    : ( unpack("B*", pack( "N", $xored_column ) ) . " - " . unpack("H*", pack( "N", $xored_column ) ) )

        $state->[0][$column] = pack("C", unpack( "x0C", pack( "N1", $xored_column ) ) );
        $state->[1][$column] = pack("C", unpack( "x1C", pack( "N1", $xored_column ) ) );
        $state->[2][$column] = pack("C", unpack( "x2C", pack( "N1", $xored_column ) ) );
        $state->[3][$column] = pack("C", unpack( "x3C", pack( "N1", $xored_column ) ) );
        #### Value of State Row 0 : ( unpack("H*", $state->[0][$column] ) )
        #### Value of State Row 1 : ( unpack("H*", $state->[1][$column] ) )
        #### Value of State Row 2 : ( unpack("H*", $state->[2][$column] ) )
        #### Value of State Row 3 : ( unpack("H*", $state->[3][$column] ) )
    }

    return $state;
}

sub _ExpandKey {
    my $self = shift;
    my $key  = shift;

    #### Initial Key: ( unpack("H*", $key ) )

    my $expanded_key = $key;

    # Nb * (Nr + 1)
    my $bits_in_initial_key = length( unpack("H*", $key ) ) * 4;
    my $words_in_key        = $bits_in_initial_key / ( 8 * 4 );
    my $number_of_rounds    = 4 * ( $NUM_ROUNDS->{ $bits_in_initial_key  } + 1);
    #### Number of Bits in Initial Key : ( $bits_in_initial_key )
    #### Words In Initial Key          : ( $words_in_key )
    #### Number of Rounds              : ( $number_of_rounds )

    for( my $expansion_round = $words_in_key; $expansion_round < $number_of_rounds; $expansion_round++ ) {
        #### Expansion Round: ( $expansion_round )

        my $temp = substr( $expanded_key, ($expansion_round * 4) - 4, 4 );
        #### Temp         : ( unpack("B*", $temp ) . " - " . unpack("H*", $temp ) )

        if( $expansion_round % $words_in_key == 0 ) {
            #### Performing Transformation...

            my $rotted_word = $self->_RotWord( $temp );
            #### Rotted Word  : ( unpack("B*", $rotted_word ) . " - " . unpack("H*", $rotted_word ) )

            my $subbed_word = $self->_SubWord( $rotted_word );
            #### Subbed Word  : ( unpack("B*", $subbed_word ) . " - " . unpack("H*", $subbed_word ) )

            my $int_subbed_word = unpack( "N1", $subbed_word );
            $temp = $int_subbed_word ^ $RCONST[ $expansion_round / $words_in_key ];
            #### Int Subbed Word : ( unpack("B*", pack( "N", $int_subbed_word ) ) . " - " . unpack("H*", pack( "N", $int_subbed_word ) ) )
            #### Index into RCON : ( $expansion_round / $words_in_key )
            #### RCON            : ( unpack("B*", pack( "N", $RCONST[$expansion_round / $words_in_key] ) ) . " - " . unpack("H*", pack( "N", $RCONST[$expansion_round / $words_in_key] ) ) )
            #### Xored Result    : ( unpack("B*", pack( "N", $temp ) ) . " - " . unpack("H*", pack("N", $temp ) ) )

            $temp = pack("N1", $temp );
            #### Temp : ( unpack("B*", $temp ) . " - " . unpack("H*", $temp ) )
        }
        elsif( $words_in_key > 6 && $expansion_round % $words_in_key == 4 ) {
            #### Performing 256 Bit Transform...

            $temp = $self->_SubWord( $temp );
            #### Subbed Word  : ( unpack("B*", $temp ) . " - " . unpack("H*", $temp ) )
        }

        my $previous_word     = substr( $expanded_key, ($expansion_round * 4) - ( $words_in_key * 4 ), 4 );
        my $int_previous_word = unpack( "N1", $previous_word );
        my $new_word          = $int_previous_word ^ unpack("N1", $temp);
        #### Previous Word     : ( unpack("B*", $previous_word) . " - " . unpack("H*", $previous_word ) )
        #### Int Previous Word : ( unpack("B*", pack("N", $int_previous_word)) . " - " . unpack("H*", pack("N", $int_previous_word ) ) )
        #### New Word          : ( unpack("B*", pack("N", $new_word ) ) . " - " . unpack("H*", pack("N", $new_word ) ) )

        $expanded_key .= pack("N1", $new_word);
        #### Expanded Key : ( unpack("H*", $expanded_key ) )
    }

    return $expanded_key;
}

sub _SubWord {
    my $self = shift;
    my $word = shift;

    my $subbed_word = "";
    for( my $byte_index = 0; $byte_index < 4; $byte_index++ ) {
        my $original_byte = substr( $word, $byte_index, 1 );

        my $xy = unpack( "H2", $original_byte );
        my $x  = substr( $xy, 0, 1 );
        my $y  = substr( $xy, 1, 1 );

        my $substituted_byte = pack( "C", $SBOX[
            ( 16 * hex($x) ) + hex($y)
        ]);

        #### Byte Index       : ( $byte_index )
        #### X Coordinate     : ( $x )
        #### Y Coordinate     : ( $y )
        #### Original Byte    : ( unpack "H2", $original_byte )
        #### Substituted Byte : ( unpack "H2", $substituted_byte )

        $subbed_word .= $substituted_byte;
    }

    return $subbed_word;
}

sub _RotWord {
    my $self = shift;
    my $word = shift;

    my @byte_array;
    for( my $byte_index = 0; $byte_index < 4; $byte_index++ ) {
        push @byte_array, substr( $word, $byte_index, 1 );
    }

    push (@byte_array, shift @byte_array);

    return join('', @byte_array );
}

sub _input_to_state {
    my $self  = shift;
    my $input = shift;

    #### Length of Input: ( length $input )

    if( length $input != 16 ) {
        croak "Invalid Input Length, Must be 128 Bits";
    }

    my $state;

    my $byte_index = 0;
    for( my $column_index = 0; $column_index < 4; $column_index++ ) {
        for( my $row_index = 0; $row_index < 4; $row_index++ ) {
            my $byte = unpack("x" . ( $byte_index++ ) . "a", $input );

            #### Row Index    : ( $row_index )
            #### Column Index : ( $column_index )
            #### Byte Index   : ( $byte_index )
            #### Raw Byte     : ( $byte )
            #### Byte         : ( unpack "H2", $byte )

            $state->[$row_index][$column_index] = $byte;
        }
    }

    return $state;
}

sub _state_to_output {
    my $self  = shift;
    my $state = shift;

    my $output = "";

    for( my $column_index = 0; $column_index < 4; $column_index++ ) {
        for( my $row_index = 0; $row_index < 4; $row_index++ ) {
            $output .= $state->[$row_index][$column_index];
        }
    }

    return $output;
}

1;
