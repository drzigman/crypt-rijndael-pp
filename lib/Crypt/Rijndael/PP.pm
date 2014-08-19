package Crypt::Rijndael::PP;

use strict;
use warnings;

use bytes;

use Smart::Comments -ENV;
use Carp;


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

}

sub _ShiftRows {
    my $state = shift;

    
}

sub _MixColumns {

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
