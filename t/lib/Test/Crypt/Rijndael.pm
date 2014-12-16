package Test::Crypt::Rijndael;

use strict;
use warnings;

use Test::More;
use Test::Exception;
use MooseX::Params::Validate;

use Crypt::Rijndael;
use Crypt::Rijndael::PP;

use Exporter 'import';
our @EXPORT_OK = qw(
    test_rijndael_xs_encryption test_rijndael_pp_encryption
);

sub test_rijndael_xs_encryption {
    my ( %args ) = validated_hash(
        \@_,
        input => { isa => 'ArrayRef' },
        key   => { isa => 'ArrayRef' },
        mode  => { isa => 'Str' },
        iv    => { isa => 'Str', optional => 1 },
        expected_cipher_text => { isa => 'ArrayRef' },
    );

    subtest 'Crypt::Rijndal' => sub {
        my $packed_input       = pack( "C*", @{ $args{input} } );
        my $packed_cipher_key  = pack( "C*", @{ $args{key} } );
        my $packed_expected_cipher_text =
            pack( "C*", @{ $args{expected_cipher_text} } );

        my $mode;
        if( $args{mode} eq 'MODE_ECB' ) {
            $mode = Crypt::Rijndael::MODE_ECB();
        }
        elsif( $args{mode} eq 'MODE_CBC' ) {
            $mode = Crypt::Rijndael::MODE_CBC();
        }

        my $cipher;
        lives_ok {
            $cipher = Crypt::Rijndael->new(
                $packed_cipher_key, $mode
            );

            if( $args{iv} ) {
                $cipher->set_iv( $args{iv} );
            }
        } 'Lives through construction of Cipher';

        my $cipher_text;
        lives_ok {
            $cipher_text = $cipher->encrypt( $packed_input );
        } 'Lives through encryption';

        cmp_ok( unpack( "H*", $cipher_text ), 'eq',
            unpack( "H*", $packed_expected_cipher_text ), "Correct Cipher Text" );
    };

    return;
}

sub test_rijndael_pp_encryption {
    my ( %args ) = validated_hash(
        \@_,
        input => { isa => 'ArrayRef' },
        key   => { isa => 'ArrayRef' },
        mode  => { isa => 'Str' },
        iv    => { isa => 'Str', optional => 1 },
        expected_cipher_text => { isa => 'ArrayRef' },
    );

    subtest 'Crypt::Rijndael::PP' => sub {
        my $packed_input       = pack( "C*", @{ $args{input} } );
        my $packed_cipher_key  = pack( "C*", @{ $args{key} } );
        my $packed_expected_cipher_text =
            pack( "C*", @{ $args{expected_cipher_text} } );

        my $mode;
        if( $args{mode} eq 'MODE_ECB' ) {
            $mode = Crypt::Rijndael::PP::MODE_ECB();
        }
        elsif( $args{mode} eq 'MODE_CBC' ) {
            $mode = Crypt::Rijndael::MODE_CBC();
        }

        my $cipher;
        lives_ok {
            $cipher = Crypt::Rijndael::PP->new(
                $packed_cipher_key, $mode
            );
            
            if( $args{iv} ) {
                $cipher->set_iv( $args{iv} );
            }
        } 'Lives through construction of Cipher';

        my $cipher_text;
        lives_ok {
            $cipher_text = $cipher->encrypt( $packed_input );
        } 'Lives through encryption';

        cmp_ok( unpack( "H*", $cipher_text ), 'eq',
            unpack( "H*", $packed_expected_cipher_text ), "Correct Cipher Text" );
    };

    return;
}

1;
