#!/usr/bin/env perl

use strict;
use warnings;
use v5.10;

my $x   = 0;
my %lut = (

    #0  => "", 1  => "", 2  => "",
    3  => "-",
    4  => "+",
    5  => "xor",
    6  => "*",
    7  => "rol",
    8  => "ror",
    9  => "shl",
    10 => "shr",
    11 => "or",
    12 => "and",
    13 => "s*",
    14 => "jnz",
);

my $alloc = 1;

sub walk {
    my $i      = shift;
    my @ops    = @{ (shift) };
    my @args8  = @{ (shift) };
    my @args16 = @{ (shift) };

    if ( $ops[$i] < 3 ) {
        die if $ops[$i] == 0 && ( $args16[$i] & 0xff ) == 0;
        say "  n$i [label=\"_"
            . (
            $ops[$i] eq 0
            ? ( "r" . $alloc++ )
            : ("r0")
            ) . "=$args16[$i]\"]";
    }
    else {
        say "  n$i [label=\""
            . $lut{ $ops[$i] }
            . "\"]; n$i -> { n$args8[$i*2] n$args8[$i*2+1] }";
        walk( $args8[ $i * 2 ],     \@ops, \@args8, \@args16 );
        walk( $args8[ $i * 2 + 1 ], \@ops, \@args8, \@args16 );
    }
}

while ( read( STDIN, my $buf, 1369 ) == 1369 ) {
    my @w = unpack( "C33 C66", $buf );

    my @ops   = @w[ 0 .. 32 ];
    my @args8 = @w[ 33 .. 97 ];
    @w = unpack( "C33 v33", $buf );
    my @args16 = @w[ 33 .. 65 ];

    #say "ops: @ops"; say "args: @args"
    say "digraph ops_$x {";
    say "  rankdir=LR;";
    walk( 1, \@ops, \@args8, \@args16 );
    say "}";

    $x++;
}
