#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'FBOS' ) || print "Bail out!  ";
    my $obj = new FBOS("FBid","FBname");
    isa_ok( $obj, 'FBOS' );
}

diag( "Testing FBOS Library loading $FBOS::VERSION, Perl $], $^X" );
