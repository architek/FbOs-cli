#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'FBOS' ) || print "Bail out!  ";
}

diag( "Testing FBOS Library loading $FBOS::VERSION, Perl $], $^X" );
