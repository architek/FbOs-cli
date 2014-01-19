#!/usr/bin/perl
use strict;
use warnings;
use WWW::Mechanize::GZip;
use JSON;
use Data::Dumper;
use Digest::HMAC_SHA1 qw/hmac_sha1_hex/;
use RRD::Simple ();
use Storable;

my $VERSION="0.1";

my $endpoint = "http://mafreebox.freebox.fr";
my $mech;
my $store  = "app_token";
my $app_id = "fr.freebox.lk";
my $maj_ver;
my $base_url;
my $prefix;

sub do_json {
    my ( $url, $content, $type ) = @_;
    $type = "POST" unless $type;
    my $req = HTTP::Request->new( $type => "$endpoint/$url" );
    $req->header( 'Content-type'   => 'application/json' );
    $req->header( 'Content-length' => length($content) );
    $req->content($content);
    $mech->request($req);
    from_json( $mech->content );
}

sub api_version {
    do_json( "api_version", "", "GET" );
}

sub login {
    my $res = do_json(
        "$prefix/login/authorize/",
        to_json {
            app_id      => $app_id,
            app_name    => "FBPerl",
            app_version => "0.1",
            device_name => "debian",
            permissions => {
                downloader => "true", parental   => "true", explorer   => "true",
                calls      => "true", contacts   => "true", settings   => "true",
            },
        }
    );
    $res->{success}
      ? {
        track_id  => $res->{result}{track_id},
        app_token => $res->{result}{app_token}
      }
      : undef;
}

sub auth_progress {
    my ($track_id) = @_;
    do_json( "$prefix/login/authorize/$track_id", "", "GET" );
}

sub app_token {
    my $auth_progress;

    #Get app token
    my $app_token = login or die "Can't get a token\n";

    #Wait for user confirmation
    warn "Please confirm on the freebox\n";
    do {
        sleep 1;
        $auth_progress = auth_progress( $app_token->{track_id} );
    } while ( $auth_progress->{result}{status} eq "pending" );
    die "User did not grant access, the return is: $auth_progress->{result}{status}\n"
      unless $auth_progress->{success}
      and $auth_progress->{result}{status} eq "granted";

    #Store app token
    store $app_token, $store;
    $app_token;
}

sub challenge {
    my $res = do_json( "$prefix/login/", "", "GET" );
    $res->{success} ? $res->{result} : undef;
}

sub session_token {
    my ($app_token) = @_;

#We request a fresh challenge every time even if we got one from auth transactions
    my $challenge = challenge or die "Can't get a challenge!?\n";
    my $res = do_json(
        "$prefix/login/session/",
        to_json {
            app_id   => $app_id,
            password => hmac_sha1_hex( $challenge->{challenge}, $app_token )
        }
    );
}

sub rrd_stats {
    my ( $db, $fields, $start_time, $end_time ) = @_;
    do_json(
        "$prefix/rrd",
        to_json {
            db         => $db,
            fields     => $fields,
            date_start => $start_time,
            date_end   => $end_time,
        }
    );
}

sub rrd_plot {
    my ( $db, $fields, $start, $end, $output, $base ) = @_;
    my $rrd_data = rrd_stats( $db, $fields, $start, $end );
    my $rrd = RRD::Simple->new(
        file   => "myfile.rrd",
        tmpdir => "/var/tmp",
    );

    unlink "myfile.rrd";

    $rrd->create( map { $_ => "GAUGE" } @$fields );

    for my $sample ( @{ $rrd_data->{result}{data} } ) {
        my $time = $sample->{time};
        delete $sample->{time};
        $rrd->update( $time, %$sample );
    }
    $rrd->graph(
        destination => $output,
        basename    => $base,
        periods     => [qw(daily)],
        width       => 800,
        height      => 200,
        title       => $db . " / " . join( " - ", @$fields )
    );
}

#Connect
$mech = WWW::Mechanize::GZip->new( autocheck => 1) or die("Couldn't build mech");

#Get Api version
my $api = api_version;
if ( $api->{api_version} =~ m/^(.*)\./ ) {
    $maj_ver = $1;
}
else {
    die "Wrong version format $api->{api_version}, no minor part found\n";
}

$base_url = $api->{api_base_url};
$base_url =~ s#/##g;

$prefix = "$base_url/v$maj_ver";

#Show info
warn
"Found $api->{device_type} ($api->{device_name}) Api version $api->{api_version} Uid $api->{uid}, will use prefix $prefix\n";

#Get an app token if we didn't already save one
my $app_token = -f $store ? retrieve $store : app_token;

#Get a session token
my $session_token = session_token $app_token->{app_token};

$session_token->{success}
  or die "Can't get a token : $session_token->{msg} (code $session_token->{error_code})\n";

#Now add the session token to following requests
$mech->add_header( 'X-Fbx-App-Auth' => $session_token->{result}{session_token} );

#You need to access the freebox web interface and then settings, access and give full access to the application

#Plot net rates from 23 hours ago up to 1 hour ago
rrd_plot( "net",
    [ "rate_down", "rate_up" ],
    time - 3600 * 23,
    time - 3600,
    "/tmp/", "rates_dsl"
);
