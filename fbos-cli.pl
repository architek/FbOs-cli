#!/usr/bin/perl
use strict;
use warnings;

package FBOS::Client;

my $VERSION = "0.3";

use LWP::UserAgent;
use JSON qw/ from_json to_json /;
use Storable;
use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;
use MIME::Base64 qw/ encode_base64url decode_base64url encode_base64/; #TODO check

my $endpoint  = "http://mafreebox.freebox.fr";
my $store     = "app_token";

BEGIN 
{
    my @attr = qw/ ua challenge track_id app_token auth_progress success api_success status error_code prefix app_id app_name/;
    no strict 'refs';
    for my $m (@attr)
    {
        *{__PACKAGE__ . "::get_$m"} = sub { $_[0]->{$m}         };
        *{__PACKAGE__ . "::set_$m"} = sub { $_[0]->{$m} = $_[1] };
    }
}

sub new {
    my ($class, $app_id, $app_name) = @_;
    my $ua = LWP::UserAgent->new;
    my $self={};
    bless $self, $class;
    $self->set_ua($ua);
    $self->set_app_id($app_id);
    $self->set_app_name($app_name);
    return $self;
}

sub GET {
    my ($self,$uri,$header) = @_;
    my $req = HTTP::Request->new( "GET", $self->get_prefix() . $uri, $header);
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
}

sub POST {
    my ($self,$uri,$header,$content) = @_;
    $content = to_json($content) if defined $content;
    my $req = HTTP::Request->new( "POST", $self->get_prefix() . $uri, $header, $content);
    $req->content_length( length($content) ) if defined $content;
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
}

sub PUT {
    my ($self,$uri,$header,$content) = @_;
    $content = to_json($content) if defined $content;
    my $req = HTTP::Request->new( "PUT", $self->prefix() . $uri, $header, $content);
    $req->content_length( length($content) ) if defined $content;
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
}

sub DELETE {
    my ($self,$uri,$header) = @_;
    my $req = HTTP::Request->new( "DELETE", $self->prefix() . $uri, $header);
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
}


sub request {
    my ($self, $req) = @_;
    my $res  = $self->get_ua()->request($req);
    $self->set_success($res->is_success());
    $self->set_status($res->status_line);
    return $res;
}

sub decode_json {
    my ($self, $response) = @_;
    #return from_json ( $response->decoded_content , {utf8 => 1});
    return from_json ( $response->decoded_content );
}

sub decode_api_response {
    my ($self, $response) = @_;
    my $api_response = $self->decode_json ( $response );
    $self->set_api_success( $api_response->{success} );
    if ( $self->get_api_success() ) {
        return exists $api_response->{result} ? $api_response->{result} : undef;
    } else {
        $self->set_error_code( $api_response->{error_code} );
        $self->set_error_msg( $api_response->{msg} );
        return undef;
    }
}

sub api_version {
    my $self = shift;
    my $req  = HTTP::Request->new( "GET", $endpoint . "/api_version" );
    my $res = $self->request($req);
    if ( $self->get_success() ) {
        my $res = $self->decode_json ( $res );
        die "Can't get api version" unless exists $res->{api_version} and exists $res->{api_base_url};
        my ($maj) = $res->{api_version} =~ /(\d*)\./;
        $self->set_prefix( $endpoint . $res->{api_base_url} . "v" . $maj . "/" );
    }
    die "Api Version " , $self->get_status() , "\n" unless $self->get_success();
}

sub login {
    my $self = shift;
    my $res = $self->POST("login/authorize/", undef, {
        app_id      => $self->get_app_id(),
        app_name    => $self->get_app_name(),
        app_version => $VERSION,
        device_name => "debian",
        permissions => {
            downloader => "true", parental   => "true", explorer   => "true",
            calls      => "true", contacts   => "true", settings   => "true",
        },
       });
    die "Login " , $self->get_status() , "\n" unless $self->get_success();
    die "Login " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub auth_progress {
    my $self = shift;
    my $res = $self->GET("login/authorize/" . $self->get_track_id());
    die "Auth Progess " , $self->get_status() , "\n" unless $self->get_success();
    die "Auth Progress " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    $self->set_auth_progress($res->{status});
    return $res;
}

sub app_token {
    my $self = shift;
    my $app_token;

    if (-f $store) {
        $app_token = retrieve $store or die "Couldn't restore application token from file found $store\n";
    } else {
        my $auth_progress;
        $app_token = $self->login();
        warn "Please confirm on the freebox\n";
        do {
            sleep 1;
            $self->auth_progress();
        } while ( $self->get_auth_progress() eq "pending" );
        die "User did not grant access, the return is:", $self->get_auth_progress() , "\n"
            unless $self->get_auth_progress() eq "granted";

        store $app_token, $store;
    }
    $self->set_app_token( $app_token->{app_token} );
    $self->set_track_id( $app_token->{track_id} );
}

sub challenge {
    my $self = shift;
    my $res = $self->GET("login/");
    die "Challenge " , $self->get_status() , "\n" unless $self->get_success();
    die "Challenge " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    $self->set_challenge($res->{challenge});
    return $res;
}

sub set_session_token {
    my $self = shift;
    $self->challenge();
    my $res = $self->POST("login/session/", undef,
        {
            app_id   => $self->get_app_id(),
            password => hmac_sha1_hex( $self->get_challenge(), $self->get_app_token() )
        }
    );
    die "Session Token" , $self->get_status() , "\n" unless $self->get_success();
    die "Session Token" , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    $self->get_ua()->default_header( 'X-Fbx-App-Auth' => $res->{session_token} );
    return $res;
}

sub connect {
    my $self = shift;
    $self->api_version();
    $self->app_token();
    $self->set_session_token();
}

############# API
sub api_connection {
    my $self=shift;
    my $res = $self->GET("connection/");
    die "API Connection " , $self->get_status() , "\n" unless $self->get_success();
    die "API Connection " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub api_dl_stats {
    my $self=shift;
    my $res = $self->GET("downloads/stats");
    die "DL Stats " , $self->get_status() , "\n" unless $self->get_success();
    die "DL Stats " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub api_fs_tasks {
    my $self=shift;
    my $res = $self->GET("fs/tasks");
    die "FS Tasks " , $self->get_status() , "\n" unless $self->get_success();
    die "FS Tasks " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub api_ls_files {
    my ($self, $path) = @_;
    $path = encode_base64url( $path );
    my $res = $self->GET("fs/ls/$path");
    die "LS Files " , $self->get_status() , "\n" unless $self->get_success();
    die "LS Files " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    $_->{path} = decode_base64url( $_->{path} ) for @$res;
    return $res;
}

sub api_airmedia_receiver {
    my ($self, $action, $type, $media) = @_;
    
    die "AirMedia Receiver only accepts type photo or video\n" unless $type eq "video" or $type eq "photo";
    $media = encode_base64($media,"") if defined $media and $type eq "photo";
    my $res = $self->POST("airmedia/receivers/Freebox Player/", undef,
        {
            action => $action,
            media_type => $type,
            media => $media,
        }
    );
    die "AirMedia Receiver " , $self->get_status() , "\n" unless $self->get_success();
    die "AirMedia Receiver " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
}

sub api_call_log {
    my ($self, $id) = @_;
    my $url = "call/log/";
    $url .= $id if defined $id;
    my $res = $self->GET("$url");
    die "Call Log " , $self->get_status() , "\n" unless $self->get_success();
    die "Call Log " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub api_call_delete {
    my ($self, $id) = @_;
    my $res = $self->DELETE("call/log/$id");
    die "Call Delete " , $self->get_status() , "\n" unless $self->get_success();
    die "Call Delete " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}

sub api_lan_browser {
    my ($self, $if) = @_;
    my $url = "lan/browser/";
    $url .= defined $if ? "$if/" : "interfaces/";
    my $res = $self->GET($url);
    die "Lan Browser " , $self->get_status() , "\n" unless $self->get_success();
    die "Lan Browser " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
    return $res;
}


package main;
use Data::Dumper;
#binmode STDOUT,':utf8';

my $fbc=new FBOS::Client("FBPerl", "FBPerlTest");
$fbc->connect();
#print Dumper $fbc->api_connection;
#print Dumper $fbc->api_dl_stats;
#print Dumper $fbc->api_fs_tasks;
#print Dumper $fbc->api_ls_files("Disque dur");
#$fbc->api_airmedia_receiver("start","video","http://anon.nasa-global.edgesuite.net/HD_downloads/GRAIL_launch_480.mov") and sleep 15 and $json->api_airmedia_receiver("stop","video");
#$fbc->api_airmedia_receiver("start","photo","Disque dur/Photos/samsung GT-I9300/Camera/IMG_20140212_195511.jpg") and sleep 10 and $json->api_airmedia_receiver("stop","photo");
#print Dumper $fbc->api_call_log;
#$fbc->api_call_delete(400);
#my $calls=$fbc->api_call_log ; $json->api_call_delete($_->{id}) for @$calls;
#print Dumper $fbc->api_lan_browser("pub");
print Dumper $fbc->api_lan_browser("pub/ether-98:4B:E1:95:AC:84");
