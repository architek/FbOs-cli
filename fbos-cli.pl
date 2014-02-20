#!/usr/bin/perl
use strict;
use warnings;

package FBOS::Client;

my $VERSION = "0.2";

use LWP::UserAgent;
use JSON qw/ from_json to_json /;
use Storable;
use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;

my $endpoint  = "http://mafreebox.freebox.fr";
my $store     = "app_token";

sub new {
    my ($class, $app_id, $app_name) = @_;
    my $ua = LWP::UserAgent->new;
    bless {
        ua       => $ua,
        app_id   => $app_id,
        app_name => $app_name,
    }, $class;
}

sub GET {
    my ($self,$uri,$header) = @_;
    my $req = HTTP::Request->new( "GET", $self->prefix() . $uri, $header);
    my $res = $self->request($req);
    return $self->success() ? $self->decode_api_response( $res ) : undef;
}

sub POST {
    my ($self,$uri,$header,$content) = @_;
    $content = to_json($content) if defined $content;
    my $req = HTTP::Request->new( "POST", $self->prefix() . $uri, $header, $content);
    $req->content_length( length($content) ) if defined $content;
    my $res = $self->request($req);
    return $self->success() ? $self->decode_api_response( $res ) : undef;
}

sub PUT {
    my ($self,$uri,$header,$content) = @_;
    $content = to_json($content) if defined $content;
    my $req = HTTP::Request->new( "PUT", $self->prefix() . $uri, $header, $content);
    $req->content_length( length($content) ) if defined $content;
    my $res = $self->request($req);
    return $self->success() ? $self->decode_api_response( $res ) : undef;
}

sub request {
    my ($self, $req) = @_;
    my $res  = $self->ua()->request($req);
    $self->success($res->is_success());
    $self->status($res->status_line);
    return $res;
}

sub decode_json {
    my ($self, $response) = @_;
    return from_json ( $response->decoded_content );
}

sub decode_api_response {
    my ($self, $response) = @_;
    my $api_response = $self->decode_json ( $response );
    $self->api_success( $api_response->{success} );
    if ( $self->api_success() ) {
        return exists $api_response->{result} ? $api_response->{result} : undef;
    } else {
        $self->error_code( $api_response->{error_code} );
        $self->error_msg( $api_response->{msg} );
        return undef;
    }
}

sub api_version {
    my $self = shift;
    my $req  = HTTP::Request->new( "GET", $endpoint . "/api_version" );
    my $res = $self->request($req);
    if ( $self->success() ) {
        my $res = $self->decode_json ( $res );
        die "Can't get api version" unless exists $res->{api_version} and exists $res->{api_base_url};
        my ($maj) = $res->{api_version} =~ /(\d*)\./;
        $self->prefix( $endpoint . $res->{api_base_url} . "v" . $maj . "/" );
    }
    return $self->success();
}

sub login {
    my $self = shift;
    my $res = $self->POST("login/authorize/", undef, {
        app_id      => $self->app_id(),
        app_name    => $self->app_name(),
        app_version => $VERSION,
        device_name => "debian",
        permissions => {
            downloader => "true", parental   => "true", explorer   => "true",
            calls      => "true", contacts   => "true", settings   => "true",
        },
       });
    die "Login " , $self->status , "\n" unless $self->success;
    die "Login " , $self->error_msg , "[", $self->error_code, "]", "\n" unless $self->api_success;
    return $res;
}

sub auth_progress {
    my $self = shift;
    my ($track_id) = @_;
    my $res = $self->GET("login/authorize/" . $self->{app_token}{track_id});
    die "Auth Progess " , $self->status , "\n" unless $self->success();
    die "Auth Progress " , $self->error_msg , "[", $self->error_code, "]", "\n" unless $self->api_success;
    return $res;
}

sub app_token {
    my $self = shift;

    my $auth_progress;

    if (-f $store) {
        $self->{app_token} = retrieve $store;
        return;
    }
    my $res = $self->login();
    $self->{app_token} = $res;
    warn "Please confirm on the freebox\n";
    do {
        sleep 1;
        $auth_progress = $self->auth_progress;
    } while ( $auth_progress->{status} eq "pending" );
    die "User did not grant access, the return is: $auth_progress->{status}\n"
      unless $auth_progress->{status} eq "granted";

    store $self->{app_token}, $store;
}

sub challenge {
    my $self = shift;
    my $res = $self->GET("login/");
    die "Challenge " , $self->status , "\n" unless $self->success();
    die "Challenge " , $self->error_msg , "[", $self->error_code, "]", "\n" unless $self->api_success;
    return $res;
}

sub session_token {
    my $self = shift;
    my $challenge = $self->challenge();
    my $res = $self->POST("login/session/", undef,
        {
            app_id   => $self->app_id(),
            password => hmac_sha1_hex( $challenge->{challenge}, $self->{app_token}{app_token} )
        }
    );
    die "Session Token" , $self->status , "\n" unless $self->success();
    die "Session Token" , $self->error_msg , "[", $self->error_code, "]", "\n" unless $self->api_success;
    return $res;
}

sub connect {
    my $self = shift;
    $self->api_version();
    $self->app_token();
    $self->{session_token} = $self->session_token();
    $self->ua->default_header( 'X-Fbx-App-Auth' => $self->{session_token}{session_token} );
}

sub api_connection {
    my $self=shift;
    my $res = $self->GET("connection/");
    die "API Connection " , $self->status , "\n" unless $self->success();
    die "API Connection " , $self->error_msg , "[", $self->error_code, "]", "\n" unless $self->api_success;
    return $res;
}

sub ua {
    my ($self)=@_;
    return $self->{ua};
}
sub success {
    my ($self, $success)=@_;
    $self->{success} = $success if defined $success;
    return $self->{success};
}
sub api_success {
    my ($self,$api_success)=@_;
    $self->{api_success} = $api_success if defined $api_success;
    return $self->{api_success};
}
sub status {
    my ($self, $status)=@_;
    $self->{status} = $status if defined $status;
    return $self->{status};
}
sub error_code {
    my ($self,$error_code)=@_;
    $self->{error_code} = $error_code if defined $error_code;
    return $self->{error_code};
}
sub error_msg {
    my ($self,$error_msg)=@_;
    $self->{error_msg} = $error_msg if defined $error_msg;
    return $self->{error_msg};
}
sub prefix {
    my ($self,$prefix)=@_;
    $self->{prefix} = $prefix if defined $prefix;
    return $self->{prefix};
}
sub app_id {
    my ($self)=@_;
    return $self->{app_id};
}
sub app_name {
    my ($self)=@_;
    return $self->{app_name};
}


package main;
use Data::Dumper;
my $app_id   = "FBPerl";
my $app_name = "FBPerlTest";


my $json=new FBOS::Client($app_id, $app_name);
$json->connect;
print Dumper $json->api_connection;
