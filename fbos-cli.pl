#!/usr/bin/perl
use strict;
use warnings;

my $VERSION="0.2";

package FBOS::Client;
use REST::Client;
use JSON qw(from_json);
our @ISA=qw/REST::Client/;

my $endpoint = "http://mafreebox.freebox.fr";
my $success;

sub _set_api_prefix {
    my $self = shift;
    my $api = from_json( $self->SUPER::GET("/api_version")->responseContent() );
    $api->{api_version}=~s/\..*//;
    $self->setHost("$endpoint$api->{api_base_url}v$api->{api_version}");
}

sub _decode_api_response {
    my $self         = shift;
    my $api_response = from_json ( shift );
    $success = $api_response->{success};
    if ($success) {
        return exists $api_response->{result} ? $api_response->{result} : undef;
    } else {
        return [ $api_response->{error_code} , $api_response->{msg} ];
    }
    #return $success ? exists $api_response->{result} ? $api_response->{result} : undef : [ $api_response->{error_code} , $api_response->{msg} ];
}

sub new {
	my $that  = shift;
	my $class = ref($that) || $that;
    my $self  = bless $that->SUPER::new(host=>$endpoint, timeout=>10), $class;
    $self->addHeader("Content-type" => 'application/json');
    $self->_set_api_prefix();
	bless $self, $class;
	return $self;
}

sub POST {
    my $self = shift;
    my $api_response = $self->SUPER::POST(@_)->responseContent();
    return $self->_decode_api_response( $api_response ) ;
}

sub GET {
    my $self = shift;
    my $api_response = $self->SUPER::GET(@_)->responseContent();
    return $self->_decode_api_response( $api_response ) ;
}

package main;
use JSON qw(to_json from_json);
use Data::Dumper;

my $app_id="fr.freebox.lk";

my $client = FBOS::Client->new();
my $res=$client->POST( "/login/authorize/",
    to_json({
        app_id      => $app_id,
        app_name    => "FBPerl",
        app_version => $VERSION,
        device_name => "debian",
        permissions => {
            downloader => "true", parental   => "true", explorer   => "true",
            calls      => "true", contacts   => "true", settings   => "true",
        },
    }));

print "Success: $success\n";
print Dumper $res;
