#!/usr/bin/perl
use strict;
use warnings;

package FBOS::Client;

my $VERSION = "0.7";

use LWP::UserAgent;
use JSON qw/ from_json to_json /;
use Storable;
use Digest::HMAC_SHA1 qw/ hmac_sha1_hex /;
use MIME::Base64 qw/ encode_base64url decode_base64url encode_base64 decode_base64 /;

my $endpoint  = "http://mafreebox.freebox.fr";
my $store     = "app_token";

#Mutators
BEGIN 
{
    my @attr = qw/ ua challenge track_id app_token auth_progress success api_success status error_code error_msg prefix app_id app_name/;
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
    my $self = {};
    bless $self, $class;
    $self->set_ua($ua);
    $self->set_app_id($app_id);
    $self->set_app_name($app_name);
    return $self;
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
    my $req = HTTP::Request->new( "PUT", $self->get_prefix() . $uri, $header, $content);
    $req->content_length( length($content) ) if defined $content;
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
}

sub DELETE {
    my ($self,$uri,$header) = @_;
    my $req = HTTP::Request->new( "DELETE", $self->get_prefix() . $uri, $header);
    my $res = $self->request($req);
    return $self->get_success() ? $self->decode_api_response( $res ) : undef;
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
		$self->set_track_id( $app_token->{track_id} );
        do {
			warn "Please confirm on the freebox\n";
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
    if ($self->get_status() =~ m/403 Forbidden/) {
        warn "Check your stored auth_token file '$store' and consider removing it to force requesting a new one\n";
    }
    $self->err_msg();
    $self->get_ua()->default_header( 'X-Fbx-App-Auth' => $res->{session_token} );
    return $res;
}

sub connect {
    my $self = shift;
    $self->api_version();
    $self->app_token();
    $self->set_session_token();
}

sub err_msg {
    my $self = shift;
    my $sn = +(caller(1))[3];
    die "$sn: " , $self->get_status() , "\n" unless $self->get_success();
    die "$sn: " , $self->get_error_msg() , "[", $self->get_error_code(), "]", "\n" unless $self->get_api_success();
}

############# API
sub api_connection {
    my $self = shift;
    my $res = $self->GET("connection/");
    $self->err_msg();
    return $res;
}

sub api_dl_stats {
    my $self = shift;
    my $res = $self->GET("downloads/stats");
    $self->err_msg();
    return $res;
}

sub api_fs_tasks {
    my $self = shift;
    my $res = $self->GET("fs/tasks");
    $self->err_msg();
    return $res;
}

sub api_ls_files {
    my ($self, $path) = @_;
    $path = encode_base64( $path );
    my $res = $self->GET("fs/ls/$path");
    $self->err_msg();
    $_->{path} = decode_base64( $_->{path}) for @$res;
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
    $self->err_msg();
}

sub api_call_log {
    my ($self, $id) = @_;
    my $url = "call/log/";
    $url .= $id if defined $id;
    my $res = $self->GET("$url");
    $self->err_msg();
    $_->{datetime} = scalar localtime ($_->{datetime}) for @$res;
    return $res;
}

sub api_call_delete {
    my ($self, $id) = @_;
    my $res = $self->DELETE("call/log/$id");
    $self->err_msg();
    return $res;
}

sub api_lan_browser {
    my ($self, $if) = @_;
    my $url = "lan/browser/";
    $url .= defined $if ? "$if/" : "interfaces/";
    my $res = $self->GET($url);
    $self->err_msg();
    return $res;
}

sub api_freeplug {
    my ($self) = @_;
    my $res = $self->GET("freeplug");
    $self->err_msg();
    return $res;
}

sub api_dhcp_conf {
    my ($self) = @_;
    my $res = $self->GET("dhcp/config");
    $self->err_msg();
    return $res;
}

sub api_dhcp_static_lease {
    my ($self, $id) = @_;
    my $url = "dhcp/static_lease/";
    $url .= $id if defined $id;
    my $res = $self->GET($url);
    $self->err_msg();
    return $res;
}

sub api_dhcp_dynamic_lease {
    my ($self) = @_;
    my $res = $self->GET("dhcp/dynamic_lease");
    $self->err_msg();
    return $res;
}

sub api_dhcp_set_static_lease {
    my ($self, $content) = @_;
    my $url = "dhcp/static_lease/";
    my $res = $self->POST($url, undef, $content);
    $self->err_msg();
    return $res;
}

sub api_dhcp_update_static_lease {
    my ($self, $config, $id) = @_;
    my $url = "dhcp/static_lease/";
    $url .= $id if defined $id;
    my $res = $self->PUT($url, undef, $config);
    $self->err_msg();
    return $res;
}

sub api_ftp_config {
    my ($self) = @_;
    my $res = $self->GET("ftp/config");
    $self->err_msg();
    return $res;
}
    
sub api_ftp_set_config {
    my ($self, $config) = @_;
    my $res = $self->PUT("ftp/config", undef, $config);
    $self->err_msg();
    return $res;
}

sub api_fw_redir {
    my ($self, $id) = @_;
    my $url = "fw/redir/";
    $url .= $id if defined $id;
    my $res = $self->GET($url);
    $self->err_msg();
    return $res;
}

sub api_fw_set_redir {
    my ($self, $content) = @_;
    my $res = $self->POST("fw/redir/", undef, $content);
    $self->err_msg();
    return $res;
}

sub api_fw_del_redir {
    my ($self, $id) = @_;
    my $res = $self->DELETE("fw/redir/$id");
    $self->err_msg();
    return $res;
}

sub api_lcd_set_config {
    my ($self, $content) = @_;
    my $res = $self->PUT("lcd/config/", undef, $content);
    $self->err_msg();
    return $res;
}

sub api_switch_status {
    my ($self) = @_;
    my $res = $self->GET("switch/status/");
    $self->err_msg();
    return $res;
}

sub api_switch_port_stat {
    my ($self, $id) = @_;
    my $res = $self->GET("switch/port/$id/stats");
    $self->err_msg();
    return $res;
}

sub api_wifi_config {
    my ($self) = @_;
    my $res = $self->GET("wifi/config");
    $self->err_msg();
    return $res;
}

sub api_wifi_ap {
    my ($self, $ap) = @_;
    $ap = defined($ap) ? "/$ap" : ""; 
    my $res = $self->GET("wifi/ap" . $ap);
    $self->err_msg();
    return $res;
}

sub api_wifi_sta {
    my ($self, $ap) = @_;
    my $res = $self->GET("wifi/ap/$ap/stations");
    $self->err_msg();
    return $res;
}

sub api_wifi_bss {
    my ($self, $bss) = @_;
    $bss = defined($bss) ? "/$bss" : ""; 
    my $res = $self->GET("wifi/bss" . $bss);
    $self->err_msg();
    return $res;
}

sub api_wifi_ap_neigh {
    my ($self, $ap) = @_;
    my $res = $self->GET("wifi/ap/$ap/neighbors");
    $self->err_msg();
    return $res;
}

sub api_wifi_ap_chanuse {
    my ($self, $ap) = @_;
    my $res = $self->GET("wifi/ap/$ap/channel_usage");
    $self->err_msg();
    return $res;
}

sub api_system {
    my ($self) = @_;
    my $res = $self->GET("system");
    $self->err_msg();
    return $res;
}

sub api_system_reboot {
    my ($self) = @_;
    my $res = $self->POST("system/reboot/",undef,undef);
    $self->err_msg();
    return $res;
}

package main;
use Data::Dumper;
#binmode STDOUT,':utf8';
#
#Examples:
#

my $fbc = new FBOS::Client("FBPerl", "FBPerlTest");
$fbc->connect();
#print Dumper $fbc->api_connection;
#print $fbc->api_connection->{ipv4} ,"\n";
#print Dumper $fbc->api_dl_stats;
#print Dumper $fbc->api_fs_tasks;
#print Dumper $fbc->api_ls_files("Disque dur/Photos/samsung GT-I9300/");
#$fbc->api_airmedia_receiver("start","video","http://anon.nasa-global.edgesuite.net/HD_downloads/GRAIL_launch_480.mov") and sleep 9 and $fbc->api_airmedia_receiver("stop","video");
#$fbc->api_airmedia_receiver("start","photo","Disque dur/Photos/samsung GT-I9300/Camera/IMG_20140212_195511.jpg") and sleep 4 and $fbc->api_airmedia_receiver("stop","photo");
#print Dumper $fbc->api_call_log;
#$fbc->api_call_delete(400);
#my $calls = $fbc->api_call_log ; $fbc->api_call_delete($_->{id}) for @$calls;
#print Dumper $fbc->api_lan_browser("pub");
#print Dumper $fbc->api_lan_browser("pub/ether-98:4B:E1:95:AC:84");
#print Dumper $fbc->api_freeplug;
#print Dumper $fbc->api_dhcp_conf;
#print Dumper $fbc->api_dhcp_static_lease("00:13:10:30:21:97");
#print Dumper $fbc->api_dhcp_update_static_lease( { comment => "Mon PC" }, "CA:FE:FA:DA:FA:DA" );
#print Dumper $fbc->api_dhcp_set_static_lease( { ip => "192.168.1.200" , mac => "00:DE:AD:B0:0B:55" } );
#for (@{$fbc->api_dhcp_dynamic_lease}) { print Dumper $_ if $_->{ip} eq "192.168.1.27" }
#print Dumper $fbc->api_ftp_config;
#$fbc->api_ftp_set_config({enabled=>\0});
#print Dumper $fbc->api_fw_redir();
#$fbc->api_fw_add_redir( { enabled        => \1, comment        => "test", lan_port       => 4242, wan_port_end   => 4242,
#    wan_port_start => 4242, lan_ip         => "192.168.1.42", ip_proto       => "tcp", src_ip         =>  "0.0.0.0" });
#$fbc->api_fw_del_redir(1);
#$fbc->api_lcd_set_config({brightness=>$_%100}) for (-50..50);
#print Dumper $fbc->api_switch_status;
#print Dumper $fbc->api_switch_port_stat(2);
#print Dumper $fbc->api_wifi_config;
#print Dumper $fbc->api_wifi_ap;
#print Dumper $fbc->api_wifi_ap(0);
#print Dumper $fbc->api_wifi_sta(0)->[0];
#print "$_->{hostname}\n" for @{ $fbc->api_wifi_sta(0) };
#print Dumper $fbc->api_wifi_bss;
#print "Your key is <", $fbc->api_wifi_bss("B0:0B:FA:DA:B0:0B")->{config}{key}, ">\n";
#print "SSID;Chan;802.11n;band;chan width;sec chan;signal\n", join ("\n", map { join(";", $_->{ssid} , $_->{channel}, $_->{capabilities}{ht}, $_->{band}, $_->{channel_width}, $_->{secondary_channel}, $_->{signal} ) } @{ $fbc->api_wifi_ap_neigh(0) } ), "\n";
#print join("\n", map { $_->{channel} } sort {$a->{noise_level}<=>$b->{noise_level}} $fbc->api_wifi_ap_chanuse(0) );
#print $_->{channel} for @{ sort { $a->{noise_level} <=> $b->{noise_level} }  $fbc->api_wifi_ap_chanuse(0) };
#print "Less noisy channel is ", +(map { $_->{channel} } sort { $a->{noise_level} <=> $b->{noise_level} } @{ $fbc->api_wifi_ap_chanuse(0) })[0], "\n";
#$fbc->api_system_reboot;
