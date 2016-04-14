#!/usr/bin/perl
use strict;
use warnings;
use FBOS;

use Data::Dumper;

my $fbc = new FBOS("FBPerl", "FBPerlTest");
$fbc->connect();
#print Dumper $fbc->api_connection;
#print Dumper $fbc->api_connection_config;
#print Dumper $fbc->api_connection_xdsl;
#print Dumper $fbc->api_connection_ftth;
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
#print Dumper [ grep { $_->{channel_width} == 40 } @{ $fbc->api_wifi_allowed_comb(0) } ];
#$fbc->api_system_reboot;
