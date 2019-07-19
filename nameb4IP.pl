#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use JSON;
use HTTP::Headers;
use LWP::Simple qw(get);
use Data::Dumper;
use Getopt::Long qw(GetOptions);
use Getopt::Long;
use HTTP::Request::Common;



my $idoit_url = 'https://idoit.svc.eurotux.pt/i-doit/src/jsonrpc.php';
my $idoit_apikey = "lk3cuqphh";
my $icinga_url = 'https://localhost:5665/v1/objects/hosts';
my $icinga_user = "root";
my $icinga_password = "c1552fd540393237";
my %group_type_hash = ('building' => 3,
			'server' => 5,
			'switch' => 8,
			'client' => 10,
			'printer' => 11,
			'storage' => 12,
			'appliance' => 23,
			'accesspoint' => 27,
			'virtual' => 59);


##############################################################
##############################################################
##############################################################
#		Functions related to idoit		     #      
		
		
		
#fetch all idoit hosts from a group_type	
sub IDOIT_listREQUEST{
	my $group_type = $_[0];
	my $apikey = $_[1];
	my $url = $_[2];
	my $body = to_json({"version"=>"2.0","method"=>"cmdb.objects.read","params"=>{"filter"=>{"type"=> $group_type},"order_by"=>"title","apikey"=>$apikey,"language"=>"en"},"id"=>1});	
	my $req = HTTP::Request->new( 'POST', $url);
	$req->header( 'Content-Type' => 'application/json' );
	$req->content ( $body );
	my $ua = LWP::UserAgent->new;
	$ua->ssl_opts( verify_hostname => 0 ,SSL_verify_mode => 0x00);
	my $responseJSON =  $ua->request($req);
	return decode_json($responseJSON->content);
}


#Category Read Generator
sub IDOIT_cat_read_GENERATOR{
	my $id = $_[0];
	my $category = $_[1];
	my $apikey = $_[2];
	my $body = to_json({"version"=>"2.0","method"=>"cmdb.category.read","params"=>{"objID"=>$id,"category"=>$category,"apikey"=>$apikey,"language"=>"en"},"id"=>1});
	return $body;
}

#Object read generator
sub IDOIT_obj_read_GENERATOR{
	my $id = $_[0];
        my $apikey = $_[1];
        my $body = to_json({"version"=>"2.0","method"=>"cmdb.object.read","params"=>{"id"=>$id,"apikey"=>$apikey,"language"=>"en"},"id"=>1});
        return $body;
}

#Just pass the JSON body as an argument
sub IDOIT_general_REQUEST{
	my $url = $_[0];
        my $body = $_[1];
	my $apikey = $_[2];
	my $req = HTTP::Request->new( 'POST', $url);
        $req->header( 'Content-Type' => 'application/json' );
        $req->content ( $body );
        my $ua = LWP::UserAgent->new;
        $ua->ssl_opts( verify_hostname => 0 ,SSL_verify_mode => 0x00);
        my $responseJSON =  $ua->request($req);
        return decode_json($responseJSON->content);
}



##############################################################
##############################################################
##############################################################
#		Functions related to icinga		     #
#							     #		


sub ICINGA_query_hosts{
	my $icinga_url = $_[0];
	my $user = $_[1];
	my $pass = $_[2];
	my $ua = LWP::UserAgent->new();
        $ua->ssl_opts( verify_hostname => 0 ,SSL_verify_mode => 0x00);
	my $req = GET $icinga_url;
	$req->authorization_basic("$user", "$pass");
	my $response = $ua->request($req);
	return decode_json($response->content);
}





##############################################################
##############################################################
##############################################################
#			Mixed functions			     #
#							     #


sub compare{
	my @icinga_host_list = $_[0];
        my $hostname = $_[1];
	my $lc_hostname = lc($hostname);
	my $noSpace_hostname= $hostname =~ s/\s//gr;
	my $lcNoSpace_hostname = lc($noSpace_hostname);
        my $host_ip = $_[2];
	my $type = $_[3];
        if (!defined $host_ip){
                return "$type: $hostname:NO DOCUMENTED IP FOUND IN I-DOIT\n";
        }
	#print Dumper @icinga_host_list;
        foreach my $names (@icinga_host_list){
                foreach my $name (@$names){
			if (!defined $name->{check_period}){
				$name->{check_period} = "NO CHECK_PERIOD ASSIGNED";
			}	
                        if ($hostname eq $name->{name} || $lc_hostname eq $name->{name} || $noSpace_hostname eq $name->{name} || $lcNoSpace_hostname eq $name->{name} ){
                                if ( $host_ip eq $name->{attrs}->{address} ){
                                        return "OK:$type:$hostname:$host_ip:$name->{check_period}\n";
					
                                }
                                else {
                                        return "OUTDATED-MONITORED UNDER DIFFERENT IP-:$type:$hostname:$host_ip:$name->{check_period}:(IS BEING MONITORED UNDER THE IP OF $name->{attrs}->{address})\n";
								
                                }
                        }

			elsif($host_ip eq $name->{attrs}->{address}) {
				return "OUTDATED-MONITORED UNDER DIFFERENT NAME-:$type:$hostname:$name->{attrs}->{address}:$name->{check_period}:(IS BEING MONITORED UNDER THE NAME OF $name->{name})\n";
				
			}


                }

        }
	return "NOT MONORITORED:$type:$hostname:$host_ip\n";

}

##############################################################
##############################################################
##############################################################
#			Actual Script			     #
#							     #



my @host_types;
GetOptions('type=s' => \@host_types,
		'a|all' => \my $all) or die "Wrong syntax!\nUsage: $0 --type {server, client, switch, printer, storage, virtual, building, accesspoint, appliance}\n ";

if(!defined $host_types[0] && !defined $all){
	print  "Wrong syntax!\nUsage: $0 --type {server, client, switch, printer, storage, virtual, building, accesspoint, appliance} ||  -a (--all)\n ";
	exit;
}
if ($all){
	push @host_types, "server", "client", "switch", "printer", "storage", "virtual", "building", "accesspoint", "appliance" ;
}

foreach my $type (@host_types){
	#Query idoit hosts
	my $responseJSON = IDOIT_listREQUEST($group_type_hash{$type}, $idoit_apikey, $idoit_url);
	my @idoit_host_list = ($responseJSON->{result});
		#Query icinga hosts
 	       my $icinga_response = ICINGA_query_hosts($icinga_url, $icinga_user, $icinga_password);
 	       my @icinga_host_list = ($icinga_response->{results});
 	       #fetches IP and compares
 	       foreach my $result (@idoit_host_list){
 	       	foreach my $host (@$result){
 	       		my $ip_response = IDOIT_general_REQUEST($idoit_url, IDOIT_cat_read_GENERATOR($host->{id},"C__CATG__IP", $idoit_apikey), $idoit_apikey);
 	       		print my $comparison = compare(@icinga_host_list, $host->{title}, $ip_response->{result}->[0]->{primary_hostaddress}->{ref_title}, $type);		
 	       	}	
 	       }	        
 	                       

}	


















