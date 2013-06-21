#!/usr/bin/perl

# geoff.jones@cyberis.co.uk - Geoff Jones 14/06/2011 - v0.1

# Script to detect transparent proxies via three different methods.
# 1.) Check to see whether an intercepting proxy does a DNS lookup on a fake host header
# 2.) Check to see whether the HTTP request headers are modified between the client and server
# 3.) Check to see whether a TCP traceroute on port 25 returns a different path to port 80

use strict;
use warnings;
use IO::Socket;
use Term::ANSIColor;

print STDOUT <<DESC;
\nScript to detect transparent proxies via three different methods.

1.) Check to see whether an intercepting proxy does a DNS lookup on a fake host header
2.) Check to see whether the HTTP (TRACE) request headers are modified between the client and server
3.) Check to see whether a TCP traceroute on port 25 returns a different path to port 80

DESC

my $truehost = "realproxytest.0x90.co.uk"; # Will resolve to an Internet facing IP
my $fakehost = "fakeproxytest.0x90.co.uk"; # Resolves to 127.0.0.1
my $tcptraceroute = "/usr/sbin/traceroute"; # The final check (traceroute) requires root privs.

my $falserequest = "GET /test.php HTTP/1.0
Host: $fakehost
User-Agent: Mozilla/5.0
Connection: close\n\n";

my $truerequest = "GET /test.php HTTP/1.0
Host: $truehost
User-Agent: Mozilla/5.0
Connection: close\n\n";

my $tracerequest = "TRACE /test.php HTTP/1.0\r
Host: $truehost\r
User-Agent: Mozilla/5.0\r
Connection: close\r\n\r\n";

#####################################################################
# Create a basic socket to the true site with the fake host header
# A transparent proxy sometimes performs a DNS lookup on the 
# host header, which will fail to 127.0.0.1 - revealing it's presence.
print "[INFO]\tChecking whether any intercepting proxies are performing DNS lookups on the fake 'Host' header.\n";

my $response = &senddata($truehost, $falserequest);

if ($response =~ /.*IP.*/) {
	# Server script returned IP - so first check for DNS lookup has passed
	print "[RESULT] The proxy [if present] did not perform a lookup on the 'Host' header. \n";
}
else {
	# Get the public IP of the proxy
	$response = &senddata($truehost, $truerequest); 
	$response =~ /^(.*IP.*)$/ || die "[ERROR]\tTrue request didn't return what I expected. Exiting.";

	print color 'red';
	print "[RESULT] There appears to be an intercepting proxy performing DNS lookups of the fake 'Host' header. ";
	print "Several interesting attacks exist if a proxy behaves in this way, such as bouncing attacks ";
	print "off the proxy, and connecting to other internal hosts from the proxy that you cannot access ";
	print "directly.\n";
	print color 'reset';

	print "[INFO]\tObtaining public IP of proxy...\n";
	print "[INFO]\t$1\n";
	exit;
}

#####################################################################
# Sending a TRACE, to see if request headers are being modified
#
print "[INFO]\tChecking whether the HTTP headers sent by this script were received unmodified by the target server\n";
$response = &senddata($truehost, $tracerequest);

#Remove response headers
$response =~ s/^.*?\r\n\r\n//sm;

# Check whether the response contains an unmodified request
if ($tracerequest eq $response) {
	print "[RESULT] The application layer HTTP headers have not been modified.\n";
}
else {
	print color 'red';
	print "[RESULT] The application layer HTTP headers have been modified. An intercepting proxy must be present.\n";
	print color 'reset';
	print "[INFO]\tYou sent:\n${tracerequest}Server Received:\n${response}";

	print "[INFO]\tObtaining public IP of proxy...\n";
	$response = &senddata($truehost, $truerequest);
	$response =~ /^(.*IP.*)$/m || die "[ERROR]\tTrue request didn't return what I expected. Exiting.";
	print "[RESULT] $1\n";
	exit;
}

#####################################################################
# As a final check, see whether a TCP traceroute on port 80 has 
# different results to a TCP traceroute on port 25

print "[INFO]\tPerforming a TCP traceroute on port 80 and port 25. If port 80 traffic tranverses the network via a different route, a proxy may be present.\n";
unless ($> == 0 || $< == 0) { die "[ERROR]You must be root to perform traceroute checks\n" }; 

my $p80 = `$tcptraceroute -T -p 80 -n $truehost | sed 's/^ //g' | grep -v '*' | cut -f 3 -d ' '`;
my $p25 = `$tcptraceroute -T -p 25 -n $truehost | sed 's/^ //g' | grep -v '*' | cut -f 3 -d ' '`;

if ($p80 ne $p25) {
	print color 'red';
	print "[RESULT] Traceroutes on port 80 and port 25 appear to be different. There could be a transparent proxy on route.\n";
	print color 'reset';

	print "[INFO]\tPort 80\n\n$p80\n\n";
	print "[INFO]\tPort 25\n\n$p25\n\n";
	
	print "[INFO]\tObtaining public IP of proxy...\n";
	$response = &senddata($truehost, $truerequest);
	$response =~ /^(.*IP.*)$/m || die "[ERROR]\tTrue request didn't return what I expected. Exiting.";;
	print "[RESULT] $1\n";
	exit;
}
else {
	print "[RESULT] No evidence of an intercepting proxy. It is still possible one exists, though it has not modified request headers, it hasn't done a lookup on the host header, and traceroutes appear sane.\n";
}

# Function to send data on port 80
sub senddata {
	my ($host, $data) = @_;

	my $sock = new IO::Socket::INET (
                                  PeerAddr => $host,
                                  PeerPort => '80',
                                  Proto => 'tcp',
                                 ) ||
	die "[ERROR]\tCould not create socket\n[ERROR]\tPort 80 outbound restricted?\n";
	
	$sock->send($data);

	return do { 
		local $/; <$sock>
	}
}
