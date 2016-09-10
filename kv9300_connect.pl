#!/usr/bin/perl
#
# Authenticate and start a VNC session with a Blackbox KV9300 series IP/KVM
# switch -- without a web browser!
#
# Copyright (C) 2016 Ryan C. Underwood <nemesis@icequake.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use strict;
use warnings;

my $url = shift;
die "Need a URL of the KV93xx series switch web interface." if (!defined($url));

my $kvm_user = undef;
my $kvm_pass = undef;
my $auth = shift;
if (defined($auth)) {
  ($kvm_user, $kvm_pass) = split /:/, $auth;
  die "Bad KVM authentication, use format user:pass" unless (defined($kvm_user) and defined($kvm_pass));
}
die "Need to supply KVM user:pass." unless (defined($kvm_user) and defined($kvm_pass));

my $http_user = undef;
my $http_pass = undef;
$auth = shift;
if (defined($auth)) {
  ($http_user, $http_pass) = split /:/, $auth;
  die "Bad basic authentication, use format user:pass" unless (defined($http_user) and defined($http_pass));
}

use File::Spec;
use File::Temp qw/ tempdir /;

my $dir = tempdir( CLEANUP => 1 );

$url =~ /^(.*):\/\/([^\/]+)/;
my $mechanism = $1;
my $host = $2;
my $port = 443;
if ($host =~ /^(.*):(.*)$/) {
  $host = $1;
  $port = $2;
}
print "OpenSSL working:\n";
my $ssl = `openssl s_client -connect $host:$port < /dev/null`;
die "Failed to fetch server SSL cert, is openssl installed?" unless $? == 0;

use IPC::Open2;
use IO::Handle;

###
### Begin SSL certificate verification logic
###

open2(my $readfh, my $writefh, 'openssl', 'x509', '-outform', 'pem') or die $!;
$writefh->print($ssl) or die $!;
my $newcert;
{
  local $/;
  $newcert = <$readfh>;
}
die unless defined($newcert);
$readfh->close;
$writefh->close or die "pipe execited with $?";

# Check for changed cert vs cert cached in profile.
use File::Basename;
my ($filename, $dirs, $suffix) = fileparse($0);
use File::HomeDir;
my $cert = File::Spec->catfile(File::HomeDir->my_home, ".$filename.pem");

my $certdiff = 1;

if (-f $cert) {
  open my $fh, "<$cert" or die "Couldn't open $cert: $!";
  local $/;
  my $oldcert = <$fh>;
  if (defined($oldcert) && $oldcert eq $newcert) {
    $certdiff = 0;
  }
}

if ($certdiff) {
  # Human readable version of new cert.
  open2($readfh, $writefh, 'openssl', 'x509', '-noout', '-issuer', '-dates', '-fingerprint') or die $!;
  $writefh->print($newcert) or die $!;
  my $newtext;
  {
    local $/;
    $newtext = <$readfh>;
  }
  die unless defined($newtext);
  $readfh->close;
  $writefh->close or die "pipe execited with $?";

  if (-f $cert) {
    # Human readable version of old cert.
    my $oldtext = `openssl x509 -in $cert -noout -issuer -dates -fingerprint`;
    die "Couldn't parse $cert: $!" unless $? == 0;

    print qq{Server presented a SSL certificate that does not match the cached version!
This could mean that your SSL session is being eavesdropped.

Cached SSL certificate:
$oldtext
};
  }
  
  print qq{
SSL certificate now presented by server:
$newtext
Accept and store the new certificate? (y/N) };
  my $input = <STDIN>;
  chomp $input;
  die "Aborted." unless (lc($input) eq 'y');
  open my $fh, ">$cert" or die "Couldn't write to $cert: $!";
  print $fh $newcert;
  close $fh;
}

###
### End SSL certificate verification logic
###

my $cert_der = File::Spec->catfile($dir, 'kvm.der');
system("openssl x509 -outform der -in $cert -out $cert_der");
die "Certificate conversion failed." unless $? == 0;

# Make a copy of default JVM cert store.
use File::Which;
use Cwd qw(realpath);
($filename, $dirs, $suffix) = fileparse(realpath(which('keytool')));
my $sys_cacerts = "$dirs/../lib/security/cacerts";
use File::Copy;
my $cacerts = File::Spec->catfile($dir, "cacerts");
print "Copying Java certificate store from ".realpath($sys_cacerts)."\n";
copy(realpath($sys_cacerts), $cacerts) or die "Couldn't copy $sys_cacerts: $!";

# Java keystore default password is "changeit".
system("echo y | keytool -storepass changeit -import -v -alias kvm -keystore $cacerts -file $cert_der >/dev/null 2>/dev/null");
die "Certificate import to local keystore failed." unless $? == 0;

###
### Fetch login page and find login form ACTION.
###

# Create a user agent object
use LWP::UserAgent;
{
  no warnings 'redefine';
  sub LWP::UserAgent::get_basic_credentials {
    my ($self, $realm, $url, $isproxy) = @_;
    print "$url requested HTTP authentication: $realm\n";
    die "But we didn't have any credentials to supply!" unless (defined($http_user) and defined($http_pass));
    return ($http_user, $http_pass);
  }
}

my $ua = LWP::UserAgent->new;
$ua->agent("MyApp/0.1 ");
$ua->cookie_jar({});
# XXX DANGER
$ua->ssl_opts(SSL_verify_mode => 0);
# XXX END DANGER

# Create a request
my $req = HTTP::Request->new(GET => $url);

# Pass request to the user agent and get a response back
# XXX: Will need to allow self-signed certs in newer LWP
my $res = $ua->request($req);

# Check the outcome of the response
if (!$res->is_success) {
	print "Failed to fetch $url: ".$res->status_line."\n";
	print qq{If this is a SSL error and you haven't loaded your own SSL cert
onto the device, try uncommenting the line of code that sets SSL_verify_mode to
zero, as the supplied SSL cert is signed by a private issuer and cannot be
verified.

Note: It will be impossible to detect an attack against your session if you do
this.
};
	die;
}

use HTML::TreeBuilder;
my $root = HTML::TreeBuilder->new_from_content($res->content);

use URI::Escape;
my $post_data = "";
my $action = undef;
eval {
  my $form = $root->look_down('_tag' => 'form', name => 'real');
  $action = $form->{action};
  my @inputs = $form->look_down('_tag' => 'input');
  my $user_field = undef;
  my $pass_field = undef;
  foreach my $input (@inputs) {
    if ($input->{type} eq 'text') {
      if (!defined($user_field)) {
        $user_field = $input->{name};
      } else {
        warn "Multiple text fields encountered in form?!";
      }
    } elsif ($input->{type} eq 'password') {
      if (!defined($pass_field)) {
        $pass_field = $input->{name};
      } else {
        warn "Multiple password fields encountered in form?!";
      }
    } elsif (defined($input->{name})) {
      $post_data .= uri_escape($input->{name})."=".uri_escape($input->value);
    }
  }
  $post_data .= uri_escape($user_field)."=".uri_escape($kvm_user)."&".uri_escape($pass_field)."=".uri_escape($kvm_pass);
};
die "Couldn't parse login form: $@" if ($@ || !$post_data || !defined($action));

###
### POST creds to login form ACTION location to get LoginSession cookie
###

# Fully qualify a relative form action
if ($action !~ /:\/\//) {
  $action = $mechanism."://$host:$port$action";
}

# Create a request
$req = HTTP::Request->new(POST => $action);
$req->content_type('application/x-www-form-urlencoded');
$req->content($post_data);

# Pass request to the user agent and get a response back
$res = $ua->request($req);

# Check the outcome of the response; should be 302 redirect
die "Couldn't log into KVM: ".$res->status_line unless($res->is_redirect);

my $login_session = undef;
$ua->cookie_jar->scan(sub {
  my ($version, $key, $val) = @_;
  if ($key eq 'LoginSession') {
     $login_session = $val;
  }
});
die "Didn't get KVM LoginSession cookie!" unless (defined($login_session));

my $main_url = $res->header("Location");
# Relative redirect?
if ($main_url !~ /^:\/\//) {
  $main_url = $action;
  $main_url =~ s/[^\/]*$//;
  $main_url .= $res->header("Location");
}

###
### Use creds and LoginSession cookie to find and fetch SSL VNC connection page with embedded APPLET tag (e.g. java-ssl.html) into temp directory
###

# Create a request
$req = HTTP::Request->new(GET => $main_url);

# Pass request to the user agent and get a response back
$res = $ua->request($req);

# Check the outcome of the response
die "Couldn't get main page: ".$res->status_line unless($res->is_success);

# Look for "with SSL encryption" string.
$root = HTML::TreeBuilder->new_from_content($res->content);

my $applet_url = undef;
eval {
  my $a_ele = $root->look_down(
    "_tag" => "a",
    sub {
      $_[0]->as_trimmed_text() =~ /with SSL encryption/;
    });
  $applet_url = $a_ele->{href};

  # Fully qualify it if necessary.
  if ($applet_url !~ /^:\/\//) {
    $applet_url = $main_url;
    $applet_url =~ s/[^\/]*$//;
    $applet_url .= $a_ele->{href};
  }
};
die "Couldn't find applet page link: $@" if ($@ || !defined($applet_url));

# Create a request
$req = HTTP::Request->new(GET => $applet_url);

# Pass request to the user agent and get a response back
$res = $ua->request($req);

# Check the outcome of the response
die "Couldn't get applet page: ".$res->status_line unless($res->is_success);

# Write it to file.
$applet_url =~ /([^\/]+$)/;
my $applet_fname = File::Spec->catfile($dir, $1);
open my $applet_fh, ">$applet_fname" or die "Couldn't open $applet_fname: $!";
my $applet_content = $res->content;
# Rewrite CODEBASE tag of VNC connection page (e.g. java-ssl.html) to temp directory.
$applet_content =~ s/codebase=[^ ]* /codebase=$dir /i;
print $applet_fh $applet_content;
close $applet_fh;

###
### Bah, using standard VNC viewer through stunnel doesn't work due to some evil auth differences.
###
#$root = HTML::TreeBuilder->new_from_content($res->content);
#my $applet = $root->look_down("_tag" => "applet");
#my $vnchost = $applet->look_down("_tag" => "param", name => "host");
#my $vncport = $applet ->look_down("_tag" => "param", name => "port");
#my $vncpass = $applet ->look_down("_tag" => "param", name => "encpassword");
#print $vncpass->{value};
#open my $vncpass_fh, "|-", 'echo -e "'.$vncpass->{value}."\n".$vncpass->{value}.'" | vncpasswd' or die "Couldn't set VNC password: $!";
#close $vncpass_fh;
##system("vncviewer -passwd ".$ENV{HOME}."/.vnc/passwd ".$vnchost->{value}.":".$vncport->{value});
#system("vncviewer -passwd ".$ENV{HOME}."/.vnc/passwd localhost:5900");

###
### Use creds and LoginSession cookie to fetch all ARCHIVEs from the CODEBASE of the APPLET into temp directory
###

$root = HTML::TreeBuilder->new_from_content($res->content);
my $applet = $root->look_down("_tag" => "applet");
my $codebase = $applet->{codebase};
my $archives = $applet->{archive};
die "Couldn't find applet code: $@" unless (defined($codebase) && defined($archives));

# Fully qualify it if necessary.
if ($codebase !~ /^:\/\//) {
	$codebase = $url;
	$codebase =~ s/\/[^\/]*$//;
	$codebase .= $applet->{codebase};
}

my @archives = split /,/, $archives;
foreach my $archive (@archives) {
  # Create a request
  $req = HTTP::Request->new(GET => "$codebase/$archive");

  # Pass request to the user agent and get a response back
  $res = $ua->request($req);

  # Check the outcome of the response
  die "Couldn't get applet page: ".$res->status_line unless($res->is_success);

  my $archive_fname = File::Spec->catfile($dir, $archive);
  open my $archive_fh, ">$archive_fname" or die "Couldn't open $archive_fname: $!";
  print $archive_fh $res->content;
  close $archive_fh;
  print "Fetched $codebase/$archive, length ".$res->header("Content-Length")." dated ".$res->header("Last-Modified")." to $dir\n";
}

###
### Generate java.policy file in temp directory.
###

my $fname = File::Spec->catfile($dir, "java.policy");
open my $fh, ">$fname" or die "Couldn't open $fname: $!";
print $fh qq|
grant
{ permission java.net.SocketPermission "*:5900", "connect";
  permission java.net.SocketPermission "*:15900", "connect";
};
|;
close $fh;

###
### Cross fingers and launch applet.
###

system("appletviewer -J-Djavax.net.ssl.trustStore='$dir/cacerts' -J-Djavax.net.ssl.trustStorePassword='changeit' -J-Djava.security.policy='$dir/java.policy' '$dir/java-ssl.html'");
