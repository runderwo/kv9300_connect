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

use Getopt::Long qw(GetOptions);

my $url;
my $kvm_auth;
my $http_auth;
my $insecure_https = 0;
my $insecure_vnc = 0;

GetOptions(
  'url=s' => \$url,
  'kvm-auth=s' => \$kvm_auth,
  'http-auth=s' => \$http_auth,
  'insecure-https' => \$insecure_https,
  'insecure-vnc' => \$insecure_vnc,
) or die qq{Usage:
$0 --url URL --kvm-auth KVMUSER:KVMPASS [--http-auth HTTPUSER:HTTPPASS] [--insecure-http] [--insecure-vnc]
};

die "Need a URL of the KV93xx series switch web interface." if (!defined($url));

my $kvm_user = undef;
my $kvm_pass = undef;
if (defined($kvm_auth)) {
  ($kvm_user, $kvm_pass) = split /:/, $kvm_auth;
  die "Bad KVM authentication, use format user:pass" unless (defined($kvm_user) and defined($kvm_pass));
}
die "Need to supply KVM user:pass." unless (defined($kvm_user) and defined($kvm_pass));

my $http_user = undef;
my $http_pass = undef;
if (defined($http_auth)) {
  ($http_user, $http_pass) = split /:/, $http_auth;
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
die "Failed to fetch HTTPS cert, is openssl installed?" unless $? == 0;

use IPC::Open2;
use IO::Handle;

###
### Begin SSL certificate management process
###

# TODO: Make this work with attached intermediate certs, if necessary.  Currently
# this will only work with single certs.
open2(my $readfh, my $writefh, 'openssl', 'x509', '-outform', 'pem') or die $!;
$writefh->print($ssl) or die $!;
my $httpscert;
{
  local $/;
  $httpscert = <$readfh>;
}
die unless defined($httpscert);
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
  if (defined($oldcert) && $oldcert eq $httpscert) {
    $certdiff = 0;
  }
}

# TODO: Handle multiple cached certs for different devices, not only one for
# this program in general.

if ($certdiff) {
  # Human readable version of new cert.
  open2($readfh, $writefh, 'openssl', 'x509', '-noout', '-issuer', '-dates', '-fingerprint') or die $!;
  $writefh->print($httpscert) or die $!;
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
  print $fh $httpscert;
  close $fh;
}

###
### End SSL certificate management process
###

my $cert_der = File::Spec->catfile($dir, 'kvm.der');
system("openssl x509 -outform der -in $cert -out $cert_der");
die "Certificate conversion failed." unless $? == 0;

# XXX
# Well, turns out customizing a Java cert store is useless, because the KV9316A
# Java VNC client does not check the certificate anyway when connecting to the
# SSL VNC port (15900).  Leaving it here anyway, since it doesn't hurt
# anything, and other devices might do the right thing...
#
# Instead, we will ensure the certs presented by the HTTPS and VNC-SSL
# servers match, since we presumably authenticated the HTTPS one ourselves.
# XXX
#
# Make a copy of default JVM cert store.
use File::Which;
use Cwd qw(realpath);
($filename, $dirs, $suffix) = fileparse(realpath(which('keytool')));
my $sys_cacerts = "$dirs/../lib/security/cacerts";
use File::Copy;
my $cacerts = File::Spec->catfile($dir, "cacerts");
print "Cloning system Java certificate store from ".realpath($sys_cacerts)."\n";
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

use IO::Socket::SSL qw( SSL_VERIFY_NONE );
$IO::Socket::SSL::DEBUG = 1;
use HTTP::Cookies;

my $ua = LWP::UserAgent->new;
$ua->cookie_jar(HTTP::Cookies->new);
if ($insecure_https) {
  print "Dropping HTTPS anti-hijacking shields!\n";
  $ua->ssl_opts(SSL_verify_mode => SSL_VERIFY_NONE);
  $ua->ssl_opts(verify_hostname => 0);
}

# Create a request
my $req = HTTP::Request->new(GET => $url);

# Pass request to the user agent and get a response back
my $res = $ua->request($req);

# Check the outcome of the response
if (!$res->is_success) {
  print "Failed to fetch $url: ".$res->status_line."\n";
  print qq{If this is a SSL error and you haven't loaded your own SSL cert
onto the device, you'll have to use the --insecure-https option to disable SSL
certificate validation, as the supplied SSL cert is signed by a private issuer
and cannot be verified.

Note: It will be impossible to detect an attack against your session if you do
this.

If you *have* loaded your own SSL cert, ensure that it advertises the proper
SAN (Subject Alternative Name) corresponding to the precise, fully-qualified
hostname in the URL you are using to connect.
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
if ($main_url !~ /:\/\//) {
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
  if ($applet_url !~ /:\/\//) {
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
### Use creds and LoginSession cookie to fetch all ARCHIVEs from the CODEBASE
### of the APPLET into temp directory.
###

$root = HTML::TreeBuilder->new_from_content($res->content);
my $applet = $root->look_down("_tag" => "applet");
my $vnchost = undef;
my $vncport = undef;
eval {
  $vnchost = $applet->look_down("_tag" => "param", name => "host")->{value};
  $vncport = $applet->look_down("_tag" => "param", name => "port")->{value};
};
die $@ if $@;

my $codebase = $applet->{codebase};
my $archives = $applet->{archive};
die "Couldn't find applet code: $@" unless (defined($codebase) && defined($archives));

# Fully qualify it if necessary.
if ($codebase !~ /:\/\//) {
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
  die "Couldn't get archive $codebase/$archive: ".$res->status_line unless($res->is_success);

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
### Verify VNC server SSL certificate matches HTTPS cert (which we hopefully
### validated, unless the user lives dangerously).  Why?  Java VNC client
### disables certificate validation...
###

print "OpenSSL working:\n";
$ssl = `openssl s_client -connect $vnchost:$vncport < /dev/null`;
die "Failed to fetch VNC server SSL cert." unless $? == 0;

open2($readfh, $writefh, 'openssl', 'x509', '-outform', 'pem') or die $!;
$writefh->print($ssl) or die $!;
my $vnccert;
{
  local $/;
  $vnccert = <$readfh>;
}
die unless defined($vnccert);
$readfh->close;
$writefh->close or die "pipe execited with $?";

my $vnc_secure = 1;
if ($httpscert ne $vnccert) {
  print "VNC SSL certificate doesn't match HTTPS certificate!\n";
  $vnc_secure = 0;
}

if ($insecure_https) {
  print "VNC anti-hijacking shields unavailable without secured HTTPS session!\n";
  $vnc_secure = 0;
}

if (!$vnc_secure) {
  if ($insecure_vnc) {
    print "VNC anti-hijacking shields down!\n";
  } else {
    die "VNC session could not be secured! Use --insecure-vnc if you don't care.";
  }
}

###
### Cross fingers and launch applet.
###
system("appletviewer -J-Djavax.net.ssl.trustStore='$dir/cacerts' -J-Djavax.net.ssl.trustStorePassword='changeit' -J-Djava.security.policy='$dir/java.policy' '$dir/java-ssl.html'");
