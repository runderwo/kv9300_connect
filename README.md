## What is this?

This is a program to launch an authenticated VNC session connected to the
console of a Black Box ServSwitch EC KV9300 series KVM over IP switch with pure
Java.

(Things not needed with this method: a web browser or browser Java plugin, SSH
access, or a native VNC client.)

## Example

The embedded webserver HTTPS and VNC SSL ports must be open to the user.

```
./kv9300_connect.pl --url URL --kvm-auth KVMUSER:KVMPASS [--http-auth HTTPUSER:HTTPPASS] [--insecure-http] [--insecure-vnc]
```

The script takes several parameters; the following two are required:
- The HTTPS URL of the KVM switch management login page
- A username:password pair to log into the KVM switch

Optional parameters:
- Optionally, a username:password pair to pass HTTP Basic authentication.
- Flags to disable SSL certificate checks (and make your session vulnerable).

```
./kv9300_connect.pl --url URL --kvm-auth KVMUSER:KVMPASS [--http-auth HTTPUSER:HTTPPASS] [--insecure-http] [--insecure-vnc]
```

Example:
```
$ ./kv9300_connect.pl --url https://10.0.0.100/ --kvm-auth 'kvmuser:kvmpass' --http-auth 'httpuser:httppass'
```

The script could be adapted for non-SSL use cases, but I don''t care about them
personally :)

## Motivation

Black Box Networks sells a line of rebadged KVM over IP switches called
ServSwitch EC.

In addition to direct native VNC client access and native VNC client SSH
tunneling, these KVM switches have a web administration interface which
launches a Java VNC client.  The VNC client authenticates to the KVM switch and
displays a custom dashboard at the bottom of the VNC display for controlling
the KVM switch hardware remotely.

The manual for the first generation (KV9304A, KV9308A, KV9316A) can be found
here:
http://ftp.blackbox.com/manuals/K/KV9300%20Series.pdf

Unfortunately, Java 1.8 security controls no longer allow non-signed applets to
run by default, necessitating various manual workarounds in the JVM
configuration to run the Java VNC client app.

Further compounding the misery, Google has removed NPAPI plugin support from
the popular Chrome browser in favor of the more modern PPAPI plugin interface,
but as a side effect has disabled the Java browser plugin which relies on
NPAPI.

Worse, as of January 2016, Oracle, the current owner of Java, announced that
the Java browser plug-in interface would be phased out due to security
concerns, eventually leaving the user with no way at all to remotely access
this series of KVM switches.

Instead, this program uses the Java `appletviewer` developer tool to launch the
KVM client applet as a standalone, native Java application.

## Installation

Just download the script and run it.

## Contribution

Send me your pull requests.

## License

MIT.
