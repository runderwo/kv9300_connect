## What is this?

This is a program to launch an authenticated VNC session connected to the
console of a Black Box KV9300 series KVM over IP switch, without using a web
browser or Java browser plugin, or a SSH tunnel.

## Example

The script takes up to three parameters, two of which are required:
- The HTTPS URL of the KVM switch management login page
- A username:password pair to log into the KVM switch
- Optionally, a username:password pair to pass HTTP Basic authentication.

```
$ ./kv9300_connect.pl https://10.0.0.100/ 'kvmuser:kvmpass' 'httpuser:httppass'
```

The script could be adapted for non-SSL use cases, but I don''t care about them
personally :)

## Motivation

Black Box sells a line of rebadged KVM over IP switches.  In addition to direct
unauthenticated VNC access and SSH tunneling, these KVM switches have a web
interface which launches a Java VNC client that authenticates to the KVM switch
and displays a custom dashboard at the bottom for controlling the KVM switch
hardware remotely.

The manual for the first generation (KV9304A, KV9308A, KV9316A) can be found
here:
http://ftp.blackbox.com/manuals/K/KV9300%20Series.pdf

Unfortunately, Java 1.8 security controls no longer allow non-signed applets to
run by default, necessitating various manual workarounds in the JVM
configuration to run the KVM switch client app.

Further compounding the misery, Google has removed NPAPI plugin support from
the popular Chrome browser in favor of the more modern PPAPI plugin interface,
but as a side effect has disabled the Java browser plugin which relies on
NPAPI.

Worse, as of January 2016, Oracle, the current owner of Java, announced that
the Java browser plug-in interface would be phased out due to security
concerns, eventually leaving the user with no way at all to remotely access
this series of KVM switches.

Instead, this program uses the Java `appletviewer` developer tool to launch the
KVM client applet as a standalone Java application.

## Installation

Just download the script and run it.

## Contribution

Send me your pull requests.

## License

MIT.
