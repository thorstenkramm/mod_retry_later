Apache Retry Later Module  
For Apache 2.4  
Thorsten Kramm, dimedis GmbH  

Based on:  
[Apache Evasive Maneuvers Module](https://github.com/jzdziarski/mod_evasive/tree/master)
For Apache 1.3 and 2.0  
Jonathan Zdziarski, Version 1.10 [2005.0117]

## Changes to the original version

* Returns "429 Too many requests" instead of "403 Forbidden" and a Retry-After header indicating when the next
  request will be allowed.
* Dropped support for Apache < 2.4

## WHAT IS mod_retry_later ?

mod_retry_later is an evasive maneuvers module for Apache to provide evasive
action in the event of an HTTP DoS or DDoS attack or brute force attack.  It
is also designed to be a detection tool, and can be easily configured to talk
to ipchains, firewalls, routers, etc.

Detection is performed by creating an internal dynamic hash table of IP
Addresses and URIs, and denying any single IP address from any of the following:

- Requesting the same page more than a few times per second
- Making more than 50 concurrent requests on the same child per second
- Making any requests while temporarily blacklisted (on a blocking list)

This method has worked well in both single-server script attacks and
distributed attacks, but just like other evasive tools, is only as
useful to the point of bandwidth and processor consumption (e.g. the
amount of bandwidth and processor required to receive/process/respond
to invalid requests), which is why it's a good idea to integrate this
with your firewalls and routers.

This module instantiates for each listener individually, and therefore has
a built-in cleanup mechanism and scaling capabilities.  Because of this,
legitimate requests are rarely ever compromised, only legitimate attacks.  Even
a user repeatedly clicking on 'reload' should not be affected unless they do
it maliciously.

## HOW IT WORKS

A web hit request comes in. The following steps take place:

- The IP address of the requestor is looked up on the temporary blacklist
- The IP address of the requestor and the URI are both hashed into a "key".  
  A lookup is performed in the listener's internal hash table to determine
  if the same host has requested this page more than once within the past
  1 second.
- The IP address of the requestor is hashed into a "key".
  A lookup is performed in the listener's internal hash table to determine
  if the same host has requested more than 50 objects within the past
  second (from the same child).

If any of the above are true, a 403 response is sent.  This conserves
bandwidth and system resources in the event of a DoS attack.  Additionally,
a system command and/or an email notification can also be triggered to block
all the originating addresses of a DDoS attack.

Once a single 429 incident occurs, mod_retry_later now blocks the entire IP
address for a period of 10 seconds (configurable).  If the host requests a
page within this period, it is forced to wait even longer.  Since this is
triggered from requesting the same URL multiple times per second, this
again does not affect legitimate users.

The blacklist can/should be configured to talk to your network's firewalls
and/or routers to push the attack out to the front lines, but this is not
required.

mod_retry_later also performs syslog reporting using daemon.alert.  Messages
will look like this:

    Aug  6 17:41:49 elijah mod_retry_later[23184]: [ID 801097 daemon.alert] Blacklisting address x.x.x.x: possible attack.

## WHAT IS THIS TOOL USEFUL FOR?

This tool is *excellent* at fending off request-based DoS attacks or scripted
attacks, and brute force attacks. When integrated with firewalls or IP filters,
mod_retry_later can stand up to even large attacks. Its features will prevent you
from wasting bandwidth or having a few thousand CGI scripts running as a
result of an attack.

If you do not have an infrastructure capable of fending off any other types
of DoS attacks, chances are this tool will only help you to the point of
your total bandwidth or server capacity for sending 403's.  Without a solid
infrastructure and address filtering tool in place, a heavy distributed DoS
will most likely still take you offline.

## HOW TO INSTALL

    apt install apache2-dev
    git clone https://github.com/thorstenkramm/mod_retry_later.git
    cd mod_retry_later
    sudo apxs -i -a -c mod_retry_later.c

## CONFIGURATION

mod_retry_later has default options configured, but you may also add the
following block to your `/etc/apache2/mods-enabled/retry_later.conf`:

```
<IfModule mod_retry_later.c>
    DOSHashTableSize    3097
    DOSPageCount        2
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
</IfModule>
```

Optionally you can also add the following directives:

    DOSEmailNotify	you@yourdomain.com
    DOSSystemCommand	"su - someuser -c '/sbin/... %s ...'"
    DOSLogDir		"/var/lock/mod_retry_later"

    DOSExcludeURIRe <REGEX>
    # DOSExcludeURIRe \.(jpg|png|gif|css|js|woff|svg)$

    DOSResponseDocument <PATH>
    # DOSResponseDocument /var/www/html/429.html

    DOSDebugLog <PATH>
    # DOSDebugLog /tmp/retry_later_debug.log

    DOSClientIPHeader <HEADER-NAME>
    #DOSClientIPHeader my-ip

You will also need to add this line if you are building with dynamic support:

    LoadModule retry_later_module /usr/lib/apache2/modules/mod_retry_later.so

(This line is already added to your configuration by apxs)

## Configuration settings

### DOSHashTableSize

The hash table size defines the number of top-level nodes for each child's
hash table.  Increasing this number will provide faster performance by
decreasing the number of iterations required to get to the record, but
consume more memory for table space.  You should increase this if you have
a busy web server.  The value you specify will automatically be tiered up to
the next prime number in the primes list (see mod_retry_later.c for a list
of primes used).

#### DOSPageCount

This is the threshold for the number of requests for the same page (or URI)
per page interval.  Once the threshold for that interval has been exceeded,
the IP address of the client will be added to the blocking list.

### DOSSiteCount

This is the threshold for the total number of requests for any object by
the same client on the same listener per site interval.  Once the threshold
for that interval has been exceeded, the IP address of the client will be added
to the blocking list.

### DOSPageInterval

The interval for the page count threshold; defaults to 1 second intervals.

### DOSSiteInterval

The interval for the site count threshold; defaults to 1 second intervals.

### DOSBlockingPeriod

The blocking period is the amount of time (in seconds) that a client will be
blocked for if they are added to the blocking list.  During this time, all
subsequent requests from the client will result in a 403 (Forbidden) and
the timer being reset (e.g. another 10 seconds).  Since the timer is reset
for every subsequent request, it is not necessary to have a long blocking
period; in the event of a DoS attack, this timer will keep getting reset.

### DOSEmailNotify

If this value is set, an email will be sent to the address specified
whenever an IP address becomes blacklisted.  A locking mechanism using /tmp
prevents continuous emails from being sent.

NOTE: Be sure MAILER is set correctly in mod_retry_later.c
The default is "/bin/mail -t %s" where %s is
used to denote the destination email address set in the configuration.  
If you are running on linux or some other operating system with a
different type of mailer, you'll need to change this.

### DOSSystemCommand

If this value is set, the system command specified will be executed
whenever an IP address becomes blacklisted.  This is designed to enable
system calls to ip filter or other tools.  A locking mechanism using /tmp
prevents continuous system calls.  Use %s to denote the IP address of the
blacklisted IP.

### DOSLogDir

Choose an alternative temp directory

By default, "/tmp" will be used for locking mechanism, which opens some
security issues if your system is open to shell users.

  	http://security.lss.hr/index.php?page=details&ID=LSS-2005-01-01

In the event you have none-privileged shell users, you'll want to create a
directory writable only to the user Apache is running as (usually root),
then set this in your httpd.conf.

### WHITELISTING IP ADDRESSES

IP addresses of trusted clients can be whitelisted to insure they are never
denied.  The purpose of whitelisting is to protect software, scripts, local
search bots, or other automated tools from being denied for requesting large
amounts of data from the server.  Whitelisting should *not* be used to add
customer lists or anything of the sort, as this will open the server to abuse.
This module is very difficult to trigger without performing some type of
malicious attack, and for that reason it is more appropriate to allow the
module to decide on its own whether an individual customer should be
blocked.

To whitelist an address (or range) add an entry to the Apache configuration
in the following fashion:

    DOSWhitelist	127.0.0.1
    DOSWhitelist	127.0.0.*

Wildcards can be used on up to the last 3 octets if necessary.  Multiple
DOSWhitelist commands may be used in the configuration.

### EXCLUDE REQUESTS FROM RATE LIMITING

Usually you only want to block the "heavy" requests. Modern web applications and the 
preload functions of browsers fire multiple requests when a website is accessed.
The vast majority of requests are for static content (css, js, images, etc).

If requests for static content count for rate limiting, you need to set high thresholds.
However, the number of requests for static content can vary from page to page. 

You can exclude requests from being processed by rate limiting by extending the 
module configuration with a line like this

    DOSExcludeURIRe \.(jpg|png|gif|css)$.

If the request URI matches the regular expression, the module terminates and Apache continues.


### CUSTOMISING THE RESPONSE DOCUMENT

Because the module acts before virtual hosts are loaded, error documents specified in your
regular Apache configuration are ignored. If you want to return a custom HTML page when a client 
hits the rate limit, you can add a line like this to the module configuration:

    DOSResponseDocument /var/www/html/429.html

### RUNNING BEHIND A REVERSE PROXY

You can instruct the module to retrieve te client's IP address from a custom header instead of
using the remote IP address from the connection. Insert a line like this to the configuration file:

    DOSClientIPHeader my-ip

The above example cause the module to give the value of the "my-ip" header preference over the remote 
IP address. If the header contains a list of values, the last (most right) element is used.

Therefore, the traditional X-Forwarded-For header is not suitable. If you run Apache behind a 
reverse proxy, the proxy must insert the client's IP address in a custom header you can trust.

If a client adds values to this header the module will ignore it, because these values will be 
the first in the list.

Header names are not case-sensitive. Using "my-ip" or "My-IP" gives the same results.

### DEBUG LOGGING

By inserting a line like this to the configuration, you can enable additional logging.

    DOSDebugLog /tmp/retry_later_debug.log

You get log lines like this example:

    [2024-05-17 09:42:57] "GET /" 429 "curl/7.74.0" "Remote-IP: ::1", "Real-Client-IP (From connection): ::1"
    [2024-05-17 09:39:59] "GET /" 429 "curl/7.74.0" "Remote-IP: ::1", "Real-Client-IP (From Header my-ip): 192.167.9.92"

This debug logging is only useful if you pretend retrieving the client's IP address from a custom header.
All requests and response code are logged to the Apache access log anyway. If you retrieve the client's IP 
address from the connection (default), the debug log contains the same information as the access log.

If the client's IP address is extracted from a custom header, the log contains both, the IP address from the 
connection, usually the IP address from the reverse proxy, and the IP address retrieved from the custom header.

**A note on system**  

If you run Apache2 from systemd the log file might not be written because systemd prevents it.
Run Apache in foreground to activate the debug log.

    apachectl -D FOREGROUND

## TWEAKING APACHE

The keep-alive settings for your children should be reasonable enough to
keep each child up long enough to resist a DOS attack (or at least part of
one).  Remember, it is the child processes that maintain their own internal
IP address tables, and so when one exits, so does all the IP information it
had. For every child that exits, another 5-10 copies of the page may get
through before putting the attacker back into '403 Land'.  With this said,
you should have a very high MaxRequestsPerChild, but not unlimited as this
will prevent cleanup.

You'll want to have a MaxRequestsPerChild set to a non-zero value, as
DosEvasive cleans up its internal hashes only on exit.  The default
MaxRequestsPerChild is usually 10000.  This should suffice in only allowing
a few requests per 10000 per child through in the event of an attack (although
if you use DOSSystemCommand to firewall the IP address, a hole will no
longer be open in between child cycles).

## TESTING

Use `ab` to simulate many parallel requests. For example:

    ab -c 5 -n 10 http://localhost/

Another way to create consecutive requests is a simple watch loop.

    watch -n 0.2 curl localhost

## KNOWN BUGS

- This module appears to conflict with the Microsoft Frontpage Extensions.
  Frontpage sucks anyway, so if you're using Frontpage I assume you're asking
  for problems, and not really interested in conserving server resources anyway.

## FEEDBACK

Use the repo issues to submit bugs.
