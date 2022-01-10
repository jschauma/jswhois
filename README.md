# jswhois -- whois lookup results in json format

`jswhois(1)` is a tool to look up and print WHOIS
results in JSON format.

## Installation

`jswhois(1)` is written in Go, so you'll need that.

Other than that, you can install it by running `make
install`.

The Makefile defaults to '/usr/local' as the prefix,
but you can change that, if you like:

```
$ make PREFIX=~ install
```

---
```
NAME
     jswhois -- whois lookup results in json format

SYNOPSIS
     jswhois [-RQVjlv] [-h host] [-p port] domain

DESCRIPTION
     The jswhois tool performs whois(1) lookups and prints results in JSON
     format.

     Since the WHOIS protocol notoriously does not include a specification of
     the WHOIS data's format or how recursive discovery should be handled, the
     results -- much like the results of the normal whois(1) command -- tend
     to vary significantly.

OPTIONS
     The following options are supported by jswhois:

     -Q	      Do a quick lookup; jswhois will not attempt to follow referrals
	      to other whois servers.  This is the default if a server is
	      explicitly specified via the -h flag.  See also the -R option.

     -R	      Do a recursive lookup; jswhois will attempt to follow referrals
	      to other whois servers.  This is the default if -h is not speci-
	      fied.  See also the -Q option.

     -V	      Print version information and exit.

     -h host  Use the specified host instead of the default (whois.iana.org).

     -l	      Only print results from the last WHOIS server queried.

     -p port  Connect to the whois server on port. If this option is not spec-
	      ified, jswhois defaults to port 43.

     -v	      Be verbose.  Can be specified multiple times.

DETAILS
     WHOIS information is notoriously unpredictably structured and hard to
     parse.  In order to process WHOIS data with even a shred of hope of not
     getting lost in terrible regular expressions and shell pipelines and yet
     without relying on proprietary APIs jswhois will attempt to reformat the
     text output in a coherent JSON object.

     The query for any domain will always begin at 'whois.iana.org' and then
     recurse as per the data encountered.  The resulting JSON document will
     then contain nested structures indexed by the name of the WHOIS server in
     question.

     Since the data is fundamentally unstructured, attempts to stuff them into
     JSON formatting is made as outlined below:

     o	 repeated fields are turned into a list
     o	 a chain of WHOIS servers queried is added to the top object

EXAMPLES
     To display the WHOIS information for the domain 'netmeister.org':

	   $ jswhois netmeister.org | jq
	   {
	     "query": "netmeister.org",
	     "chain": [
	       "whois.iana.org",
	       "whois.pir.org",
	       "whois.gandi.net"
	     ],
	     "whois.iana.org": {
	       "domain": "ORG"
	       "organisation": {
		 "name": "Public Interest Registry (PIR)",
		 "address": [
		   "11911 Freedom Drive 10th Floor,",
		   "Suite 1000",
		   "Reston, VA 20190",
		   "United States"
		 ]
	       },
	       "contact": [ {
		 "name": "administrative",
		 ...
	       }, ... ]
	     }
	     "whois.pir.org": {
	       "Domain Name": "NETMEISTER.ORG",
	       ...
	     },
	     "whois.gandi.net": {
	       "Domain Name": "netmeister.org",
	       ...
	     }
	   }

EXIT STATUS
     The jswhois utility exits 0 on success, and >0 if an error occurs.

SEE ALSO
     whois(1), jq(1)

HISTORY
     jswhois was originally written by Jan Schaumann <jschauma@netmeister.org>
     in December 2021.

BUGS
     Please file bugs and feature requests by emailing the author.
```
