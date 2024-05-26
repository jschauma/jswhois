/* whois lookup results in json format
 *
 * This code is beerware:
 *
 * Originally written by Jan Schaumann
 * <jschauma@netmeister.org> in December 2021.
 *
 * As long as you retain this notice you can
 * do whatever you want with this code.  If we
 * meet some day, and you think this code is
 * worth it, you can buy me a beer in return.
 */

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const PROGNAME = "jswhois"
const VERSION = "1.1"

const EXIT_FAILURE = 1
const EXIT_SUCCESS = 0

const IANAWHOIS = "whois.iana.org"

var DEFAULT_WHOIS = IANAWHOIS
var PORT = 43
var FORCE = false
var LEAF_ONLY = false
var OUTPUT = map[string]interface{}{}
var RECURSIVE = true
var VERBOSITY int

var COMMENTS = map[string]bool{
	"%":    true, /* e.g., whois.iana.org */
	"*":    true, /* e.g., whois.nic.it */
	"#":    true, /* e.g., whois.nic.uk */
	"[ ":   true, /* e.g., whois.jprs.jp */
	" ---": true, /* not really a comment, but can be skipped */
	"- ":   true, /* e.g., whois.kr */
}

var END = map[string]bool{
	">>>":                                true,
	"--":                                 true,
	"terms of use:":                      true,
	"this whois information is provided": true,
	"copyright notice":                   true,
	"[disclaimer]":                       true,
}

/* Various commonly encountered lines that we count as commentary: */
var COMMENTARY = map[string]bool{
	"whois lookup made":   true,
	"all rights reserved": true,
	"copyright":           true,
	"for more information on whois status codes": true,
	"register your domain name at":               true,
	"url of the":                                 true,
	"record expires on":                          true,
	"record created on":                          true,
	"please visit":                               true,
	"available at":                               true,
}

/* Some of these patterns are duplicates, because
 * while we process the same format, we may create
 * data objects in a different manner. */
var FORMAT_PATTERNS = map[string]*regexp.Regexp{
	/* e.g., whois.nic.tm
	 *
	 * key1  : value1
	 *       : value2
	 * key2  : value1
	 */
	"columnContinue": regexp.MustCompile(`^(\s*)([^:]+):\s*(.*)$`),

	/* e.g., whois.iana.org
	 *
	 * key1: value1
	 * key2: value2
	 *
	 * key3: value3
	 * key4: value4
	 */
	"twoColumnsStrict":       regexp.MustCompile(`^\s*([^\s][^:]+):\s*(.*)$`),

	/* e.g., whois.dns.pl
	 *
	 * key1:   value1
	 * key2:   value2
	 *         value2-cont
	 *
	 * key3:
	 * value1
	 * value2
	 */
	"twoColumnsAddIfMissing": regexp.MustCompile(`^\s*([^\s][^:]+):\s*(.*)$`),

	/* e.g., whois.sgnic.sg
	 *
	 * Key1: Value1
	 * Key2: Value2
	 *
	 *     Key3:
	 *        SubKey1: Value4
	 */
	"simpleSubobjects": regexp.MustCompile(`^(\s*)([^:]+):(\s+.*)?$`),

	/* e.g., whois.dot.ml
	 *
	 * Almost the same as 'simpleSubobjects', but
	 * we populate documents slightly differently so use
	 * the same regex, but a different name.
	 *
	 * key1:
	 *   subkey1: value1
	 *   subkey2: value2
	 *
	 * key2:
	 *   subkey1: value1
	 *   subkey2: value2
	 *
	 * key3:
	 *   value1
	 *   value2
	 */
	"twoColumnSubobjects": regexp.MustCompile(`^(\s*)([^:]+):(\s+.*)?$`),

	/* e.g., whois.jprs.jp
	 *
	 * key1:   value1
	 * [key2]  value2
	 *
	 * [key3]  value3
	 *         value3-cont
	 */
	"twoColumnsBrackets":   regexp.MustCompile(`^(\[?[^\]:]+[\]:])\s*(.+)?`),

	/* e.g., whois.nic.uk
	 *
	 * key1:
	 *   value1
	 *   value2
	 *
	 * key2:
	 *   value1
	 *   value2
	 */
	"multiline":            regexp.MustCompile(`^\s*(.*)`),
}

const DEFAULT_FORMAT = "twoColumnsStrict"

/* "createObject" is like IANA output:
 *
 * key1: val
 * key2: val
 *
 * key3: val
 * key4: val
 *
 * This setting is used at times to force the creation
 * of subobjects that are grouped together.
 */
var CREATE_OBJECT_LOOKUP = map[string]bool{
	"whois.afrinic.net":   true,
	"whois.apnic.net":     true,
	"whois.dns.be":        true,
	"whois.dominio.gq":    true,
	"whois.dot.cf":        true,
	"whois.dot.ml":        true,
	"whois.dot.tk":        true,
	"whois.iana.org":      true,
	"whois.isnic.is":      true,
	"whois.isoc.org.il":   true,
	"whois.lacnic.net":    true,
	"whois.marnet.mk":     true,
	"whois.nic.alsace":    true,
	"whois.nic.aquarelle": true,
	"whois.nic.ar":        true,
	"whois.nic.at":        true,
	"whois.nic.bo":        true,
	"whois.nic.bostik":    true,
	"whois.nic.bzh":       true,
	"whois.nic.corsica":   true,
	"whois.nic.cr":        true,
	"whois.nic.cz":        true,
	"whois.nic.fr":        true,
	"whois.nic.lancaster": true,
	"whois.nic.leclerc":   true,
	"whois.nic.mma":       true,
	"whois.nic.museum":    true,
	"whois.nic.mw":        true,
	"whois.nic.ovh":       true,
	"whois.nic.paris":     true,
	"whois.nic.pm":        true,
	"whois.nic.re":        true,
	"whois.nic.sm":        true,
	"whois.nic.sn":        true,
	"whois.nic.sncf":      true,
	"whois.nic.tf":        true,
	"whois.nic.tr":        true,
	"whois.nic.ve":        true,
	"whois.nic.wf":        true,
	"whois.nic.yt":        true,
	"whois.registro.br":   true,
	"whois.ripe.net":      true,
	"whois.rnids.rs":      true,
	"whois.sk-nic.sk":     true,
	"whois.tznic.or.tz":   true,
	"whois.ua":            true,
}

var FORMAT_LOOKUP = map[string]string{
	"whois.bnnic.bn":           "simpleSubobjects",
	"whois.cctld.uz":           "multiline",
	"whois.dns.be":             "twoColumnSubobjects",
	"whois.dns.pl":             "twoColumnsAddIfMissing",
	"whois.domain-registry.nl": "multiline",
	"whois.dominio.gq":         "twoColumnSubobjects",
	"whois.dot.cf":             "twoColumnSubobjects",
	"whois.dot.ml":             "twoColumnSubobjects",
	"whois.dot.tk":             "twoColumnSubobjects",
	"whois.educause.edu":       "multiline",
	"whois.eu":                 "simpleSubobjects",
	"whois.gg":                 "simpleSubobjects",
	"whois.je":                 "simpleSubobjects",
	"whois.jprs.jp":            "twoColumnsBrackets",
	"whois.kr":                 "twoColumnSubobjects",
	"whois.kg":                 "simpleSubobjects",
	"whois.monic.mo":           "multiline",
	"whois.mx":                 "twoColumnSubobjects",
	"whois.nic.as":             "simpleSubobjects",
	"whois.nic.aw":             "simpleSubobjects",
	"whois.nic.it":             "twoColumnSubobjects",
	"whois.nic.lv":             "twoColumnSubobjects",
	"whois.nic.net.sa":         "multiline",
	"whois.nic.sm":             "twoColumnSubobjects",
	"whois.nic.tm":             "columnContinue",
	"whois.nic.tr":             "twoColumnSubobjects",
	"whois.nic.uk":             "multiline",
	"whois.register.bg":        "multiline",
	"whois.sgnic.sg":           "simpleSubobjects",
	"whois.tld.ee":             "twoColumnSubobjects",
	"whois.tonic.to":           "multiline",
	"whois.twnic.net.tw":       "multiline",
}

/* Some whois servers generate output that continues
 * after common 'end' markers... */
var IGNOREEND_LOOKUP = map[string]bool{
	"whois.bnnic.bn":     true,
	"whois.educause.edu": true,
	"whois.gg":           true,
	"whois.minico.mo":    true,
	"whois.nic.firmdale": true,
	"whois.nic.gdn":      true,
	"whois.sgnic.sg":     true,
}

/* Some whois servers begin (or end) object markers
 * or keys with additional strings. */
var STRIPSTRINGS_LOOKUP = map[string][]string {
	"whois.nic.tr": []string{"**"},
	"whois.nic.lv": []string{"[", "]"},
}

/* Used to force creation of key-values in a strict
 * two-column format.  This helps when encountering
 * single-column lines that belong to a previous
 * subobject. */
var TWOCOLUMN_LOOKUP = map[string]bool{
	"whois.bnnic.bn":   true,
	"whois.eu":         true,
	"whois.gg":         true,
	"whois.je":         true,
	"whois.kg":         true,
	"whois.mx":         true,
	"whois.nic.as":     true,
	"whois.nic.aw":     true,
	"whois.nic.it":     true,
	"whois.nic.lv":     true,
	"whois.nic.net.sa": true,
	"whois.nic.sm":     true,
	"whois.sgnic.sg":   true,
}

var NS_RE = regexp.MustCompile(`(?i)^(n(ame ?)?(server)s?( information)?)|(d(omain|ns)( servers)?)`)
var KV_RE = regexp.MustCompile(`^([^:]+):\s+(.+)$`)

type SubObject map[string]interface{}

/*
 * Functions
 */

func addNewSubobject(thing interface{}, k, v string) []SubObject {
	l := []SubObject{}

	switch thing.(type) {
	case SubObject:
		l = append(l, thing.(SubObject))
		s := SubObject{k: v}
		l = append(l, s)
	case []SubObject:
		l = thing.([]SubObject)
		s := SubObject{k: v}
		l = append(l, s)
	case string:
		l = append(l, SubObject{ k : []string{ thing.(string), v } })
	case []string:
		l = append(l, SubObject{ k : append(thing.([]string), v) })
	case nil:
		l = append(l, SubObject{ k : v })
	default:
		fail("Unexpected new subobject type: %s (|%v|%s|%s|)\n", reflect.TypeOf(thing), thing, k, v)
	}
	return l
}

func addToExistingSubobject(thing interface{}, k, v string) interface{} {

	switch thing.(type) {
	case SubObject:
		s := thing.(SubObject)
		s[k] = addVal(s[k], v)
		return s
	case []SubObject:
		return addToLastSubobject(thing.([]SubObject), k, v)
	case string:
		return []string{ thing.(string), v }
	case []string:
		return append(thing.([]string), v)
	default:
		fail("Unexpected existing subobject type: %s (|%s|%s|)\n", reflect.TypeOf(thing), k, v)
	}

	return nil
}

func addToLastSubobject(l []SubObject, k, v string) []SubObject {
	ll := len(l) - 1
	s := l[ll]
	s[k] = addVal(s[k], v)
	l[ll] = s
	return l
}

func addVal(which interface{}, item interface{}) (back interface{}) {
	switch which.(type) {
	case string:
		switch item.(type) {
		case []string:
			back = append([]string{which.(string)}, item.([]string)...)
		case string:
			if len(item.(string)) > 0 {
				back = []string{which.(string), item.(string)}
			} else {
				back = which
			}
		case SubObject:
			back = item
		}
	case []string:
		switch item.(type) {
		case string:
			if len(item.(string)) > 0 {
				back = append(which.([]string), item.(string))
			} else {
				back = which
			}
		case []string:
			back = append(which.([]string), item.([]string)...)
		}
	case []SubObject:
		back = append(which.([]SubObject), item.(SubObject))
	case SubObject:
		back = []SubObject{which.(SubObject), item.(SubObject)}
	case nil:
		back = item
	default:
		fail("Unexpected value type: %s\n%s\n", reflect.TypeOf(which), which)
	}

	return
}

func argcheck(flag string, args []string, i int) {
	if len(args) <= (i + 1) {
		fail("'%v' needs an argument", flag)
	}
}

/* This function is all sorts of convoluted and
 * difficult to debug.  Several formats or sections
 * are functionally similar and could probably be
 * combined more elegantly.
 *
 * By and large the logic goes somewhat like this:
 *
 * Try to parse line-by-line and identify key-value
 * pairs based on the whois server's known or
 * speculated format and regex.
 *
 * 'key: val' becomes simply '"key" : "val"'; but:
 * - if we encounter a subsequent 'key: val', then
 *   we build a list ('"key" : [ "val1", "val2" ]')
 * - if we use 'createObject', then we group key-value
 *   pairs that are separated by empty lines into a
 *   subobject
 *
 * 'key:' or 'key' alone on a line can be
 * - the marker for a new subobject
 * - a continuation of a previous key
 * - a comment
 *
 * Since the whois protocol does not define any output
 * format, we basically get whatever a human on the
 * other end decided would make sense.  And for the
 * most part this is easy to visually identify as
 * logical blocks or subobjects _by another human_,
 * but trying to teach a stupid computer this sort of
 * thing is really tedious and annoying, which is why
 * we ended up with the mess below.  I apologize.
 */
func askWhois(server, query string) (data map[string]interface{}) {
	data = map[string]interface{}{}
	verbose(2, "Looking up '%s' at '%s'...", query, server)

	nextWhois := ""
	subObject := SubObject{}
	previousKey := ""
	thisKey := ""
	var previousValue interface{}

	/* Name Servers get expanded differently, so
	 * we used a separate subobject to collect them. */
	nsAddrs := SubObject{}

	/* Used in combination with 'twoColumn' to
 	 * determine whether a single line should be
 	 * added to the previous entry. */
	columns := 0

	/* Effectively a signal that we had an empty
 	 * line.  Used to create subobjects if needed. */
	newBlock := false

	/* e.g., ati.tn
	 *
	 * key1: val
	 * key2: val
	 *
	 * key3
	 * key4: val
	 * key5
	 * key6: val
	 *
	 * So we set 'noObjectsUntil = key3' to ensure
	 * the first entries remain top-level.
	 */
	noObjectsUntil := ""

	/* The name of the current subobject, used to
	 * track if we need to append or create a new
	 * subobject. */
	objectName := ""

	/* Some whois servers use whitespace
	 * indentation to signal logical groupings.
	 * We rarely rely on that, but as a fallback
	 * keep track. */
	indentation := ""

	/* Ok, this is sneaky.  We use a map for O(1)
	 * lookup; if an entry is found, it uses these
	 * types of objects or settings. */
	_, createObject := CREATE_OBJECT_LOOKUP[server]
	_, twoColumn := TWOCOLUMN_LOOKUP[server]
	_, ignoreEnd := IGNOREEND_LOOKUP[server]

	stripStrings := STRIPSTRINGS_LOOKUP[server]

	format, found := FORMAT_LOOKUP[server]
	if !found {
		format = DEFAULT_FORMAT
	}

	/* Special cases for whois servers using different formats: */
	switch server {
	case "whois.ati.tn":
		noObjectsUntil = "Details"
	case "whois.nic.tr":
		delete(COMMENTS, "*")
	case "whois.nic.net.sa":
		delete(COMMENTS, "*")
	}

	response := runWhois(server, query)
	for _, line := range strings.Split(response, "\n") {
		columns = 0

		kvFound := false
		keyvalue := KV_RE.FindStringSubmatch(line)
		if len(keyvalue) > 0 {
			kvFound = true
		}

		if hasMarker(COMMENTS, line) {
			continue
		}

		if !ignoreEnd && hasMarker(END, line) {
			break
		}

		if hasMarker(COMMENTARY, line) {
			data["comments"] = addVal(data["comments"], line)
			continue
		}

		for _, s := range stripStrings {
			line = strings.TrimLeft(line, s)
			line = strings.TrimRight(line, s)
		}

		if len(noObjectsUntil) > 0 && strings.HasPrefix(line, noObjectsUntil) {
			noObjectsUntil = ""
			createObject = true
			previousKey = ""
			previousValue = nil
			objectName = strings.TrimRight(line, ":")
			continue
		}

		/* Multiple scenarios:
		 * - we just ended a number of values for a multiline entry
		 * - we ended a logical section and have a sub-object to add */

		if format != "simpleSubobjects" && len(line) < 1 {
			if format == "multiline" && len(objectName) > 0 {
				if reflect.TypeOf(data[objectName]) == reflect.TypeOf([]string{}) {
					data[objectName] = expand(objectName, data[objectName].([]string))
					objectName = ""
				}
			}

			if createObject && len(objectName) > 0 {
				/* Our subObject only contains one element,
				 * so reparent into 'data'... */
				if len(subObject) < 2 {
					for k, v := range subObject {
						data[k] = v
					}
				} else {
					/* ...otherwise add the object to 'data'. */
					if len(nsAddrs) > 0 {
						subObject["nserver"] = nsAddrs
					}
					data[objectName] = addVal(data[objectName], subObject)
				}
				objectName = ""
				previousKey = ""
				previousValue = nil
			}

			/* successive empty lines reset everything */
			if newBlock {
				objectName = ""
				previousKey = ""
				previousValue = nil
			}

			/* Reset any interim object that we may have added to 'data' above. */
			subObject = SubObject{}

			if format == "twoColumnsAddIfMissing" || format == "multiline" {
				objectName = ""
			}

			newBlock = true

			/* Either way, we are on an empty line, so let's move on. */
			continue
		}

		/* Now we know we do not have an an empty line. */

		key := ""
		currentValue := ""
		p := FORMAT_PATTERNS[format]
		m := p.FindStringSubmatch(line)
		switch format {
		case "multiline":
			if len(m) > 0 {
				key = m[1]
				currentValue = key
			}
		case "twoColumnsAddIfMissing":
			fallthrough
		case "twoColumnsBrackets":
			fallthrough
		case "twoColumnsStrict":
			if len(m) > 0 {
				columns = len(m)
				key = m[1]
				currentValue = key
				if columns > 1 {
					currentValue = m[2]
				}
			}
		case "columnContinue":
			fallthrough
		case "simpleSubobjects":
			fallthrough
		case "twoColumnSubobjects":
			if len(m) > 0 {
				indentation = m[1]
				key = m[2]
				currentValue = key
				if len(m) > 2 {
					currentValue = m[3]
				}
			} else {
				currentValue = strings.TrimSpace(line)
			}
		}

		currentValue = strings.TrimSpace(currentValue)

		/* Some commentary contains URLs, so let's not split those. */
		if (strings.HasSuffix(key, "http") || strings.HasSuffix(key, "https")) &&
			strings.HasPrefix(currentValue, "//") {
			key = line
			currentValue = line
		}

		/* e.g., whois.nic.tn fills key spaces with ... */
		key = strings.TrimRight(key, ".")
		key = strings.TrimSpace(key)

		/* e.g., whois.nic.tg fills value spaces with ... */
		currentValue = strings.TrimLeft(currentValue, ".")

		var o interface{}
		objectFound := false

		if len(objectName) < 1 {
			if format != "multiline" {
				objectName = key

			} else if !strings.HasSuffix(key, ":") {
				if kvFound {
					data[strings.TrimSpace(keyvalue[1])] = strings.TrimSpace(keyvalue[2])
				} else {
					data["comments"] = addVal(data["comments"], key)
				}

				/* Multiline, no key - we're done. */
				goto _END_OF_LOOP
			}
		}

		o, objectFound = data[objectName]

		if format == "columnContinue" {
			if len(key) < 1 {
				key = previousKey
			}
			if strings.Contains(currentValue, ",") {
				data[key] = addVal(data[key], strings.Split(currentValue, ","))
			} else {
				data[key] = addVal(data[key], currentValue)
			}
			previousKey = key
			goto _END_OF_LOOP
		}

		if format == "simpleSubobjects" {
			/*
			 * Key1: Value1
			 * Key2: Value2
			 *
			 *     Key3:
			 *        SubKey1: Value4
			 */

			/* key3 */
			if len(key) > 0 && len(currentValue) < 1 {
				if len(subObject) > 0 {
					if len(previousKey) < 1 {
						for k, v := range subObject {
							data[k] = v
						}
					} else {
						data[previousKey] = subObject
					}
				}
				subObject = SubObject{}
				previousKey = key

			/* key: value */
			} else if len(key) > 0 && currentValue != key {
				subObject[key] = addVal(subObject[key], currentValue)

			/* continued value */
			} else if len(currentValue) > 0 && len(previousKey) > 0 {
				data[previousKey] = addVal(data[previousKey], currentValue)
			}

			thisKey = ""
		}

		if format == "twoColumnSubobjects" {
			/*
			 * key1:
			 *   subkey1: value1
			 *   subkey2: value2
			 *
			 * key2:
			 *   value1
			 *   value2
			 */
			if !kvFound {

				/* key2 */
				if newBlock {
					objectName = strings.TrimSpace(line)
					objectName = strings.TrimRight(objectName, ":")
					data[objectName] = SubObject{}
					newBlock = false
					goto _END_OF_LOOP
				}

				/* no previous object */
				if !objectFound {
					if len(currentValue) > 0 {
						data["comments"] = addVal(data["comments"], currentValue)
					}
					goto _END_OF_LOOP
				}

				if len(previousKey) < 1 {
					previousKey = objectName
				}
				/* value1 */
				data[objectName] = updateTopOrSubobject(o, previousKey, currentValue)
			} else {
				if objectFound {
					if newBlock {
						data[objectName] = addNewSubobject(o, key, currentValue)
						newBlock = false
						goto _END_OF_LOOP
					} else if len(indentation) < 1 {
						/* We just hope sub-objects are indented; otherwise,
 						 * we really can't tell. */
						data[key] = addVal(data[key], currentValue)
					} else {
						data[objectName] = addToExistingSubobject(data[objectName], key, currentValue)
					}
				} else {
					/* new single-line object */
					data[key] = currentValue
					objectName = ""
				}
				previousKey = key
			}
			goto _END_OF_LOOP
		}

		if format == "twoColumnsBrackets" {
			/*
			 * key1:   value1
			 * [key2]  value2
			 *
			 * [key3]  value3
			 *         value3-cont
			 */

			key = strings.TrimRight(key, ":")
			previousKey = strings.TrimRight(previousKey, ":")
			objectName = strings.TrimRight(objectName, ":")

			if !strings.HasPrefix(key, "[") {
				if len(key) > 0 && len(currentValue) > 0 {
					/* key1 */
					data[key] = SubObject{key: currentValue}
					objectName = key
				} else {
					/* value-cont */
					currentValue = strings.TrimSpace(line)
					data[objectName] = updateTopOrSubobject(o, previousKey, currentValue)
					goto _END_OF_LOOP
				}

			} else if ((len(previousKey) < 1) && (len(key) < 1)) ||
				((previousKey == objectName) && (len(key) == 0)) {
				/* any key */

				data[objectName] = updateTopOrSubobject(o, previousKey, currentValue)

			} else if len(objectName) > 0 && (currentValue != key) && len(currentValue) > 0 {
				/* [key2] */
				switch o.(type) {
				case SubObject:
					s := o.(SubObject)
					which := key
					if len(key) < 1 {
						which = previousKey
					}
					s[which] = addVal(s[which], currentValue)
					data[objectName] = s
					previousKey = which
					goto _END_OF_LOOP
				case nil:
					if len(previousKey) < 1 {
						data[objectName] = currentValue
					} else {
						s := SubObject{}
						if len(key) > 0 {
							s[key] = currentValue
						}
						data[objectName] = s
					}
				default:
					if key != objectName {
						data[key] = currentValue
					} else {
						data[objectName] = addVal(data[objectName], currentValue)
					}
				}
			}

			previousKey = key
			goto _END_OF_LOOP
		}

		if format == "twoColumnsAddIfMissing" {
			/*
			 * key1:   value1
			 * key2:   value2
			 *         value2-cont
			 *
			 * key3:
			 * value1
			 * value2
			 */
			re := regexp.MustCompile(`(^\s+)(.*)$`)
			if m := re.FindStringSubmatch(line); len(m) > 0 {
				/* value2 */
				thisKey = previousKey
				currentValue = strings.TrimSpace(line)
			} else if len(currentValue) < 1 && strings.HasSuffix(line, ":") {
				/* key3: */
				data[key] = []string{}
				objectName = key
			} else if len(currentValue) < 1 && len(objectName) > 0 {
				/* value2-cont */
				data[objectName] = addVal(data[objectName], line)
			} else {
				thisKey = key
			}

		} else if format == "multiline" {
			/*
			 * key1:
			 *   value1
			 *   value2
			 */
			if strings.HasSuffix(key, ":") {
				objectName = strings.TrimSuffix(key, ":")
			} else if len(currentValue) > 0 && len(objectName) > 0 {
				data[objectName] = addVal(data[objectName], strings.TrimSpace(line))
			} else {
				thisKey = key
			}
			previousKey = key
		} else if columns < 2 {
			/* Some whois servers use single-column lines as
			 * a continuation of the previous entry. */
			if twoColumn {
				if len(thisKey) > 0 {
					data[thisKey] = addVal(data[thisKey], currentValue)
				}

			} else if len(thisKey) < 1 {
				/* Otherwise, unless we have a current key, we
				 * pretend it's some single-line comment. */
				if len(currentValue) > 0 {
					data["comments"] = addVal(data["comments"], currentValue)
				}
			}
			/* Either way, we're done here. */
			continue
		} else {
			thisKey = key
			if len(key) < 1 && createObject && newBlock {
				objectName = line
				newBlock = false
				continue
			}
		}

		switch strings.ToLower(thisKey) {
		case "nsstat":
			fallthrough
		case "nslastaa":
			fallthrough
		case "remarks":
			/* e.g., nic.at uses:
			 * nserver:  ns1.nic.at
			 * remarks:  2001:67c:1bc::98
			 *
			 * e.g., registrro.br uses
			 * nserver: a.dns.br
			 * nsstat:  20220104
			 * nslastaa: 20220104
			 */
			if previousKey == "nserver" {
				nsAddrs[previousValue.(string)] = addVal(nsAddrs[previousValue.(string)], currentValue)
				previousKey = thisKey
				continue
			}
		case "whois":
			fallthrough
		case "refer":
			fallthrough
		case "registrar whois server":
			t := currentValue
			/* Sometimes a WHOIS server is listed as a URL. */
			re := regexp.MustCompile(`^(https?://)([^/]+)/?$`)
			if m := re.FindStringSubmatch(currentValue); m != nil {
				t = m[2]
			}
			if t != server {
				nextWhois = t
			}
		}

		if thisKey != previousKey {
			/* we created a subobject */
			if len(subObject) > 0 {
				for k, v := range subObject {
					if reflect.TypeOf(v) == reflect.TypeOf([]string{}) {
						subObject[k] = expand(k, v.([]string))
					}
				}
				if len(thisKey) > 0 {
					subObject[thisKey] = addVal(subObject[thisKey], currentValue)
				}
			} else if createObject && len(key) > 0 && len(currentValue) > 0 {
				subObject = SubObject{key: currentValue}
			} else if len(thisKey) > 0 {
				data[thisKey] = addVal(data[thisKey], currentValue)
			}
			previousValue = currentValue
		} else {
			if len(subObject) > 0 && len(thisKey) > 0 {
				subObject[thisKey] = addVal(subObject[thisKey], currentValue)
			} else if len(thisKey) > 0 {
				data[thisKey] = addVal(data[thisKey], currentValue)
			}
		}
		previousKey = thisKey

		_END_OF_LOOP:
		if len(line) > 0 {
			newBlock = false
		}

	}
	/* We're done processing all output from the WHOIS server. */

	if len(nextWhois) > 0 {
		data["next"] = nextWhois
	}

	data = cleanupData(data)
	return
}

func cleanupData(in map[string]interface{}) (out map[string]interface{}) {
	out = map[string]interface{}{}
	for k, v := range in {
		out[k] = v
		switch v.(type) {
		case []string:
			if NS_RE.MatchString(strings.ToLower(k)) {
				out[k] = expand(k, v.([]string))
			}
		case SubObject:
			/* re-parent single-key subobjects */
			if len(v.(SubObject)) < 2 {
				for sk, sv := range v.(SubObject) {
					if k == sk {
						out[sk] = sv
						delete(out, k)
						continue
					}

					i := sv
					switch sv.(type) {
					case string:
						i = expand(sk, []string{sv.(string)})
					case []string:
						i = expand(sk, sv.([]string))
					}

					if reflect.TypeOf(i) == reflect.TypeOf([]string{}) {
						l := i.([]string)
						i = l[0]
					}
					out[k] = SubObject{ sk: i }
				}
			}
		}
	}
	return
}

/* Expand a list of strings:
 * - if the list contains only a single element, return that element
 * - name server lines may contain "name IP [IP]", so
 *   turn that into a "{ name : [ IP1, IP2 ] }" */
func expand(entry string, list []string) (back interface{}) {
	lol := map[string][]string{}

	if !NS_RE.MatchString(strings.ToLower(entry)) {
		return list
	}

	ns := []string{}
	multiFields := false
	for _, line := range list {
		elements := strings.Fields(line)
		for n, e := range elements {
			e = strings.TrimLeft(e, "[(")
			e = strings.TrimRight(e, "])")

			/* multiple addresses not space separated */
			expanded := false
			for _, c := range []string{"][", ")(", ","} {
				items := strings.Split(e, c)
				if len(items) > 1 {
					expanded = true
					elements[n] = items[0]
					for _, i := range items[1:] {
						if len(i) > 0 {
							elements = append(elements, i)
						}
					}
				}
			}
			if !expanded {
				elements[n] = e
			}
		}

		if _, found := lol[elements[0]]; found {
			lol[elements[0]] = append(lol[elements[0]], elements[1:]...)
		} else {
			lol[elements[0]] = elements[1:]
		}
		ns = append(ns, elements[0])
		if len(elements[1:]) > 0 {
			multiFields = true
		}
	}
	if multiFields {
		back = lol
	} else {
		back = ns
	}

	return
}

func fail(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(EXIT_FAILURE)
}

func getopts() {
	var err error
	eatit := false
	args := os.Args[1:]
	os.Args = args
	for i, arg := range args {
		if eatit {
			eatit = false
			os.Args = os.Args[1:]
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			break
		}
		switch arg {
		case "-?":
			usage(os.Stdout)
			os.Exit(EXIT_SUCCESS)
		case "-Q":
			RECURSIVE = false
		case "-R":
			RECURSIVE = true
		case "-V":
			printVersion()
			os.Exit(EXIT_SUCCESS)
		case "-f":
			FORCE = true
		case "-h":
			eatit = true
			argcheck("-h", args, i)
			DEFAULT_WHOIS = args[i+1]
		case "-l":
			LEAF_ONLY = true
		case "-p":
			eatit = true
			argcheck("-p", args, i)
			PORT, err = strconv.Atoi(args[i+1])
			if err != nil {
				fail("Port must be a number.")
			}
		case "-v":
			VERBOSITY++
		default:
			fmt.Fprintf(os.Stderr, "Unexpected option or argument: %v\n", args[i])
			usage(os.Stderr)
			os.Exit(EXIT_FAILURE)
		}

		os.Args = os.Args[1:]
	}
}

func hasMarker(list map[string]bool, line string) (yesno bool) {
	yesno = false
	line = strings.ToLower(line)
	for c, _ := range list {
		if strings.HasPrefix(line, c) {
			return true
		}
	}
	return
}

func lookupWhois() {

	var allOutput = []map[string]interface{}{}
	verbose(1, "Looking up %d names...", len(os.Args))

	for _, q := range os.Args {
		OUTPUT = map[string]interface{}{}
		OUTPUT["query"] = q
		allOutput = append(allOutput, oneLookup())
	}

	j, _ := json.Marshal(allOutput)
	fmt.Printf("%s\n", j)
}


func oneLookup() (rval map[string]interface{}) {
	rval = map[string]interface{}{}
	query := OUTPUT["query"].(string)

	verbose(2, "Looking up %s...", query)

	validateQuery(query)

	var chain = []string{DEFAULT_WHOIS}
	OUTPUT[DEFAULT_WHOIS] = askWhois(DEFAULT_WHOIS, query)

	data := OUTPUT[DEFAULT_WHOIS].(map[string]interface{})
	if RECURSIVE {
		for {
			w, found := data["next"].(string)
			delete(data, "next")
			if !found {
				break
			}
			chain = append(chain, w)
			OUTPUT[w] = askWhois(w, query)
			data = OUTPUT[w].(map[string]interface{})
		}
	}
	delete(OUTPUT[DEFAULT_WHOIS].(map[string]interface{}), "next")

	OUTPUT["chain"] = chain

	if LEAF_ONLY {
		rval["query"] = OUTPUT["query"]
		rval["chain"] = chain
		rval[chain[len(chain)-1]] = data
	} else {
		rval = OUTPUT
	}

	return
}


func printVersion() {
	fmt.Printf("%v version %v\n", PROGNAME, VERSION)
}

func runWhois(server, query string) (response string) {
	verbose(3, "Asking %s for '%s'...", server, query)

	server += fmt.Sprintf(":%d", PORT)
	conn, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to %s: %s\n", server, err)
		return
	}
	defer conn.Close()

	/* Why, yes, WHOIS is indeed the world's most
	 * simple protocol. See RFC3912. */
	fmt.Fprintf(conn, "%s\r\n", query)
	s := bufio.NewScanner(conn)
	for s.Scan() {
		response += s.Text() + "\n"
	}

	return
}

func updateTopOrSubobject(thing interface{}, k, v string) interface{} {

	switch thing.(type) {
	case SubObject:
		if len(k) > 0 {
			s := thing.(SubObject)
			s[k] = addVal(s[k], v)
			return s
		} else {
			return v
		}

	case string:
		return addVal(thing, v)
	case []string:
		return addVal(thing, v)

	case []SubObject:
		return addToLastSubobject(thing.([]SubObject), k, v)

	case nil:
		return v

	default:
		fail("Unexpected object type: %s\n", reflect.TypeOf(thing))
	}

	return nil
}

func usage(out io.Writer) {
	usage := `Usage: %v [-?QRVflpv] [-h server] [-p port]
	-?         print this help and exit
	-Q         quick lookup (i.e., do not recurse)
	-R         recursive lookup (default)
	-V         print version information and exit
        -f         force lookups
	-h server  query this server (default: %s)
        -l         only print output for the last / leaf whois server
        -p port    query the whois server on this port (default: %d)
	-v         be verbose
`
	fmt.Fprintf(out, usage, PROGNAME, IANAWHOIS, PORT)
}

func validateQuery(query string) {
	if FORCE {
		return
	}

	verbose(3, "Validating %s...", query)
	if ip := net.ParseIP(query); ip != nil {
		return
	}

	if _, err := net.LookupHost(query); err != nil {
		fail("%s does not resolve; use '-f' to proceed anyway\n", query)
	}
}

func verbose(level int, format string, v ...interface{}) {
	if level <= int(VERBOSITY) {
		fmt.Fprintf(os.Stderr, "%s ", time.Now().Format("2006-01-02 15:04:05"))
		for i := 0; i < level; i++ {
			fmt.Fprintf(os.Stderr, "=")
		}
		fmt.Fprintf(os.Stderr, "> "+format+"\n", v...)
	}
}

/*
 * Main
 */

func main() {
	getopts()
	lookupWhois()
}
