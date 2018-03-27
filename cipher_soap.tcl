# Meat of the cipher SOAP service.

package require xml
package require dom
package require SOAP::Domain

package require cipher

namespace eval urn:tclsoap:cipher {

   proc getLanguages {} {
       return english
   }

   proc getCipherTypes {} {
       return [cipher types]
   }

   SOAP::export getCipherTypes
   SOAP::export getLanguages
}

SOAP::Domain::register -prefix /cipher \
    -namespace urn:tclsoap:cipher -uri urn:tclsoap:cipher
