package server

import "encoding/xml"

const (
	RPCGetRequest       = "GET"
	RPCGetConfigRequest = "GET-Config"
	RPCGetSchemas       = "/netconf-state:netconf-state/schemas"
	RPCGetYangModules   = "/modules-state:modules-state[xmlns=urn:ietf:params:xml:ns:yang:ietf-yang-library]"

	RPCDelimiter   = "]]>]]>"
	ChunkDelimiter = "\n##\n"

	ChunkedMessage = "\n#%d\n%s\n##\n"

	NsNetconfMonitoring = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"

	// NETCONF capability URNs advertised in the <hello>; see
	// advertisedBaseCapabilities for the policy on which ones are listed.
	CapNetconf10       = "urn:ietf:params:netconf:base:1.0"
	CapNetconf11       = "urn:ietf:params:netconf:base:1.1"
	CapWritableRunning = "urn:ietf:params:netconf:capability:writable-running:1.0"
	CapXPath           = "urn:ietf:params:netconf:capability:xpath:1.0"
	CapMonitoring      = NsNetconfMonitoring
)

// advertisedBaseCapabilities returns the fixed NETCONF capability URNs sent in
// the server <hello>, independent of the dynamically discovered YANG modules
// and the yang-library capability.
//
// Only capabilities whose operations this server actually implements are
// returned (RFC 6241 §8):
//   - base:1.0 / base:1.1      protocol base
//   - :writable-running:1.0    <edit-config> writes the running datastore directly
//   - :xpath:1.0               XPath select filters in <get>/<get-config>
//   - ietf-netconf-monitoring  <get-schema>
//
// Capabilities for operations this server does NOT implement are deliberately
// excluded so the <hello> never advertises something it cannot honor:
// :candidate, :validate, :confirmed-commit, :with-defaults, :notification,
// :interleave, :rollback-on-error and :url. :startup is also excluded — the
// SONiC-specific <commit> persists the running config with sonic-cfggen, which
// is not the RFC 6241 §8.7 startup datastore / <copy-config> mechanism.
func advertisedBaseCapabilities() []string {
	return []string{
		CapNetconf10,
		CapNetconf11,
		CapWritableRunning,
		CapXPath,
		CapMonitoring,
	}
}

type RPCError struct {
	XMLName       xml.Name `xml:"rpc-error"`
	ErrorType     string   `xml:"error-type"`
	ErrorTag      string   `xml:"error-tag"`
	ErrorSeverity string   `xml:"error-severity"`
	ErrorAppTag   string   `xml:"error-app-tag"`
	ErrorPath     string   `xml:"error-path"`
	ErrorMessage  string   `xml:"error-message"`
	ErrorInfo     struct {
		BadElement   string `xml:"bad-element"`
		BadAttribute string `xml:"bad-attribute"`
		BadNamespace string `xml:"bad-namespace"`
		SessionID    string `xml:"session-id"`
		InnerXML     []byte `xml:",innerxml"`
	} `xml:"error-info"`
}

type Filter struct {
	Type    string `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 type,attr,omitempty"`
	Select  string `xml:"select,attr,omitempty"`
	Subtree string `xml:",innerxml"`
}

type Get struct {
	XMLName xml.Name `xml:"rpc"`
	// Filter  *Filter  `xml:"filter,omitempty"`
	// WithDefaults DefaultsMode `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults with-defaults,omitempty"`
}

type DefaultsMode string

type Hello struct {
	XMLName      xml.Name `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 hello"`
	Capabilities []string `xml:"capabilities>capability"`
	SessionID    int      `xml:"session-id,omitempty"`
}

type Schema struct {
	XMLName    xml.Name `xml:"schema"`
	Identifier string   `xml:"identifier"`
	Version    string   `xml:"version,omitempty"`
	Format     string   `xml:"format,omitempty"`
	NameSpace  string   `xml:"namespace,omitempty"`
	Location   string   `xml:"location,omitempty"`
	ModelPath  string   `xml:"-"`
}

type ModulesState struct {
	XMLName     xml.Name `xml:"urn:ietf:params:xml:ns:yang:ietf-yang-library modules-state"`
	ModuleSetId *string  `xml:"module-set-id"`
	Modules     []Module `xml:"urn:ietf:params:xml:ns:yang:ietf-yang-library modules"`
}

type Module struct {
	XMLName         xml.Name `xml:"module"`
	Name            *string  `xml:",name"`
	ConformanceType string   `xml:"conformance-type"`
	Feature         []string `xml:"feature"`
	Namespace       *string  `xml:"namespace"`
	Revision        *string  `xml:"revision"`
	Schema          *string  `xml:"schema"`
	// Submodule       Module `xml:"submodule"`
	// Deviation       map[ModuleKey]*ModuleKey `xml:"deviation"`
}

type State struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring netconf-state"`
	Schemas []Schema `xml:"schemas>schema"`
}

type GetSchema struct {
	XMLName    xml.Name `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring get-schema"`
	Identifier string   `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring identifier"`
	Version    string   `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring version,omitempty"`
	Format     string   `xml:"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring format,omitempty"`
}
