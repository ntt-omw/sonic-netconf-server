package server

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"orange/sonic-netconf-server/build/netconf_codegen"

	"github.com/antchfx/xmlquery"
	"github.com/golang/glog"
)

type Config struct {
	path      string
	operation string
	payload   map[string]interface{}
	keys      int
}

type GetRequest struct {
	path 		string
	filters 	[]string
}

type RPCRequest struct {
	path    string
	payload map[string]interface{}
}

func ParseGetRequest(node *xmlquery.Node, appendAll bool) ([]GetRequest, error) {
	// TODO: check source tag for config source, for now assume always running config
	// TODO: request path creation assumes parent -> one child structure in filter tag, validation required

	glog.Info("Starting parse Get request")

	// Start with filter node
	filterNode := xmlquery.FindOne(node, "//filter")

	if filterNode == nil {
		return []GetRequest{}, errors.New("Need filter element, can't return all configuration for now")
	}

	queryPaths := []GetRequest{}

	// create base url i.e modelname
	containers := xmlquery.Find(filterNode, "./*") // get child node

	for _, modelContainer := range containers {

		glog.Infof("Parsing for model %s started", modelContainer.Data)

		// Single request
		mainPath := "/" + modelContainer.Data + ":" + modelContainer.Data //translib path building
		glog.Infof("Main path updated %s", mainPath)

		// inner containers
		innerContainers := xmlquery.Find(modelContainer, "./*")

		if len(innerContainers) == 0 {
			glog.Info("main container Children are zero, appending")
			queryPaths = append(queryPaths, GetRequest{path: mainPath, filters: []string{}})
			continue
		}

		// Handler inner container
		for _, innerContainer := range xmlquery.Find(modelContainer, "./*") {

			glog.Infof("Inner container %+v", innerContainer)
			if innerContainer == nil {
				queryPaths = append(queryPaths, GetRequest{path: mainPath, filters: []string{}})
				continue
			}

			path := mainPath + "/" + innerContainer.Data
			glog.Infof("Path updated %s", path)

			// Handle each "list" inside innerContainer
			children := xmlquery.Find(innerContainer, "./*")

			glog.Infof("child len %d", len(children))

			if len(children) == 0 {
				glog.Info("inner container Children are zero, appending")
				queryPaths = append(queryPaths, GetRequest{path: path, filters: []string{}})
				continue
			}

			for _, child := range children {

				glog.Info("Child parsing started %v", child)

				innerPath := path + "/" + child.Data
				glog.Infof("Path updated %s", innerPath)

				var keys []string

				if strings.Contains(innerPath, "sonic") {
					keys = netconf_codegen.SonicMap[innerPath]
					glog.Infof("Sonic path detected, using sonic keys %v", keys)
				} else {
					keys = netconf_codegen.CommonMap[innerPath]
					glog.Infof("Common path detected, using common keys %v", keys)
				}

				glog.Infof("Searching for keys and updating path")

				
				for _, key := range keys {
					keyNode := xmlquery.FindOne(child, "//*[local-name() = '"+key+"']")
					
					if keyNode != nil {
						glog.Infof("Keynode %s found %+v", key, keyNode)

						dataNode := xmlquery.FindOne(child, "//*[local-name() = '"+key+"']/text()")

						if dataNode != nil {
							innerPath += "[" + key + "=" + fmt.Sprintf("%v", strings.TrimSpace(dataNode.Data)) + "]"
							glog.Infof("Path updated %s", innerPath)
						}

						// else{
						// 	glog.Infof("Key [%s] data is empty, should be used as list filter", key)
						// 	listFilters = append(listFilters, key)
						// }
					}
				}


				listFilters := []string{}

				leafs := xmlquery.Find(child, "./*")

				for _, leaf := range leafs {
					dataNode := xmlquery.FindOne(child, "//*[local-name() = '"+leaf.Data+"']/text()")
					if dataNode == nil {
						glog.Infof("Empty leaf, should be used as list filter", leaf.Data)
						listFilters = append(listFilters, leaf.Data)
					}
				}

				glog.Infof("Filters for list %+s %+v", child.Data, listFilters)

				// if keysFound == 0 {
				// 	glog.Infof("List level request without any keys, returning entire list")
				// }

				queryPaths = append(queryPaths, GetRequest{path: innerPath, filters: listFilters})
			}

			glog.Infof("Parsing for model %s ended", modelContainer.Data)
		}

	}

	glog.Infof("Paths found in get request", queryPaths)

	return queryPaths, nil
} 

func ParseGetSchemaRequest(node *xmlquery.Node) (GetSchema, error) {
	identifier := xmlquery.FindOne(node, "//identifier/text()")
	format := xmlquery.FindOne(node, "//format/text()")
	version := xmlquery.FindOne(node, "//version/text()")

	s := GetSchema{}
	if identifier == nil {
		return s, errors.New("Identifier not passed")
	}

	s.Identifier = identifier.Data

	if format != nil {
		s.Format = format.Data
	}

	if version != nil {
		s.Version = version.Data
	}

	return s, nil
}

func ParseEditRequest(node *xmlquery.Node) ([]Config, error) {

	// get target
	targetNode := xmlquery.FindOne(node, "//*[local-name() = 'target']/*")
	if targetNode == nil {
		return []Config{}, errors.New("target store unsepecified")
	}

	if targetNode.Data != "running" {
		return []Config{}, errors.New("Target must be running config")
	}

	var configs []Config

	// Dispatch per top-level container: SONiC YANG uses the legacy 3-level extractors
	// (which depend on netconf_codegen.SonicMap key tables), OpenConfig and other
	// non-SONiC modules use the generic recursive parser that resolves the module
	// prefix from the XML namespace.
	configNode := xmlquery.FindOne(node, "//*[local-name() = 'config']")
	if configNode != nil {
		for _, modelContainer := range xmlquery.Find(configNode, "./*") {
			if !isSonicContainer(modelContainer) {
				configs = append(configs, parseEditConfigOC(modelContainer)...)
			}
		}
	}

	deleteRequest, err := extractAtomicRequestsByOpTag2(node, "delete")
	if err == nil {
		configs = append(configs, deleteRequest...)
	}

	removeRequest, err := extractAtomicRequestsByOpTag2(node, "remove")
	if err == nil {
		configs = append(configs, removeRequest...)
	}

	mergeRequest, err := extractTransactionalRequestByOpTag2(node, "merge")
	if err == nil {
		configs = append(configs, mergeRequest...)
	}

	replaceRequest, err := extractTransactionalRequestByOpTag3(node, "replace")
	if err == nil {
		configs = append(configs, replaceRequest...)
	}

	createRequest, err := extractTransactionalRequestByOpTag2(node, "create")
	if err == nil {
		configs = append(configs, createRequest...)
	}

	glog.Infof("configs %+v", configs)

	return configs, nil
}

// isSonicContainer reports whether the model container at the top of an edit-config
// payload targets a SONiC-YANG module. The decision controls dispatch in
// ParseEditRequest: SONiC containers fall through to the legacy 3-level extractors
// that consult netconf_codegen.SonicMap; everything else (OpenConfig, IETF YANG)
// goes through parseEditConfigOC.
func isSonicContainer(node *xmlquery.Node) bool {
	if strings.HasPrefix(node.Prefix, "sonic-") {
		return true
	}
	if node.Prefix == "" && strings.HasPrefix(node.Data, "sonic-") {
		return true
	}
	if ns := containerNamespace(node); ns != "" && strings.Contains(ns, "sonic") {
		return true
	}
	return false
}

// containerNamespace returns the XML namespace URI in effect for the given node,
// considering both an explicit `xmlns:<prefix>="..."` declaration and the inherited
// default `xmlns="..."`. It walks up the parent chain so containers nested under
// `<config>` still resolve to the namespace declared on the model container.
func containerNamespace(node *xmlquery.Node) string {
	target := node.Prefix
	for n := node; n != nil; n = n.Parent {
		for _, a := range n.Attr {
			if target == "" {
				if a.Name.Local == "xmlns" && (a.Name.Space == "" || a.Name.Space == "xmlns") {
					return a.Value
				}
			} else {
				if a.Name.Space == "xmlns" && a.Name.Local == target {
					return a.Value
				}
			}
		}
	}
	return ""
}

// resolveModulePrefix maps a node to its YANG module name. When the node carries
// an XML namespace prefix (e.g. `oc-if`), the prefix is honored verbatim; otherwise
// the inherited default namespace is looked up against YangModules.
func resolveModulePrefix(node *xmlquery.Node) string {
	if node.Prefix != "" {
		// Prefer the registered YANG module whose namespace matches the prefix
		// declaration; fall back to the prefix literal so user-provided shorthand
		// like `oc-if:interfaces` still produces a workable path.
		if ns := containerNamespace(node); ns != "" {
			if mod := yangModuleByNamespace(ns); mod != "" {
				return mod
			}
		}
		return node.Prefix
	}
	if ns := containerNamespace(node); ns != "" {
		return yangModuleByNamespace(ns)
	}
	return ""
}

func yangModuleByNamespace(ns string) string {
	for _, m := range YangModules.Modules {
		if m.Namespace != nil && *m.Namespace == ns && m.Name != nil {
			return *m.Name
		}
	}
	return ""
}

// parseEditConfigOC emits Config entries for a non-SONiC top-level container in an
// edit-config payload. The whole subtree is encoded as a single translib Set call:
//
//   - path      = "/{module}:{container}"
//   - operation = nc:operation attribute on the container (default "merge", RFC 6241)
//   - payload   = the BODY of the container — i.e. the JSON representation of its
//                 children, NOT wrapped under "{module}:{container}" again.
//
// translib walks the path to land at the target container, and then unmarshals
// the payload into that container's body. Wrapping the payload under the same
// "{module}:{container}" key produces translib errors of the form
// "JSON contains unexpected field {module}:{container}". An earlier version of
// this dispatcher and the legacy SONiC-YANG extractors emitted the wrapped
// form; live testing on a 2B'+ed25519 build (test/it/result/SUMMARY.md) showed
// both reject this shape.
//
// Per-leaf operations are not split out; clients that need fine-grained edits
// should send separate edit-config RPCs.
func parseEditConfigOC(modelContainer *xmlquery.Node) []Config {
	modulePrefix := resolveModulePrefix(modelContainer)
	if modulePrefix == "" {
		modulePrefix = modelContainer.Data
	}

	op := getOperation(modelContainer, "merge")
	payloadValue := buildEditPayload(modelContainer)

	// Config.payload is typed map[string]interface{}; buildEditPayload returns
	// a map for the common (containment) case. For a degenerate empty container
	// the helper returns the empty string from getInnerText(nil) — keep the
	// typed field happy with an empty map in that case.
	payload, ok := payloadValue.(map[string]interface{})
	if !ok {
		payload = map[string]interface{}{}
	}

	return []Config{{
		path:      "/" + modulePrefix + ":" + modelContainer.Data,
		operation: op,
		payload:   payload,
	}}
}

// buildEditPayload recursively converts an XML subtree into a JSON-shaped value.
// Children with identical tag names — and children that "look like" a YANG list
// entry — are emitted as JSON arrays per RFC 7951 §4.2.4. Leaves return their
// text value with the same scalar-conversion rules used by the legacy SONiC
// extractors (uint -> bool -> string fallback).
func buildEditPayload(node *xmlquery.Node) interface{} {
	children := xmlquery.Find(node, "./*")
	if len(children) == 0 {
		return getInnerText(xmlquery.FindOne(node, "text()"))
	}

	grouped := map[string][]*xmlquery.Node{}
	order := []string{}
	for _, c := range children {
		if _, seen := grouped[c.Data]; !seen {
			order = append(order, c.Data)
		}
		grouped[c.Data] = append(grouped[c.Data], c)
	}

	result := make(map[string]interface{})
	for _, name := range order {
		nodes := grouped[name]
		if len(nodes) > 1 || looksLikeListEntry(nodes[0]) {
			arr := make([]interface{}, 0, len(nodes))
			for _, n := range nodes {
				arr = append(arr, buildEditPayload(n))
			}
			result[name] = arr
			continue
		}
		result[name] = buildEditPayload(nodes[0])
	}
	return result
}

// looksLikeListEntry returns true for an XML element that the YANG schema is
// (very likely) treating as a list entry. The heuristic identifies the
// canonical OpenConfig / IETF shape: a list entry typically has BOTH a
// content-match child (the key leaf, e.g. <name>Ethernet0</name>) AND at least
// one nested container child (e.g. <config>...</config>). Pure container nodes
// (`<config>`, `<state>`, etc.) only have content-match leaf children with no
// further containment, and so are NOT mistaken for list entries.
//
// translib's RFC 7951 unmarshaller requires every YANG list value to be a JSON
// array even when only one entry is present. Without this wrapping it rejects
// the payload with
//
//	unmarshalList for schema X: jsonList ... (map): got type map[string]interface{},
//	expect []interface{}
//
// observed during live IT against a 2B'+ed25519+unwrap build.
func looksLikeListEntry(node *xmlquery.Node) bool {
	hasContentMatch := false
	hasContainerChild := false
	for _, c := range xmlquery.Find(node, "./*") {
		if isContentMatchNode(c) {
			hasContentMatch = true
		} else if isContainmentNode(c) {
			hasContainerChild = true
		}
	}
	return hasContentMatch && hasContainerChild
}

func ParseRPCRequest(node *xmlquery.Node) ([]RPCRequest, error) {

	var requests []RPCRequest

	for _, rpcContainer := range xmlquery.Find(node, "//*[local-name() = 'sonic-rpc']/*") {

		rpc := strings.TrimSpace(rpcContainer.Data)
		payload := make(map[string]interface{})

		for _, leaf := range xmlquery.Find(rpcContainer, "./*") {

			leafTag := strings.TrimSpace(leaf.Data)
			leafTextNode := xmlquery.FindOne(leaf, "text()")
			leafText := getInnerText(leafTextNode)

			payload[leafTag] = leafText
		}

		formattedPayload := make(map[string]interface{})
		formattedPayload["sonic-rpc:input"] = payload

		rpcRequest := RPCRequest{
			path:    "/sonic-rpc:" + rpc,
			payload: formattedPayload,
		}

		requests = append(requests, rpcRequest)
	}

	return requests, nil
}

func extractTransactionalRequestByOpTag2(node *xmlquery.Node, opTag string) ([]Config, error) {

	var configs []Config

	containers := xmlquery.Find(node, "//*[local-name() = 'config']/*")

	for _, modelContainer := range containers {

		if !isSonicContainer(modelContainer) {
			continue
		}

		var config Config
		config.operation = opTag
		config.payload = make(map[string]interface{})

		config.path = "/" + modelContainer.Data + ":" + modelContainer.Data //translib path building

		// Handle inner container
		for _, innerContainer := range xmlquery.Find(modelContainer, "./*") {

			// Handle outer container
			innerContainerPayload := make(map[string][]interface{})

			// Handle each "list" inside innerContainer
			lists := xmlquery.Find(innerContainer, "./*")

			for _, list := range lists {

				listOp := getOperation(list, "merge")


				listPath := config.path + "/" + innerContainer.Data + "/" + list.Data
				var leafListSet map[string]bool
				if strings.Contains(listPath, "sonic") {
					leafListSet = netconf_codegen.SonicLeafListFields[listPath]
				} else {
					leafListSet = netconf_codegen.CommonLeafListFields[listPath]
				}

				// Check leafs for atomic operations
				leafs := xmlquery.Find(list, "./*")

				listItemData := make(map[string]interface{})

				for _, leaf := range leafs {

					leafTextNode := xmlquery.FindOne(leaf, "text()")
					leafText := getInnerText(leafTextNode)
					leafTag := strings.TrimSpace(leaf.Data)

					leafOp := getOperation(leaf, "n/a")
					if leafOp == "n/a" {
						leafOp = listOp
					}

					if leafOp != opTag {
						continue
					}

					// quotes means we want this leaf to be a string
					str, ok := leafText.(string)
					if ok && strings.Contains(str, "\"") {
						leafText, _ = strconv.Unquote(str)
					}


					if leafListSet[leafTag] {
						if existing, exists := listItemData[leafTag]; exists {
							listItemData[leafTag] = append(existing.([]interface{}), leafText)
						} else {
							listItemData[leafTag] = []interface{}{leafText}
						}
					} else {
						listItemData[leafTag] = leafText
					}
				}

				if len(listItemData) != 0 {
					innerContainerPayload[list.Data] = append(innerContainerPayload[list.Data], listItemData)
				}
			}

			if len(innerContainerPayload) != 0 {
				config.payload[modelContainer.Data+":"+innerContainer.Data] = innerContainerPayload
			}
		}

		if len(config.payload) != 0 {
			configs = append(configs, config)
		}
	}

	return configs, nil
}

func extractTransactionalRequestByOpTag3(node *xmlquery.Node, opTag string) ([]Config, error) {

	var configs []Config

	containers := xmlquery.Find(node, "//*[local-name() = 'config']/*")

	for _, modelContainer := range containers {

		if !isSonicContainer(modelContainer) {
			continue
		}

		var config Config
		config.operation = opTag
		config.payload = make(map[string]interface{})

		config.path = "/" + modelContainer.Data + ":" + modelContainer.Data //translib path building

		// Handle inner container
		for _, innerContainer := range xmlquery.Find(modelContainer, "./*") {
	
			// Handle outer container
			innerContainerPayload := make(map[string][]interface{})

			// Handle each "list" inside innerContainer
			lists := xmlquery.Find(innerContainer, "./*")

			for _, list := range lists {

				listOp := getOperation(list, "merge")

				
				listPath := config.path + "/" + innerContainer.Data + "/" + list.Data
				var leafListSet map[string]bool
				if strings.Contains(listPath, "sonic") {
					leafListSet = netconf_codegen.SonicLeafListFields[listPath]
				} else {
					leafListSet = netconf_codegen.CommonLeafListFields[listPath]
				}

				// Check leafs for atomic operations
				leafs := xmlquery.Find(list, "./*")

				listItemData := make(map[string]interface{})

				for _, leaf := range leafs {

					leafTextNode := xmlquery.FindOne(leaf, "text()")
					leafText := getInnerText(leafTextNode)
					leafTag := strings.TrimSpace(leaf.Data)

					leafOp := getOperation(leaf, "n/a")
					if leafOp == "n/a" {
						leafOp = listOp
					}

					if leafOp != opTag {
						continue
					}

					// quotes means we want this leaf to be a string
					str, ok := leafText.(string)
					if ok && strings.Contains(str, "\"") {
						leafText, _ = strconv.Unquote(str)
					}

					
					if leafListSet[leafTag] {
						if existing, exists := listItemData[leafTag]; exists {
							listItemData[leafTag] = append(existing.([]interface{}), leafText)
						} else {
							listItemData[leafTag] = []interface{}{leafText}
						}
					} else {
						listItemData[leafTag] = leafText
					}
				}

				if len(listItemData) != 0 {
					innerContainerPayload[list.Data] = append(innerContainerPayload[list.Data], listItemData)
				}
			}

			if len(innerContainerPayload) != 0 {
				config.payload[modelContainer.Data+":"+modelContainer.Data] = make(map[string]interface{})
				config.payload[modelContainer.Data+":"+modelContainer.Data].(map[string]interface{})[innerContainer.Data] = innerContainerPayload
			}
		}

		if len(config.payload) != 0 {
			configs = append(configs, config)
		}
	}

	return configs, nil
}

func extractAtomicRequestsByOpTag2(node *xmlquery.Node, opTag string) ([]Config, error) {

	containers := xmlquery.Find(node, "//*[local-name() = 'config']/*")

	var configs []Config

	for _, modelContainer := range containers {

		if !isSonicContainer(modelContainer) {
			continue
		}

		// Handle outer container
		basePath := "/" + modelContainer.Data + ":" + modelContainer.Data //translib path building

		// Handler inner containers
		for _, innerContainer := range xmlquery.Find(modelContainer, "./*") {

			if innerContainer == nil {
				continue
			}

			path := basePath + "/" + innerContainer.Data

			// Handle each "list" inside innerContainer
			lists := xmlquery.Find(innerContainer, "./*")

			for _, list := range lists {

				innerPath := path + "/" + list.Data
				listOp := getOperation(list, "merge")

				var keys []string

				if strings.Contains(innerPath, "sonic") {
					keys = netconf_codegen.SonicMap[innerPath]
				} else {
					keys = netconf_codegen.CommonMap[innerPath]
				}

				// update path with keys for list
				for _, key := range keys {
					keyNode := xmlquery.FindOne(list, "//*[local-name() = '"+key+"']/text()")
					if keyNode != nil {
						innerPath += "[" + key + "=" + fmt.Sprintf("%v", strings.TrimSpace(keyNode.Data)) + "]"
					}
				}

				if listOp == opTag {
					// Append update list for keys
					var leafConfig Config
					leafConfig.operation = listOp
					leafConfig.path = innerPath
					leafConfig.payload = make(map[string]interface{})
					leafConfig.keys = len(keys)
					configs = append(configs, leafConfig)
				}

				// Check leafs for atomic operations
				leafs := xmlquery.Find(list, "./*")

				for _, leaf := range leafs {

					leafTag := strings.TrimSpace(leaf.Data)
					leafPath := innerPath + "/" + leafTag

					leafTextNode := xmlquery.FindOne(leaf, "text()")
					leafText := getInnerText(leafTextNode)

					isKey := false

					// Check if leaf is key to not skip its config
					for _, key := range keys {
						if key == leafTag {
							isKey = true
						}
					}

					if isKey {
						continue
					}

					leafOp := getOperation(leaf, "n/a")
					if leafOp == "n/a" {
						leafOp = listOp
					}

					if leafOp != opTag {
						continue
					}

					var leafConfig Config
					leafConfig.operation = opTag
					leafConfig.path = leafPath
					leafConfig.payload = make(map[string]interface{})
					leafConfig.payload[modelContainer.Data+":"+leafTag] = leafText
					leafConfig.keys = len(keys)
					configs = append(configs, leafConfig)
				}
			}
		}
	}

	sort.Slice(configs, func(i, j int) bool {
		return configs[i].keys > configs[j].keys
	})

	return configs, nil
}

func getOperation(node *xmlquery.Node, defaultVal string) string {

	for _, s := range node.Attr {
		if s.Name.Local == "operation" {
			return s.Value
		}
	}

	return defaultVal
}

func getInnerText(node *xmlquery.Node) interface{} {

	if node != nil {

		val := strings.TrimSpace(node.Data)

		// No conversion
		if node.Parent.SelectAttr("conversion") == "none" {
			return val
		}

		// try converting to float
		float, err := strconv.ParseUint(val, 10, 64)
		if err == nil {
			return float
		}

		// try boolean conversion
		boolean, err := strconv.ParseBool(val)
		if err == nil {
			return boolean
		}

		return val
	}

	return ""
}

func appendParamsToPath(path string, params map[string]interface{}, appendAll bool) string {

	if appendAll {
		for k, val := range params {
			path += "/[" + k + "=" + fmt.Sprintf("%v", val) + "]"
		}
		return path
	}

	var keys []string

	if strings.Contains(path, "sonic") {
		keys = netconf_codegen.SonicMap[path]
	} else {
		keys = netconf_codegen.CommonMap[path]
	}

	for _, key := range keys {
		if val, ok := params[key]; ok {
			path += "[" + key + "=" + fmt.Sprintf("%v", val) + "]"
		} else {
			panic("key for path not given")
		}
	}

	return path
}

func buildPath(node *xmlquery.Node, path string) string {

	if node == nil {
		return path
	}

	textNode := xmlquery.FindOne(node, "text()")

	if textNode == nil || strings.TrimSpace(textNode.Data) == "" {
		path += "/" + node.Data
	}

	return buildPath(xmlquery.FindOne(node, "./*"), path)
}

func getParameters(node *xmlquery.Node) map[string]interface{} {
	return _getParameters(node, make(map[string]interface{}))
}

func _getParameters(node *xmlquery.Node, params map[string]interface{}) map[string]interface{} {

	if node == nil {
		return params
	}

	children := xmlquery.Find(node, "./*")

	for _, c := range children {

		textChildren := xmlquery.Find(c, "text()")

		for _, tc := range textChildren {

			if strings.TrimSpace(tc.Data) == "" {
				continue
			}

			val := strings.TrimSpace(tc.Data)

			if tc.Parent.SelectAttr("conversion") == "none" {
				params[c.Data] = val
				continue
			}

			// try converting to float
			float, err := strconv.ParseFloat(val, 64)
			if err == nil {
				params[c.Data] = float
				continue
			}

			// try boolean conversion
			boolean, err := strconv.ParseBool(val)
			if err == nil {
				params[c.Data] = boolean
				continue
			}

			params[c.Data] = val
		}

	}

	return _getParameters(xmlquery.FindOne(node, "./*"), params)
}
