module github.com/qoryai/qory-github

go 1.27.1

require (
	github.com/qoryai/integrations v0.1.0
	github.com/qoryai/runner v0.6.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	golang.org/x/text v0.14.0
	gopkg.in/yaml.v3 v3.0.1
)

// Until qoryai/integrations v0.1.0 is tagged, the module is read from its checkout beside
// this one. Remove this line once the tag exists.
replace github.com/qoryai/integrations => ../../integrations/main
