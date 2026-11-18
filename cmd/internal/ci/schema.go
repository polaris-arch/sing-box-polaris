package main

import (
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateDocument(filename, fragment string, document any) error {
	input, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer input.Close()
	schema, err := jsonschema.UnmarshalJSON(input)
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(jsonschema.SchemeURLLoader{})

	const resource = "urn:polaris:ci-schema"
	if err := compiler.AddResource(resource, schema); err != nil {
		return err
	}
	compiled, err := compiler.Compile(resource + fragment)
	if err != nil {
		return err
	}
	return compiled.Validate(document)
}
