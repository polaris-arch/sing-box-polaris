package daemon

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestRuntimeImpactPolicyGeneratedFieldsUseAdditiveDescriptorAndWire(t *testing.T) {
	for _, test := range []struct {
		message  proto.Message
		number   protoreflect.FieldNumber
		name     protoreflect.Name
		kind     protoreflect.Kind
		repeated bool
	}{
		{&PlanRuntimeConfigRequest{ClientImpactPolicyVersion: 1}, 7, "client_impact_policy_version", protoreflect.Uint32Kind, false},
		{&RuntimeConfigPlan{ClientImpactPolicyVersion: 1, ImpactConfirmationRequired: true}, 14, "client_impact_policy_version", protoreflect.Uint32Kind, false},
		{&RuntimeConfigPlan{ClientImpactPolicyVersion: 1, ImpactConfirmationRequired: true}, 15, "impact_confirmation_required", protoreflect.BoolKind, false},
		{&RuntimeCapabilities{SupportedClientImpactPolicyVersions: []uint32{1}}, 11, "supported_client_impact_policy_versions", protoreflect.Uint32Kind, true},
	} {
		field := test.message.ProtoReflect().Descriptor().Fields().ByNumber(test.number)
		if field == nil || field.Name() != test.name || field.Kind() != test.kind || field.IsList() != test.repeated || (test.repeated && !field.IsPacked()) {
			t.Fatalf("generated descriptor does not match the public field: %v", field)
		}
		wire, err := proto.Marshal(test.message)
		if err != nil {
			t.Fatal(err)
		}
		decoded := test.message.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(wire, decoded); err != nil || !proto.Equal(test.message, decoded) {
			t.Fatalf("generated binary field lost its value: %v", err)
		}
		content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(test.message)
		if err != nil {
			t.Fatal(err)
		}
		proto.Reset(decoded)
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, decoded); err != nil || !proto.Equal(test.message, decoded) {
			t.Fatalf("generated JSON field lost its value: %v", err)
		}
	}
	service := File_daemon_runtime_config_proto.Services().ByName("RuntimeConfigService")
	if service == nil || service.Methods().Len() != 6 {
		t.Fatal("consumer protocol changed the RPC surface")
	}
	if fields := (&ApplyRuntimeConfigRequest{}).ProtoReflect().Descriptor().Fields(); fields.Len() != 7 || fields.ByName("client_impact_policy_version") != nil {
		t.Fatal("consumer capability must not replace the original Apply acknowledgement")
	}
}

func TestRuntimeImpactPolicyLegacyBinaryAndStrictJSONHaveDifferentCompatibility(t *testing.T) {
	legacyFile := protodesc.ToFileDescriptorProto(File_daemon_runtime_config_proto)
	for _, message := range legacyFile.MessageType {
		fields := message.Field[:0]
		for _, field := range message.Field {
			if field.GetName() != "client_impact_policy_version" && field.GetName() != "impact_confirmation_required" && field.GetName() != "supported_client_impact_policy_versions" {
				fields = append(fields, field)
			}
		}
		message.Field = fields
	}
	legacy, err := protodesc.NewFile(legacyFile, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	requestDescriptor := legacy.Messages().ByName("PlanRuntimeConfigRequest")
	original := &PlanRuntimeConfigRequest{ContractVersion: 1, ClientImpactPolicyVersion: 1}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest := dynamicpb.NewMessage(requestDescriptor)
	if err := proto.Unmarshal(wire, oldRequest); err != nil || len(oldRequest.GetUnknown()) == 0 {
		t.Fatal("legacy binary parser did not retain additive unknown data")
	}
	forwarded, err := proto.Marshal(oldRequest)
	if err != nil {
		t.Fatal(err)
	}
	var restored PlanRuntimeConfigRequest
	if err := proto.Unmarshal(forwarded, &restored); err != nil || !proto.Equal(original, &restored) {
		t.Fatal("legacy binary forwarding changed the additive field")
	}
	strict := protojson.UnmarshalOptions{DiscardUnknown: false}
	for _, input := range []string{
		`{"contract_version":1,"client_impact_policy_version":1}`,
		`{"contract_version":1,"client_impact_policy_version":0}`,
	} {
		if err := strict.Unmarshal([]byte(input), dynamicpb.NewMessage(requestDescriptor)); err == nil {
			t.Fatal("legacy strict JSON accepted an unknown field; the App must omit it before negotiation")
		}
	}
	if err := strict.Unmarshal([]byte(`{"contract_version":1}`), dynamicpb.NewMessage(requestDescriptor)); err != nil {
		t.Fatalf("omitted consumer policy broke legacy strict JSON: %v", err)
	}
}
