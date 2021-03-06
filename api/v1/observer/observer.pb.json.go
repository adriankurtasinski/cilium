// Code generated by protoc-gen-go-json. DO NOT EDIT.
// source: observer/observer.proto

package observer

import (
	"bytes"

	"github.com/golang/protobuf/jsonpb"
)

// MarshalJSON implements json.Marshaler
func (msg *ServerStatusRequest) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := (&jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		OrigName:     true,
	}).Marshal(&buf, msg)
	return buf.Bytes(), err
}

// UnmarshalJSON implements json.Unmarshaler
func (msg *ServerStatusRequest) UnmarshalJSON(b []byte) error {
	return (&jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}).Unmarshal(bytes.NewReader(b), msg)
}

// MarshalJSON implements json.Marshaler
func (msg *ServerStatusResponse) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := (&jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		OrigName:     true,
	}).Marshal(&buf, msg)
	return buf.Bytes(), err
}

// UnmarshalJSON implements json.Unmarshaler
func (msg *ServerStatusResponse) UnmarshalJSON(b []byte) error {
	return (&jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}).Unmarshal(bytes.NewReader(b), msg)
}

// MarshalJSON implements json.Marshaler
func (msg *GetFlowsRequest) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := (&jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		OrigName:     true,
	}).Marshal(&buf, msg)
	return buf.Bytes(), err
}

// UnmarshalJSON implements json.Unmarshaler
func (msg *GetFlowsRequest) UnmarshalJSON(b []byte) error {
	return (&jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}).Unmarshal(bytes.NewReader(b), msg)
}

// MarshalJSON implements json.Marshaler
func (msg *GetFlowsResponse) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := (&jsonpb.Marshaler{
		EnumsAsInts:  false,
		EmitDefaults: false,
		OrigName:     true,
	}).Marshal(&buf, msg)
	return buf.Bytes(), err
}

// UnmarshalJSON implements json.Unmarshaler
func (msg *GetFlowsResponse) UnmarshalJSON(b []byte) error {
	return (&jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}).Unmarshal(bytes.NewReader(b), msg)
}
