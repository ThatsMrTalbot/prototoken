// Code generated by protoc-gen-go.
// source: token.proto
// DO NOT EDIT!

/*
Package prototoken is a generated protocol buffer package.

It is generated from these files:
	token.proto

It has these top-level messages:
	Token
*/
package prototoken

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/any"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Token struct {
	Value     *google_protobuf.Any `protobuf:"bytes,1,opt,name=Value,json=value" json:"Value,omitempty"`
	Signature []byte               `protobuf:"bytes,2,opt,name=Signature,json=signature,proto3" json:"Signature,omitempty"`
}

func (m *Token) Reset()                    { *m = Token{} }
func (m *Token) String() string            { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()               {}
func (*Token) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Token) GetValue() *google_protobuf.Any {
	if m != nil {
		return m.Value
	}
	return nil
}

func init() {
	proto.RegisterType((*Token)(nil), "prototoken.Token")
}

var fileDescriptor0 = []byte{
	// 129 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x2e, 0xc9, 0xcf, 0x4e,
	0xcd, 0xd3, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x02, 0x53, 0x60, 0x11, 0x29, 0xc9, 0xf4,
	0xfc, 0xfc, 0xf4, 0x9c, 0x54, 0x7d, 0xb0, 0x50, 0x52, 0x69, 0x9a, 0x7e, 0x62, 0x5e, 0x25, 0x44,
	0x99, 0x52, 0x20, 0x17, 0x6b, 0x08, 0x48, 0x8d, 0x90, 0x16, 0x17, 0x6b, 0x58, 0x62, 0x4e, 0x69,
	0xaa, 0x04, 0xa3, 0x02, 0xa3, 0x06, 0xb7, 0x91, 0x88, 0x1e, 0x44, 0x8f, 0x1e, 0x4c, 0x8f, 0x9e,
	0x63, 0x5e, 0x65, 0x10, 0x6b, 0x19, 0x48, 0x89, 0x90, 0x0c, 0x17, 0x67, 0x70, 0x66, 0x7a, 0x5e,
	0x62, 0x49, 0x69, 0x51, 0xaa, 0x04, 0x13, 0x50, 0x3d, 0x4f, 0x10, 0x67, 0x31, 0x4c, 0x20, 0x89,
	0x0d, 0xac, 0xc5, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0xf8, 0xd7, 0x86, 0x6e, 0x8f, 0x00, 0x00,
	0x00,
}
