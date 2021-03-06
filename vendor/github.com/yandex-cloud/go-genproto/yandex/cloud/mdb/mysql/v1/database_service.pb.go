// Code generated by protoc-gen-go. DO NOT EDIT.
// source: yandex/cloud/mdb/mysql/v1/database_service.proto

package mysql

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/yandex-cloud/go-genproto/yandex/cloud"
	_ "github.com/yandex-cloud/go-genproto/yandex/cloud/api"
	operation "github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type GetDatabaseRequest struct {
	// ID of the MySQL cluster that the database belongs to.
	// To get the cluster ID use a [ClusterService.List] request.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// Name of the MySQL database to return.
	// To get the name of the database use a [DatabaseService.List] request.
	DatabaseName         string   `protobuf:"bytes,2,opt,name=database_name,json=databaseName,proto3" json:"database_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetDatabaseRequest) Reset()         { *m = GetDatabaseRequest{} }
func (m *GetDatabaseRequest) String() string { return proto.CompactTextString(m) }
func (*GetDatabaseRequest) ProtoMessage()    {}
func (*GetDatabaseRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{0}
}

func (m *GetDatabaseRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetDatabaseRequest.Unmarshal(m, b)
}
func (m *GetDatabaseRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetDatabaseRequest.Marshal(b, m, deterministic)
}
func (m *GetDatabaseRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetDatabaseRequest.Merge(m, src)
}
func (m *GetDatabaseRequest) XXX_Size() int {
	return xxx_messageInfo_GetDatabaseRequest.Size(m)
}
func (m *GetDatabaseRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetDatabaseRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetDatabaseRequest proto.InternalMessageInfo

func (m *GetDatabaseRequest) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *GetDatabaseRequest) GetDatabaseName() string {
	if m != nil {
		return m.DatabaseName
	}
	return ""
}

type ListDatabasesRequest struct {
	// ID of the MySQL cluster to list databases in.
	// To get the cluster ID use a [ClusterService.List] request.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// The maximum number of results per page to return. If the number of available
	// results is larger than [page_size], the service returns a [ListDatabasesResponse.next_page_token]
	// that can be used to get the next page of results in subsequent list requests.
	PageSize int64 `protobuf:"varint,2,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	// Page token. To get the next page of results, Set [page_token] to the [ListDatabasesResponse.next_page_token]
	// returned by a previous list request.
	PageToken            string   `protobuf:"bytes,3,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListDatabasesRequest) Reset()         { *m = ListDatabasesRequest{} }
func (m *ListDatabasesRequest) String() string { return proto.CompactTextString(m) }
func (*ListDatabasesRequest) ProtoMessage()    {}
func (*ListDatabasesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{1}
}

func (m *ListDatabasesRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListDatabasesRequest.Unmarshal(m, b)
}
func (m *ListDatabasesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListDatabasesRequest.Marshal(b, m, deterministic)
}
func (m *ListDatabasesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListDatabasesRequest.Merge(m, src)
}
func (m *ListDatabasesRequest) XXX_Size() int {
	return xxx_messageInfo_ListDatabasesRequest.Size(m)
}
func (m *ListDatabasesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListDatabasesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListDatabasesRequest proto.InternalMessageInfo

func (m *ListDatabasesRequest) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *ListDatabasesRequest) GetPageSize() int64 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListDatabasesRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

type ListDatabasesResponse struct {
	// List of MySQL databases.
	Databases []*Database `protobuf:"bytes,1,rep,name=databases,proto3" json:"databases,omitempty"`
	// This token allows you to get the next page of results for list requests. If the number of results
	// is larger than [ListDatabasesRequest.page_size], use the [next_page_token] as the value
	// for the [ListDatabasesRequest.page_token] parameter in the next list request. Each subsequent
	// list request will have its own [next_page_token] to continue paging through the results.
	NextPageToken        string   `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListDatabasesResponse) Reset()         { *m = ListDatabasesResponse{} }
func (m *ListDatabasesResponse) String() string { return proto.CompactTextString(m) }
func (*ListDatabasesResponse) ProtoMessage()    {}
func (*ListDatabasesResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{2}
}

func (m *ListDatabasesResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListDatabasesResponse.Unmarshal(m, b)
}
func (m *ListDatabasesResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListDatabasesResponse.Marshal(b, m, deterministic)
}
func (m *ListDatabasesResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListDatabasesResponse.Merge(m, src)
}
func (m *ListDatabasesResponse) XXX_Size() int {
	return xxx_messageInfo_ListDatabasesResponse.Size(m)
}
func (m *ListDatabasesResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListDatabasesResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListDatabasesResponse proto.InternalMessageInfo

func (m *ListDatabasesResponse) GetDatabases() []*Database {
	if m != nil {
		return m.Databases
	}
	return nil
}

func (m *ListDatabasesResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

type CreateDatabaseRequest struct {
	// ID of the MySQL cluster to create a database in.
	// To get the cluster ID use a [ClusterService.List] request.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// Configuration of the database to create.
	DatabaseSpec         *DatabaseSpec `protobuf:"bytes,2,opt,name=database_spec,json=databaseSpec,proto3" json:"database_spec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *CreateDatabaseRequest) Reset()         { *m = CreateDatabaseRequest{} }
func (m *CreateDatabaseRequest) String() string { return proto.CompactTextString(m) }
func (*CreateDatabaseRequest) ProtoMessage()    {}
func (*CreateDatabaseRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{3}
}

func (m *CreateDatabaseRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateDatabaseRequest.Unmarshal(m, b)
}
func (m *CreateDatabaseRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateDatabaseRequest.Marshal(b, m, deterministic)
}
func (m *CreateDatabaseRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateDatabaseRequest.Merge(m, src)
}
func (m *CreateDatabaseRequest) XXX_Size() int {
	return xxx_messageInfo_CreateDatabaseRequest.Size(m)
}
func (m *CreateDatabaseRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateDatabaseRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateDatabaseRequest proto.InternalMessageInfo

func (m *CreateDatabaseRequest) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *CreateDatabaseRequest) GetDatabaseSpec() *DatabaseSpec {
	if m != nil {
		return m.DatabaseSpec
	}
	return nil
}

type CreateDatabaseMetadata struct {
	// ID of the MySQL cluster where a database is being created.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// Name of the MySQL database that is being created.
	DatabaseName         string   `protobuf:"bytes,2,opt,name=database_name,json=databaseName,proto3" json:"database_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateDatabaseMetadata) Reset()         { *m = CreateDatabaseMetadata{} }
func (m *CreateDatabaseMetadata) String() string { return proto.CompactTextString(m) }
func (*CreateDatabaseMetadata) ProtoMessage()    {}
func (*CreateDatabaseMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{4}
}

func (m *CreateDatabaseMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CreateDatabaseMetadata.Unmarshal(m, b)
}
func (m *CreateDatabaseMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CreateDatabaseMetadata.Marshal(b, m, deterministic)
}
func (m *CreateDatabaseMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateDatabaseMetadata.Merge(m, src)
}
func (m *CreateDatabaseMetadata) XXX_Size() int {
	return xxx_messageInfo_CreateDatabaseMetadata.Size(m)
}
func (m *CreateDatabaseMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateDatabaseMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_CreateDatabaseMetadata proto.InternalMessageInfo

func (m *CreateDatabaseMetadata) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *CreateDatabaseMetadata) GetDatabaseName() string {
	if m != nil {
		return m.DatabaseName
	}
	return ""
}

type DeleteDatabaseRequest struct {
	// ID of the MySQL cluster to delete a database in.
	// To get the cluster ID, use a [ClusterService.List] request.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// Name of the database to delete.
	// To get the name of the database, use a [DatabaseService.List] request.
	DatabaseName         string   `protobuf:"bytes,2,opt,name=database_name,json=databaseName,proto3" json:"database_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteDatabaseRequest) Reset()         { *m = DeleteDatabaseRequest{} }
func (m *DeleteDatabaseRequest) String() string { return proto.CompactTextString(m) }
func (*DeleteDatabaseRequest) ProtoMessage()    {}
func (*DeleteDatabaseRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{5}
}

func (m *DeleteDatabaseRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteDatabaseRequest.Unmarshal(m, b)
}
func (m *DeleteDatabaseRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteDatabaseRequest.Marshal(b, m, deterministic)
}
func (m *DeleteDatabaseRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteDatabaseRequest.Merge(m, src)
}
func (m *DeleteDatabaseRequest) XXX_Size() int {
	return xxx_messageInfo_DeleteDatabaseRequest.Size(m)
}
func (m *DeleteDatabaseRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteDatabaseRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteDatabaseRequest proto.InternalMessageInfo

func (m *DeleteDatabaseRequest) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *DeleteDatabaseRequest) GetDatabaseName() string {
	if m != nil {
		return m.DatabaseName
	}
	return ""
}

type DeleteDatabaseMetadata struct {
	// ID of the MySQL cluster where a database is being deleted.
	ClusterId string `protobuf:"bytes,1,opt,name=cluster_id,json=clusterId,proto3" json:"cluster_id,omitempty"`
	// Name of the MySQL database that is being deleted.
	DatabaseName         string   `protobuf:"bytes,2,opt,name=database_name,json=databaseName,proto3" json:"database_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteDatabaseMetadata) Reset()         { *m = DeleteDatabaseMetadata{} }
func (m *DeleteDatabaseMetadata) String() string { return proto.CompactTextString(m) }
func (*DeleteDatabaseMetadata) ProtoMessage()    {}
func (*DeleteDatabaseMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_2a4229dfcf64927d, []int{6}
}

func (m *DeleteDatabaseMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteDatabaseMetadata.Unmarshal(m, b)
}
func (m *DeleteDatabaseMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteDatabaseMetadata.Marshal(b, m, deterministic)
}
func (m *DeleteDatabaseMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteDatabaseMetadata.Merge(m, src)
}
func (m *DeleteDatabaseMetadata) XXX_Size() int {
	return xxx_messageInfo_DeleteDatabaseMetadata.Size(m)
}
func (m *DeleteDatabaseMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteDatabaseMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteDatabaseMetadata proto.InternalMessageInfo

func (m *DeleteDatabaseMetadata) GetClusterId() string {
	if m != nil {
		return m.ClusterId
	}
	return ""
}

func (m *DeleteDatabaseMetadata) GetDatabaseName() string {
	if m != nil {
		return m.DatabaseName
	}
	return ""
}

func init() {
	proto.RegisterType((*GetDatabaseRequest)(nil), "yandex.cloud.mdb.mysql.v1.GetDatabaseRequest")
	proto.RegisterType((*ListDatabasesRequest)(nil), "yandex.cloud.mdb.mysql.v1.ListDatabasesRequest")
	proto.RegisterType((*ListDatabasesResponse)(nil), "yandex.cloud.mdb.mysql.v1.ListDatabasesResponse")
	proto.RegisterType((*CreateDatabaseRequest)(nil), "yandex.cloud.mdb.mysql.v1.CreateDatabaseRequest")
	proto.RegisterType((*CreateDatabaseMetadata)(nil), "yandex.cloud.mdb.mysql.v1.CreateDatabaseMetadata")
	proto.RegisterType((*DeleteDatabaseRequest)(nil), "yandex.cloud.mdb.mysql.v1.DeleteDatabaseRequest")
	proto.RegisterType((*DeleteDatabaseMetadata)(nil), "yandex.cloud.mdb.mysql.v1.DeleteDatabaseMetadata")
}

func init() {
	proto.RegisterFile("yandex/cloud/mdb/mysql/v1/database_service.proto", fileDescriptor_2a4229dfcf64927d)
}

var fileDescriptor_2a4229dfcf64927d = []byte{
	// 701 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0x4d, 0x4f, 0x13, 0x4f,
	0x1c, 0xce, 0x52, 0xfe, 0x0d, 0x1d, 0xe0, 0x4f, 0x32, 0xb1, 0xa4, 0x36, 0x62, 0x70, 0x49, 0xa0,
	0xa9, 0xd9, 0x9d, 0x5d, 0x88, 0x24, 0x28, 0x1c, 0x68, 0x31, 0x84, 0xc4, 0xb7, 0x2c, 0x9e, 0x10,
	0xd3, 0xcc, 0x76, 0xc7, 0x75, 0x63, 0xf7, 0x85, 0xce, 0xb4, 0xe1, 0x45, 0x0e, 0x72, 0x30, 0x91,
	0xab, 0x89, 0xf1, 0x03, 0xf8, 0x09, 0xf8, 0x06, 0x9e, 0xe0, 0x8c, 0x47, 0xaf, 0x1e, 0x3c, 0x7b,
	0xf4, 0x64, 0x76, 0xa6, 0xdd, 0x76, 0xa1, 0xad, 0xc5, 0x72, 0x9b, 0xcc, 0xef, 0x79, 0x66, 0x9e,
	0x67, 0xe6, 0xf9, 0xcd, 0x00, 0x6d, 0x0f, 0x7b, 0x16, 0xd9, 0x45, 0xe5, 0x8a, 0x5f, 0xb3, 0x90,
	0x6b, 0x99, 0xc8, 0xdd, 0xa3, 0x3b, 0x15, 0x54, 0xd7, 0x91, 0x85, 0x19, 0x36, 0x31, 0x25, 0x25,
	0x4a, 0xaa, 0x75, 0xa7, 0x4c, 0xd4, 0xa0, 0xea, 0x33, 0x1f, 0xde, 0x14, 0x0c, 0x95, 0x33, 0x54,
	0xd7, 0x32, 0x55, 0xce, 0x50, 0xeb, 0x7a, 0xf6, 0x96, 0xed, 0xfb, 0x76, 0x85, 0x20, 0x1c, 0x38,
	0x08, 0x7b, 0x9e, 0xcf, 0x30, 0x73, 0x7c, 0x8f, 0x0a, 0x62, 0x76, 0x3a, 0xb6, 0x55, 0x88, 0xf1,
	0x03, 0x52, 0xe5, 0x90, 0x06, 0x62, 0x36, 0x86, 0x88, 0xaa, 0x97, 0x70, 0x53, 0x31, 0x5c, 0x1d,
	0x57, 0x1c, 0xab, 0xbd, 0x9c, 0xfb, 0xbb, 0x27, 0x81, 0x94, 0xdf, 0x4b, 0x00, 0xae, 0x13, 0xb6,
	0xd6, 0x98, 0x35, 0xc8, 0x4e, 0x8d, 0x50, 0x06, 0xef, 0x02, 0x50, 0xae, 0xd4, 0x28, 0x23, 0xd5,
	0x92, 0x63, 0x65, 0xa4, 0x69, 0x29, 0x97, 0x2a, 0x8c, 0xfd, 0x3c, 0xd5, 0xa5, 0xe3, 0x33, 0x7d,
	0x78, 0x79, 0xe5, 0x9e, 0x66, 0xa4, 0x1a, 0xf5, 0x0d, 0x0b, 0x16, 0xc1, 0x78, 0x74, 0x52, 0x1e,
	0x76, 0x49, 0x66, 0x88, 0xe3, 0x6f, 0x87, 0xf8, 0x5f, 0xa7, 0xfa, 0xff, 0x2f, 0xb0, 0xb2, 0xbf,
	0xaa, 0x6c, 0x69, 0xca, 0x52, 0x49, 0x79, 0x99, 0x17, 0x2b, 0x2c, 0x2e, 0x18, 0x63, 0x4d, 0xd2,
	0x13, 0xec, 0x12, 0xf9, 0x93, 0x04, 0x6e, 0x3c, 0x72, 0x68, 0xa4, 0x84, 0xfe, 0x93, 0x94, 0x39,
	0x90, 0x0a, 0xb0, 0x4d, 0x4a, 0xd4, 0xd9, 0x17, 0x32, 0x12, 0x05, 0xf0, 0xfb, 0x54, 0x4f, 0x6a,
	0x8a, 0xae, 0x69, 0x9a, 0x31, 0x12, 0x16, 0x37, 0x9d, 0x7d, 0x02, 0x73, 0x00, 0x70, 0x20, 0xf3,
	0xdf, 0x10, 0x2f, 0x93, 0xe0, 0xab, 0xa6, 0x8e, 0xcf, 0xf4, 0xff, 0x96, 0x57, 0x74, 0x4d, 0x33,
	0xf8, 0x2a, 0xcf, 0xc3, 0x9a, 0x7c, 0x24, 0x81, 0xf4, 0x05, 0x61, 0x34, 0xf0, 0x3d, 0x4a, 0xe0,
	0x2a, 0x48, 0x35, 0x2d, 0xd0, 0x8c, 0x34, 0x9d, 0xc8, 0x8d, 0xce, 0xcf, 0xa8, 0x5d, 0xb3, 0xa1,
	0x46, 0x67, 0xdc, 0x62, 0xc1, 0x59, 0x30, 0xe1, 0x91, 0x5d, 0x56, 0x6a, 0xd3, 0xc2, 0x0f, 0xcf,
	0x18, 0x0f, 0xa7, 0x9f, 0x45, 0x22, 0x3e, 0x4b, 0x20, 0x5d, 0xac, 0x12, 0xcc, 0xc8, 0x40, 0x37,
	0x65, 0xb4, 0xdd, 0x14, 0x0d, 0x48, 0x99, 0x6f, 0x36, 0x3a, 0x3f, 0xd7, 0x87, 0xea, 0xcd, 0x80,
	0x94, 0x0b, 0xc3, 0xe1, 0xc2, 0xad, 0x8b, 0x0b, 0xe7, 0xe4, 0x6d, 0x30, 0x19, 0x57, 0xf6, 0x98,
	0x30, 0x1c, 0x22, 0xe0, 0xd4, 0x65, 0x69, 0xed, 0x62, 0x66, 0x3a, 0xc6, 0xe6, 0x42, 0x2c, 0x3e,
	0x48, 0x20, 0xbd, 0x46, 0x2a, 0x64, 0x40, 0xe3, 0xd7, 0x12, 0xd1, 0x6d, 0x30, 0x19, 0x97, 0x72,
	0x9d, 0x4e, 0xe7, 0xdf, 0x25, 0xc1, 0x44, 0x74, 0xd8, 0xe2, 0xbd, 0x81, 0x5f, 0x24, 0x90, 0x58,
	0x27, 0x0c, 0x2a, 0x3d, 0x2e, 0xe8, 0x72, 0xf7, 0x66, 0xfb, 0x49, 0xa1, 0xbc, 0x71, 0xf4, 0xed,
	0xc7, 0xc7, 0xa1, 0x22, 0x5c, 0x45, 0x2e, 0xf6, 0xb0, 0x4d, 0x2c, 0x25, 0x7a, 0x23, 0x1a, 0xca,
	0x29, 0x3a, 0x68, 0xb9, 0x3a, 0x8c, 0x5e, 0x0e, 0x8a, 0x0e, 0x62, 0x6e, 0x0e, 0x43, 0x99, 0xc3,
	0x61, 0x8b, 0x40, 0xd4, 0x63, 0xe3, 0x4e, 0xcd, 0x9d, 0xd5, 0xfa, 0x27, 0x88, 0xa6, 0x93, 0x97,
	0xb8, 0xec, 0x05, 0xa8, 0x5f, 0x59, 0x36, 0xfc, 0x2a, 0x81, 0xa4, 0x88, 0x2a, 0xec, 0xb5, 0x6f,
	0xc7, 0x3e, 0xcb, 0xde, 0x89, 0x33, 0x5a, 0x0f, 0xf2, 0xd3, 0xe6, 0x48, 0x36, 0x4f, 0xce, 0xf3,
	0x72, 0xd7, 0x6e, 0x18, 0x69, 0xce, 0x70, 0x03, 0x8b, 0xf2, 0xd5, 0x0d, 0xdc, 0x97, 0xf2, 0xf0,
	0xbb, 0x04, 0x92, 0x22, 0x84, 0x3d, 0x3d, 0x74, 0x6c, 0x99, 0x7e, 0x3c, 0xbc, 0x3d, 0x39, 0xcf,
	0xa3, 0xae, 0x39, 0x4f, 0x8b, 0xef, 0x4d, 0xfc, 0x1d, 0x66, 0xed, 0x95, 0xfa, 0xd0, 0x0d, 0xd8,
	0x9e, 0x08, 0x52, 0x7e, 0xf0, 0x20, 0x15, 0x2c, 0x30, 0x15, 0x53, 0x88, 0x03, 0x27, 0xe6, 0x6b,
	0xab, 0x68, 0x3b, 0xec, 0x75, 0xcd, 0x54, 0xcb, 0xbe, 0x8b, 0x04, 0x52, 0x11, 0x7f, 0x9c, 0xed,
	0x2b, 0x36, 0xf1, 0xb8, 0x2e, 0xd4, 0xf5, 0xf3, 0x7b, 0xc0, 0x07, 0x66, 0x92, 0xc3, 0x16, 0xfe,
	0x04, 0x00, 0x00, 0xff, 0xff, 0xfc, 0x8b, 0xc4, 0xd2, 0xfa, 0x07, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// DatabaseServiceClient is the client API for DatabaseService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DatabaseServiceClient interface {
	// Returns the specified MySQL database.
	//
	// To get the list of available MySQL databases, make a [List] request.
	Get(ctx context.Context, in *GetDatabaseRequest, opts ...grpc.CallOption) (*Database, error)
	// Retrieves the list of MySQL databases in the specified cluster.
	List(ctx context.Context, in *ListDatabasesRequest, opts ...grpc.CallOption) (*ListDatabasesResponse, error)
	// Creates a new MySQL database in the specified cluster.
	Create(ctx context.Context, in *CreateDatabaseRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Deletes the specified MySQL database.
	Delete(ctx context.Context, in *DeleteDatabaseRequest, opts ...grpc.CallOption) (*operation.Operation, error)
}

type databaseServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDatabaseServiceClient(cc grpc.ClientConnInterface) DatabaseServiceClient {
	return &databaseServiceClient{cc}
}

func (c *databaseServiceClient) Get(ctx context.Context, in *GetDatabaseRequest, opts ...grpc.CallOption) (*Database, error) {
	out := new(Database)
	err := c.cc.Invoke(ctx, "/yandex.cloud.mdb.mysql.v1.DatabaseService/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *databaseServiceClient) List(ctx context.Context, in *ListDatabasesRequest, opts ...grpc.CallOption) (*ListDatabasesResponse, error) {
	out := new(ListDatabasesResponse)
	err := c.cc.Invoke(ctx, "/yandex.cloud.mdb.mysql.v1.DatabaseService/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *databaseServiceClient) Create(ctx context.Context, in *CreateDatabaseRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, "/yandex.cloud.mdb.mysql.v1.DatabaseService/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *databaseServiceClient) Delete(ctx context.Context, in *DeleteDatabaseRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, "/yandex.cloud.mdb.mysql.v1.DatabaseService/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DatabaseServiceServer is the server API for DatabaseService service.
type DatabaseServiceServer interface {
	// Returns the specified MySQL database.
	//
	// To get the list of available MySQL databases, make a [List] request.
	Get(context.Context, *GetDatabaseRequest) (*Database, error)
	// Retrieves the list of MySQL databases in the specified cluster.
	List(context.Context, *ListDatabasesRequest) (*ListDatabasesResponse, error)
	// Creates a new MySQL database in the specified cluster.
	Create(context.Context, *CreateDatabaseRequest) (*operation.Operation, error)
	// Deletes the specified MySQL database.
	Delete(context.Context, *DeleteDatabaseRequest) (*operation.Operation, error)
}

// UnimplementedDatabaseServiceServer can be embedded to have forward compatible implementations.
type UnimplementedDatabaseServiceServer struct {
}

func (*UnimplementedDatabaseServiceServer) Get(ctx context.Context, req *GetDatabaseRequest) (*Database, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (*UnimplementedDatabaseServiceServer) List(ctx context.Context, req *ListDatabasesRequest) (*ListDatabasesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (*UnimplementedDatabaseServiceServer) Create(ctx context.Context, req *CreateDatabaseRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (*UnimplementedDatabaseServiceServer) Delete(ctx context.Context, req *DeleteDatabaseRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}

func RegisterDatabaseServiceServer(s *grpc.Server, srv DatabaseServiceServer) {
	s.RegisterService(&_DatabaseService_serviceDesc, srv)
}

func _DatabaseService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDatabaseRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DatabaseServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/yandex.cloud.mdb.mysql.v1.DatabaseService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DatabaseServiceServer).Get(ctx, req.(*GetDatabaseRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DatabaseService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListDatabasesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DatabaseServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/yandex.cloud.mdb.mysql.v1.DatabaseService/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DatabaseServiceServer).List(ctx, req.(*ListDatabasesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DatabaseService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateDatabaseRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DatabaseServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/yandex.cloud.mdb.mysql.v1.DatabaseService/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DatabaseServiceServer).Create(ctx, req.(*CreateDatabaseRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DatabaseService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteDatabaseRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DatabaseServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/yandex.cloud.mdb.mysql.v1.DatabaseService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DatabaseServiceServer).Delete(ctx, req.(*DeleteDatabaseRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _DatabaseService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "yandex.cloud.mdb.mysql.v1.DatabaseService",
	HandlerType: (*DatabaseServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _DatabaseService_Get_Handler,
		},
		{
			MethodName: "List",
			Handler:    _DatabaseService_List_Handler,
		},
		{
			MethodName: "Create",
			Handler:    _DatabaseService_Create_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _DatabaseService_Delete_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "yandex/cloud/mdb/mysql/v1/database_service.proto",
}
