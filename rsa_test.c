#include "rsa_test.h"

//xxd -i
unsigned char pub_key_der[] = {
  0x30, 0x82, 0x01, 0x0a,
  0x02, 0x82, 0x01, 0x01, 
  0x00, 0xb5, 0xd9, 0x22, 0xd6, 0xb4, 0x62,
  0xf9, 0x92, 0x75, 0x87, 0xc3, 0x71, 0x73, 0x79, 0x49, 0xf9, 0xd5, 0x95, 0x7e, 0xf6, 0x0c, 0x68,
  0x07, 0xa5, 0x63, 0xee, 0xad, 0x6f, 0x6e, 0x32, 0xf8, 0xcc, 0x63, 0x3d, 0xe5, 0xf5, 0xf4, 0xe9,
  0x13, 0xdc, 0x75, 0x6b, 0xa6, 0xfc, 0x5f, 0x63, 0x08, 0x11, 0x0a, 0xa1, 0xa3, 0xa7, 0xad, 0xc7,
  0x51, 0xb4, 0x58, 0xfb, 0xa9, 0xbf, 0x77, 0x6b, 0x10, 0xf6, 0xcd, 0x31, 0x5a, 0x1b, 0x18, 0x19,
  0xd2, 0x4f, 0x6f, 0x27, 0xeb, 0xea, 0x99, 0x34, 0xdc, 0xd4, 0xa0, 0x1c, 0xd5, 0x35, 0x9a, 0xd6,
  0x34, 0xf8, 0xd3, 0x04, 0x5b, 0xb9, 0x14, 0x49, 0x9d, 0x1f, 0xc9, 0x80, 0x66, 0x0b, 0xce, 0x96,
  0x60, 0x19, 0x41, 0x24, 0xc6, 0x18, 0x50, 0xe5, 0x3b, 0x37, 0x3b, 0xc9, 0xac, 0x0f, 0x84, 0xce,
  0xa1, 0x33, 0x6b, 0x45, 0x65, 0xe6, 0x17, 0xa5, 0x7f, 0x96, 0x66, 0x58, 0x4f, 0x4f, 0x48, 0x6e,
  0x2c, 0xed, 0xb8, 0x9a, 0x04, 0xa6, 0x8c, 0x56, 0x1f, 0x4c, 0xa9, 0x69, 0xfb, 0x16, 0x12, 0xc9,
  0x9c, 0xec, 0x8f, 0xd9, 0x5a, 0x73, 0xcc, 0x54, 0x6f, 0x01, 0x64, 0x7a, 0x9a, 0x68, 0xe9, 0x24,
  0x2f, 0x50, 0x09, 0x26, 0xdd, 0xb3, 0xc9, 0x36, 0x15, 0x84, 0xaf, 0x41, 0x47, 0xcb, 0xa1, 0x99,
  0x20, 0x13, 0x67, 0x6a, 0x68, 0x8d, 0x20, 0x31, 0x79, 0xb1, 0x68, 0x39, 0x92, 0xe5, 0xae, 0xd6,
  0x13, 0xbd, 0x0a, 0x2d, 0x23, 0x15, 0xa0, 0x21, 0x6f, 0x9b, 0x2e, 0x05, 0x53, 0xd2, 0xe9, 0xc5,
  0x23, 0x4b, 0x68, 0x10, 0x61, 0xac, 0xa2, 0x81, 0xc1, 0x7e, 0x01, 0x81, 0xb4, 0x69, 0xbf, 0x6f,
  0x8d, 0x82, 0x72, 0xb8, 0x31, 0xc4, 0x6c, 0x82, 0xbd, 0x2d, 0xe8, 0x38, 0x3a, 0xf7, 0x4f, 0x50,
  0x5b, 0x6f, 0x46, 0x23, 0xfd, 0xc7, 0x01, 0x9c, 0x2f, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01
};
unsigned int pub_key_der_len = 270;

unsigned char private_der[] = {
  0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xb5, 0xd9, 0x22, 0xd6, 0xb4, 0x62, 0xf9, 0x92, 0x75, 0x87, 0xc3, 0x71,
  0x73, 0x79, 0x49, 0xf9, 0xd5, 0x95, 0x7e, 0xf6, 0x0c, 0x68, 0x07, 0xa5,
  0x63, 0xee, 0xad, 0x6f, 0x6e, 0x32, 0xf8, 0xcc, 0x63, 0x3d, 0xe5, 0xf5,
  0xf4, 0xe9, 0x13, 0xdc, 0x75, 0x6b, 0xa6, 0xfc, 0x5f, 0x63, 0x08, 0x11,
  0x0a, 0xa1, 0xa3, 0xa7, 0xad, 0xc7, 0x51, 0xb4, 0x58, 0xfb, 0xa9, 0xbf,
  0x77, 0x6b, 0x10, 0xf6, 0xcd, 0x31, 0x5a, 0x1b, 0x18, 0x19, 0xd2, 0x4f,
  0x6f, 0x27, 0xeb, 0xea, 0x99, 0x34, 0xdc, 0xd4, 0xa0, 0x1c, 0xd5, 0x35,
  0x9a, 0xd6, 0x34, 0xf8, 0xd3, 0x04, 0x5b, 0xb9, 0x14, 0x49, 0x9d, 0x1f,
  0xc9, 0x80, 0x66, 0x0b, 0xce, 0x96, 0x60, 0x19, 0x41, 0x24, 0xc6, 0x18,
  0x50, 0xe5, 0x3b, 0x37, 0x3b, 0xc9, 0xac, 0x0f, 0x84, 0xce, 0xa1, 0x33,
  0x6b, 0x45, 0x65, 0xe6, 0x17, 0xa5, 0x7f, 0x96, 0x66, 0x58, 0x4f, 0x4f,
  0x48, 0x6e, 0x2c, 0xed, 0xb8, 0x9a, 0x04, 0xa6, 0x8c, 0x56, 0x1f, 0x4c,
  0xa9, 0x69, 0xfb, 0x16, 0x12, 0xc9, 0x9c, 0xec, 0x8f, 0xd9, 0x5a, 0x73,
  0xcc, 0x54, 0x6f, 0x01, 0x64, 0x7a, 0x9a, 0x68, 0xe9, 0x24, 0x2f, 0x50,
  0x09, 0x26, 0xdd, 0xb3, 0xc9, 0x36, 0x15, 0x84, 0xaf, 0x41, 0x47, 0xcb,
  0xa1, 0x99, 0x20, 0x13, 0x67, 0x6a, 0x68, 0x8d, 0x20, 0x31, 0x79, 0xb1,
  0x68, 0x39, 0x92, 0xe5, 0xae, 0xd6, 0x13, 0xbd, 0x0a, 0x2d, 0x23, 0x15,
  0xa0, 0x21, 0x6f, 0x9b, 0x2e, 0x05, 0x53, 0xd2, 0xe9, 0xc5, 0x23, 0x4b,
  0x68, 0x10, 0x61, 0xac, 0xa2, 0x81, 0xc1, 0x7e, 0x01, 0x81, 0xb4, 0x69,
  0xbf, 0x6f, 0x8d, 0x82, 0x72, 0xb8, 0x31, 0xc4, 0x6c, 0x82, 0xbd, 0x2d,
  0xe8, 0x38, 0x3a, 0xf7, 0x4f, 0x50, 0x5b, 0x6f, 0x46, 0x23, 0xfd, 0xc7,
  0x01, 0x9c, 0x2f, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x00, 0x61, 0x1c, 0x41, 0xc4, 0x92, 0xb4, 0x40, 0x3e, 0xfc, 0x50, 0xb2,
  0x08, 0x85, 0xf8, 0x01, 0x8f, 0x4f, 0x85, 0xf4, 0x35, 0x05, 0x4f, 0x10,
  0xb6, 0x3b, 0xf5, 0x9b, 0xdc, 0xe3, 0xe6, 0x88, 0x82, 0xed, 0x84, 0x82,
  0xa7, 0xa4, 0x50, 0x4b, 0xf0, 0xf1, 0x2b, 0xba, 0x13, 0x10, 0x05, 0x5c,
  0xab, 0x6d, 0x18, 0x00, 0xc3, 0x6c, 0xc4, 0x02, 0x57, 0xe3, 0x25, 0x11,
  0xf3, 0x53, 0x9c, 0x73, 0x84, 0xb8, 0xf3, 0x60, 0x01, 0x14, 0x0f, 0xc6,
  0x05, 0xf1, 0x80, 0x4a, 0x36, 0x0f, 0xf6, 0xf0, 0xef, 0x03, 0x4a, 0x22,
  0x79, 0xeb, 0xe3, 0xf4, 0x89, 0xe4, 0x76, 0x71, 0x5d, 0x16, 0xfe, 0x70,
  0xd0, 0x26, 0xd5, 0x50, 0xa9, 0x81, 0x7b, 0x40, 0x7a, 0x7c, 0x15, 0x5d,
  0x4c, 0x62, 0xf6, 0xe7, 0x76, 0x89, 0x91, 0x1b, 0x37, 0x76, 0x5e, 0xba,
  0x2b, 0x31, 0x5f, 0xf0, 0x18, 0xbe, 0x0b, 0xfd, 0x63, 0xb7, 0x73, 0xa6,
  0xb1, 0x15, 0x54, 0xef, 0x07, 0x40, 0xa7, 0x89, 0xc1, 0xf8, 0xd6, 0x44,
  0x72, 0x30, 0xa0, 0x70, 0xfa, 0x0a, 0xca, 0xf7, 0xfe, 0x5c, 0xed, 0xb1,
  0x92, 0x63, 0xd8, 0xcc, 0x72, 0xd1, 0xf7, 0xa0, 0xea, 0x01, 0xb3, 0x3f,
  0xb5, 0x54, 0x5b, 0xd0, 0xf5, 0x25, 0x11, 0x12, 0x0d, 0x53, 0x84, 0x15,
  0x31, 0x79, 0x76, 0xb3, 0xef, 0xa3, 0xe6, 0xa3, 0x2d, 0xd3, 0x63, 0x3b,
  0xc4, 0x3d, 0xbe, 0x59, 0x87, 0x4e, 0xef, 0x4d, 0x20, 0x94, 0x6f, 0x23,
  0xc8, 0x54, 0x27, 0x79, 0x3d, 0x8b, 0x23, 0x06, 0xaf, 0x2c, 0xa3, 0x70,
  0xa0, 0x6b, 0x5f, 0x89, 0xa0, 0x87, 0x79, 0x1e, 0x25, 0xee, 0x37, 0x6f,
  0x94, 0x5f, 0xc1, 0x58, 0xa0, 0x90, 0x6d, 0x41, 0xc1, 0x5d, 0x50, 0x0a,
  0x7c, 0xf8, 0xb1, 0x31, 0x1e, 0xce, 0xd7, 0x0b, 0x60, 0x30, 0x28, 0x15,
  0x4b, 0x74, 0x31, 0x26, 0x21, 0x02, 0x81, 0x81, 0x00, 0xd9, 0xaf, 0x66,
  0xe7, 0x62, 0x43, 0x54, 0x41, 0x79, 0x84, 0x4d, 0xc9, 0xfa, 0x1b, 0xd9,
  0xd5, 0x65, 0x5e, 0x03, 0x16, 0xb2, 0x10, 0xd0, 0x81, 0x25, 0x39, 0x99,
  0xbe, 0x83, 0x3c, 0xf0, 0xfe, 0x5d, 0x61, 0x89, 0x8e, 0x03, 0xab, 0xca,
  0x2a, 0x9e, 0x63, 0x4a, 0x52, 0x18, 0x9d, 0xee, 0x12, 0x2c, 0x33, 0xd6,
  0x8a, 0x78, 0xe7, 0x08, 0x2c, 0x3a, 0x37, 0x0c, 0xea, 0x87, 0x73, 0x74,
  0x48, 0x6b, 0x44, 0x77, 0xb4, 0x68, 0x8c, 0xc5, 0x80, 0xae, 0xf3, 0x3b,
  0x3b, 0xfd, 0x4d, 0xd3, 0x95, 0x9b, 0xc5, 0xe1, 0x29, 0x6d, 0x33, 0x5a,
  0x34, 0x8a, 0xa7, 0x3b, 0x0d, 0x9f, 0x11, 0xde, 0x9d, 0x0e, 0xeb, 0x4f,
  0xb7, 0xbc, 0xdf, 0xbb, 0xcf, 0x43, 0x7d, 0xa4, 0x1d, 0x3a, 0x47, 0xf0,
  0x02, 0x6c, 0x6b, 0x09, 0x42, 0xad, 0x37, 0xc5, 0x23, 0xa2, 0x58, 0x4c,
  0x08, 0x22, 0x62, 0x42, 0x45, 0x02, 0x81, 0x81, 0x00, 0xd5, 0xda, 0xf7,
  0xf7, 0x57, 0x1b, 0x34, 0x74, 0xd5, 0x22, 0x03, 0xbe, 0x23, 0x3f, 0x47,
  0xa4, 0x6e, 0xfe, 0x7b, 0xbb, 0x5a, 0x4e, 0x8a, 0x14, 0x82, 0xd5, 0xd5,
  0x82, 0xb3, 0x86, 0xd1, 0xe2, 0x8f, 0xe1, 0x2c, 0xd0, 0x85, 0x06, 0x28,
  0x8c, 0x03, 0x39, 0x28, 0x42, 0x0f, 0x94, 0xde, 0x71, 0x94, 0x2c, 0x59,
  0x61, 0xf0, 0x4c, 0x4a, 0xad, 0xdf, 0xd6, 0x99, 0x7f, 0xe0, 0x7d, 0xe4,
  0x59, 0xfb, 0x5f, 0x86, 0x9e, 0x64, 0x54, 0xa8, 0x56, 0xd2, 0xfc, 0x0d,
  0x0a, 0xbf, 0x57, 0x3c, 0x13, 0x1d, 0x87, 0xbf, 0x6b, 0xcc, 0xa1, 0xb8,
  0xe9, 0x04, 0x2d, 0xd2, 0x40, 0xbb, 0xc5, 0x29, 0xf0, 0xd1, 0x5e, 0x64,
  0xb9, 0xdb, 0x32, 0x33, 0xe8, 0x66, 0x08, 0x23, 0x99, 0x99, 0x01, 0x70,
  0xe5, 0x10, 0x49, 0xf0, 0xc4, 0x02, 0x4c, 0xd3, 0xbe, 0x9d, 0xa2, 0x7c,
  0xbf, 0x23, 0x99, 0x86, 0xcd, 0x02, 0x81, 0x81, 0x00, 0xd8, 0x0b, 0x58,
  0x12, 0xde, 0x98, 0x39, 0xff, 0xfd, 0x6d, 0x4c, 0x92, 0xdf, 0x92, 0x52,
  0xa0, 0x92, 0xc9, 0x3a, 0x41, 0x85, 0x1a, 0x61, 0x05, 0x3b, 0x7f, 0xae,
  0x51, 0xc1, 0x08, 0x73, 0x99, 0xcf, 0xed, 0xe4, 0xca, 0x38, 0x64, 0x7f,
  0xf1, 0xca, 0x5e, 0x7a, 0xbd, 0x7d, 0xc7, 0x08, 0x27, 0xab, 0x0d, 0x0b,
  0xa9, 0x44, 0x92, 0xee, 0xae, 0x8e, 0x5c, 0x62, 0x8a, 0x45, 0x42, 0x55,
  0xaf, 0x26, 0x1e, 0xbe, 0xbb, 0x23, 0x64, 0x4b, 0x04, 0x0b, 0x1e, 0x45,
  0xb4, 0xa5, 0x12, 0x5f, 0xa2, 0xc5, 0x06, 0x20, 0x10, 0xb0, 0x5b, 0x5d,
  0xf4, 0x75, 0x83, 0xc1, 0x7d, 0x24, 0x59, 0x64, 0xd9, 0xf5, 0x9b, 0x9e,
  0xf3, 0x99, 0x15, 0x67, 0xdd, 0x2d, 0x7b, 0x7d, 0xac, 0xb0, 0x52, 0x03,
  0x27, 0x34, 0x99, 0x0a, 0x88, 0xcd, 0x47, 0x63, 0x75, 0x99, 0x43, 0x0e,
  0xba, 0xa7, 0xfd, 0x63, 0x0d, 0x02, 0x81, 0x80, 0x73, 0x62, 0x51, 0xa8,
  0x02, 0x37, 0x8b, 0x75, 0xfe, 0x08, 0xfc, 0x3b, 0xfa, 0x88, 0x89, 0xff,
  0x0e, 0x64, 0x00, 0x1e, 0x75, 0xfb, 0x2a, 0x45, 0x26, 0xd2, 0x79, 0x00,
  0xac, 0x1c, 0x71, 0xe1, 0xeb, 0xff, 0x72, 0x4e, 0x8f, 0x77, 0x63, 0x29,
  0x28, 0x14, 0x0e, 0xc4, 0x95, 0xe3, 0x9c, 0xa1, 0x6b, 0x71, 0x02, 0x48,
  0xf5, 0x7e, 0x34, 0x4c, 0xdc, 0x18, 0xcd, 0x79, 0x51, 0x86, 0x9b, 0x4e,
  0x71, 0x72, 0x79, 0x0f, 0xbc, 0xd2, 0x70, 0x81, 0x68, 0x14, 0xd6, 0x74,
  0x96, 0x08, 0x5b, 0x41, 0x75, 0x0d, 0x69, 0x1a, 0xa0, 0xae, 0x21, 0x36,
  0x98, 0x2a, 0xa0, 0xe6, 0x8c, 0x69, 0x34, 0xd7, 0xda, 0x1f, 0x33, 0xf9,
  0x93, 0x6a, 0xe2, 0xd6, 0xe1, 0x36, 0x42, 0xfe, 0xfc, 0xae, 0xea, 0x5a,
  0xad, 0x0f, 0x37, 0xf8, 0x89, 0xc5, 0x29, 0xfa, 0x0e, 0xd3, 0x3c, 0xbb,
  0x64, 0x59, 0xd1, 0x81, 0x02, 0x81, 0x80, 0x19, 0x50, 0x14, 0x5a, 0x7d,
  0x79, 0x68, 0x53, 0x5e, 0xf5, 0x60, 0xd3, 0x93, 0xef, 0x2b, 0x7d, 0x9f,
  0x09, 0x01, 0xf2, 0x8f, 0x8b, 0xc9, 0xf4, 0xa6, 0xd4, 0xac, 0x8d, 0x96,
  0x28, 0x9a, 0xea, 0x1e, 0x75, 0x85, 0x2b, 0xdc, 0xe4, 0xa7, 0x81, 0x48,
  0x96, 0x72, 0x4c, 0x06, 0xf8, 0xc6, 0xc3, 0x50, 0x1c, 0x3c, 0x07, 0x0f,
  0x9c, 0xa3, 0xec, 0x14, 0x4b, 0x3d, 0x09, 0xbd, 0xf4, 0xcc, 0x37, 0x13,
  0xa2, 0xd0, 0x8a, 0xde, 0x3b, 0xa6, 0xaf, 0x13, 0x10, 0x3b, 0xa0, 0xe3,
  0xe8, 0x67, 0x12, 0xc8, 0xc9, 0xc5, 0x30, 0xc4, 0x60, 0xb1, 0x0b, 0xd8,
  0xb7, 0x16, 0x3c, 0x64, 0xd5, 0xe1, 0x4e, 0xf3, 0xa0, 0x7c, 0xb0, 0x19,
  0x75, 0x34, 0x59, 0xb8, 0x64, 0xcc, 0x67, 0x4e, 0x98, 0x02, 0xd0, 0x7b,
  0x6a, 0x67, 0x2e, 0x38, 0x1d, 0x4b, 0x0d, 0xda, 0x37, 0xb7, 0x25, 0x14,
  0x83, 0x3d, 0x92
};
unsigned int private_der_len = 1191;

unsigned char m[]= {// hello
0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a
};
#if 0
unsigned char priveta_en[] = { // 私钥加密的 hello , openssl
  0xb4, 0xab, 0xf1, 0x95, 0xb4, 0x4f, 0x48, 0xb7, 0xe8, 0x10, 0xdc, 0xd1,
  0x27, 0xbf, 0xa9, 0xa0, 0xff, 0xc1, 0xbb, 0xbb, 0x42, 0x1f, 0xdf, 0x60,
  0x51, 0xce, 0x5f, 0x58, 0x35, 0xa4, 0x9d, 0xfc, 0x96, 0x49, 0xd7, 0x6d,
  0x71, 0xd9, 0xec, 0xa1, 0x53, 0x3d, 0x86, 0x2c, 0x59, 0x0b, 0x5b, 0x23,
  0xb1, 0xc0, 0xc4, 0x7b, 0xb9, 0x16, 0x8c, 0xf4, 0xbf, 0x5d, 0x71, 0x1d,
  0x67, 0xb9, 0x64, 0xd3, 0xf6, 0x3d, 0xc6, 0x4e, 0xeb, 0xd2, 0x3c, 0xe7,
  0x9d, 0xb3, 0xed, 0x02, 0xb5, 0xeb, 0x52, 0x5e, 0x6b, 0x30, 0xa5, 0x7a,
  0x8d, 0xea, 0xc8, 0x9b, 0xc5, 0x7f, 0xbf, 0xab, 0x15, 0x90, 0xdc, 0xe3,
  0x98, 0xc4, 0xf6, 0x4f, 0xe7, 0x1d, 0x0e, 0xfa, 0x0e, 0x71, 0x3c, 0x7d,
  0x77, 0xc9, 0xe9, 0x94, 0xe4, 0xcf, 0xbc, 0xe6, 0x78, 0xb2, 0xd1, 0x32,
  0xb7, 0x62, 0x55, 0xdc, 0x3b, 0x7a, 0x2e, 0xb7, 0xc7, 0x24, 0x18, 0xa3,
  0xd8, 0x02, 0x49, 0xaf, 0x67, 0x00, 0x94, 0xbe, 0x27, 0xed, 0x18, 0x64,
  0x36, 0x71, 0xfe, 0xb1, 0xc4, 0xd7, 0xeb, 0x51, 0xe7, 0x04, 0x2d, 0x08,
  0x45, 0x76, 0x3a, 0x76, 0xe7, 0x18, 0x39, 0x21, 0xfc, 0x73, 0x4b, 0x1a,
  0xec, 0xcd, 0xb9, 0x29, 0xdc, 0xad, 0x34, 0xf2, 0xaf, 0xb4, 0x26, 0xbe,
  0xd9, 0x9f, 0xf1, 0xbf, 0xab, 0x16, 0xa9, 0x47, 0x3c, 0x4d, 0x71, 0xe9,
  0xb0, 0xc3, 0xfd, 0x9c, 0x9d, 0x5e, 0x6c, 0x05, 0x57, 0x4e, 0x71, 0x5d,
  0x47, 0x34, 0xcd, 0xdf, 0x76, 0xe3, 0xd9, 0xa2, 0x39, 0x02, 0xa2, 0xce,
  0x67, 0x9b, 0x74, 0xa9, 0x0e, 0xc2, 0x21, 0x67, 0x6d, 0x38, 0xcb, 0xa0,
  0x60, 0xb0, 0x70, 0x1d, 0xa3, 0x0b, 0xe8, 0x6d, 0xd9, 0x47, 0xc0, 0x5b,
  0xee, 0x21, 0xdb, 0xa5, 0x05, 0x50, 0x00, 0xbb, 0x35, 0x21, 0x3f, 0xc8,
  0x72, 0x03, 0xcb, 0x03
};

#else
unsigned char priveta_en[] = { // 私钥加密的 hello , linux kernel
  0x7c, 0xe3, 0x84, 0x77, 0x13, 0xeb, 0x4f, 0xa6, 0xfd, 0xa5, 0x17, 0x74,
  0x0a, 0x41, 0x40, 0x24, 0xb4, 0x38, 0x9c, 0xd6, 0xf2, 0x2e, 0xda, 0x5a,
  0x61, 0x4c, 0x12, 0x8a, 0x7d, 0x61, 0x22, 0xe2, 0x0c, 0x28, 0xb3, 0x3e,
  0x4e, 0x1f, 0x98, 0x97, 0xf2, 0x02, 0xf5, 0x30, 0xde, 0xa7, 0x8c, 0xf6,
  0x55, 0x8d, 0xd3, 0x55, 0xde, 0x3c, 0xa8, 0x2c, 0x13, 0xd0, 0x37, 0xcd,
  0xab, 0x0d, 0xe2, 0xed, 0x9a, 0x97, 0x0c, 0xc7, 0x7c, 0x4a, 0xf1, 0xef,
  0xf1, 0x69, 0x89, 0xb8, 0xe9, 0xb8, 0x14, 0x92, 0x54, 0xc2, 0x07, 0x68,
  0x92, 0xae, 0x22, 0x49, 0x3e, 0xa3, 0x8a, 0x44, 0x77, 0x5b, 0x72, 0x5f,
  0xe3, 0xd8, 0x08, 0x9b, 0xbe, 0xb8, 0x35, 0xbd, 0x01, 0x3e, 0x5f, 0x39,
  0x2c, 0x1a, 0xd5, 0x7e, 0x53, 0x9c, 0xdc, 0x61, 0xe5, 0x9b, 0xab, 0xd2,
  0x1d, 0x69, 0x1f, 0x93, 0x35, 0xdf, 0x8e, 0x17, 0x7b, 0xcf, 0x3f, 0xf5,
  0x74, 0x91, 0x8f, 0x62, 0xe3, 0xac, 0x48, 0xa0, 0x53, 0x12, 0xc1, 0x09,
  0x0b, 0x3b, 0xd4, 0x91, 0x0c, 0xf2, 0xd7, 0x9d, 0x37, 0xfa, 0x59, 0xaa,
  0x37, 0x00, 0x69, 0x63, 0x4d, 0x49, 0xfb, 0x95, 0xd7, 0xbb, 0x81, 0x69,
  0x49, 0xb7, 0x66, 0x2b, 0xa2, 0x2b, 0x2c, 0x50, 0x37, 0x07, 0x77, 0x9c,
  0xe5, 0x6b, 0xdf, 0x5c, 0x5f, 0xb8, 0x78, 0xeb, 0x78, 0xe8, 0xa4, 0x2c,
  0xce, 0xa4, 0xf0, 0x98, 0x6b, 0x16, 0xf1, 0x48, 0xc5, 0x93, 0xb8, 0xca,
  0xf1, 0x45, 0x0f, 0x51, 0xf4, 0xc9, 0x09, 0xa6, 0xbf, 0x2a, 0x02, 0x0e,
  0xc6, 0x15, 0xab, 0x2f, 0xdf, 0xe7, 0xec, 0x97, 0xc9, 0xd8, 0x85, 0x3b,
  0xa5, 0x01, 0x02, 0xd6, 0xf6, 0x48, 0xa0, 0xce, 0x81, 0xfa, 0xca, 0x92,
  0x49, 0x31, 0x71, 0x64, 0xcb, 0x6b, 0xfa, 0x81, 0x09, 0x4b, 0x5e, 0x12,
  0xe3, 0x1b, 0x78, 0xec
};
#endif
unsigned int priveta_en_len = 256;
