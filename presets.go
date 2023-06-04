package main

import (
	"github.com/Noooste/fhttp/http2"
	tls "github.com/Noooste/utls"

	"errors"
)

const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV  uint16 = 0x5600
	GREASE_PLACEHOLDER        = 0x0a0a
)

type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
)

func DefaultHeaderSettings(navigator string) []http2.Setting {
	switch navigator {
	case firefox:
		return []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 131072},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		}

	default: //chrome
		return []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	}
}

func DefaultWindowsUpdate(navigator string) uint32 {
	switch navigator {
	case firefox:
		return 12517377
	default:
		return 15663105
	}
}

func DefaultStreamPriorities(navigator string) []http2.StreamPriority {
	switch navigator {
	case firefox:
		return []http2.StreamPriority{
			{
				StreamId: 3,
				PriorityParam: http2.PriorityParam{
					Weight: 200,
				},
			},
			{
				StreamId: 5,
				PriorityParam: http2.PriorityParam{
					Weight: 100,
				},
			},
			{
				StreamId: 7,
				PriorityParam: http2.PriorityParam{
					Weight: 0,
				},
			},
			{
				StreamId: 9,
				PriorityParam: http2.PriorityParam{
					Weight:    0,
					StreamDep: 7,
				},
			},
			{
				StreamId: 11,
				PriorityParam: http2.PriorityParam{
					Weight:    0,
					StreamDep: 3,
				},
			},
			{
				StreamId: 13,
				PriorityParam: http2.PriorityParam{
					Weight: 240,
				},
			},
		}

	default:
		return []http2.StreamPriority{}
	}
}

func DefaultHeaderPriorities(navigator string) http2.PriorityParam {
	switch navigator {
	case firefox:
		return http2.PriorityParam{
			Weight:    41,
			StreamDep: 13,
			Exclusive: false,
		}

	default:
		return http2.PriorityParam{
			Weight:    0,
			StreamDep: 0,
			Exclusive: true,
		}
	}
}

func GetSpecsFromNavigator(navigator string) (*tls.ClientHelloSpec, error) {
	switch navigator {
	case chrome:
		return &tls.ClientHelloSpec{
			CipherSuites: []uint16{
				GREASE_PLACEHOLDER,
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.SNIExtension{},
				&tls.UtlsExtendedMasterSecretExtension{},
				&tls.RenegotiationInfoExtension{},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					GREASE_PLACEHOLDER,
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&tls.SessionTicketExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.StatusRequestExtension{},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					1027,
					2052,
					1025,
					1283,
					2053,
					1281,
					2054,
					1537,
				}},
				&tls.SCTExtension{},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519},
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
					tls.PskModeDHE,
				}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				}},
				&tls.CompressCertificateExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
				&tls.ApplicationSettingsExtension{
					SupportedALPNList: []string{
						"h2",
					},
				},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			},
		}, nil
	case firefox:
		return &tls.ClientHelloSpec{
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethods: []byte{
				0,
			},
			Extensions: []tls.TLSExtension{
				&tls.SNIExtension{},                      //server_name
				&tls.UtlsExtendedMasterSecretExtension{}, //extended_master_secret
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, //extensionRenegotiationInfo
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ //supported_groups
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
					tls.CurveP521,
					tls.CurveID(tls.FakeFFDHE2048),
					tls.CurveID(tls.FakeFFDHE3072),
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
					0x0,
				}},
				&tls.SessionTicketExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //application_layer_protocol_negotiation
				&tls.StatusRequestExtension{},
				&tls.DelegatedCredentialsExtension{
					AlgorithmsSignature: []tls.SignatureScheme{ //signature_algorithms
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					},
				},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256}, //key_share
				}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.VersionTLS13, //supported_versions
					tls.VersionTLS12,
				}},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ //signature_algorithms
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
					tls.ECDSAWithSHA1,
					tls.PKCS1WithSHA1,
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{ //psk_key_exchange_modes
					tls.PskModeDHE,
				}},
				&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},                 //record_size_limit
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}, //padding
			}}, nil
	default:
		return nil, errors.New("Can't get client hello from" + navigator)
	}
}
