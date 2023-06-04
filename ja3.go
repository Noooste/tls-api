package main

import (
	"errors"
	"github.com/Noooste/utls"
	"strconv"
	"strings"
)

const (
	chrome  = "chrome"
	firefox = "firefox"
	opera   = "opera"
	safari  = "safari"
	edge    = "edge"
	ios     = "ios"
	android = "android"
)

func StringToSpec(ja3 string, specifications map[string][]interface{}, navigator string) (*tls.ClientHelloSpec, error) {
	specs := &tls.ClientHelloSpec{}

	information := strings.Split(ja3, ",")

	if len(information) != 5 {
		return nil, errors.New("invalid JA3")
	}

	ciphers := strings.Split(information[1], "-")
	rawExtensions := strings.Split(information[2], "-")

	curves := strings.Split(information[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}

	pointFormats := strings.Split(information[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	//ciphers suite
	finalCiphers, convertErr := TurnToUint(ciphers, navigator, true)
	if convertErr != "" {
		return nil, errors.New(convertErr + "cipher")
	}
	specs.CipherSuites = finalCiphers

	//extensions

	extensions, minVers, maxVers, err := GetExtensions(rawExtensions, specifications, pointFormats, curves, navigator)

	if err != nil {
		return nil, err
	}
	specs.Extensions = extensions
	specs.TLSVersMin = minVers
	specs.TLSVersMax = maxVers

	return specs, nil
}

func TurnToUint(value []string, navigator string, isCipherSuite bool) ([]uint16, string) {
	var converted []uint16
	var nextIndex int

	if isCipherSuite && navigator == chrome {
		converted = make([]uint16, len(value)+1)
		converted[0] = tls.GREASE_PLACEHOLDER
		nextIndex = 1
	} else {
		converted = make([]uint16, len(value))

	}

	//cipher suites
	for _, cipher := range value {
		value, err := strconv.Atoi(cipher)

		if err != nil {
			return nil, cipher + " is not a valid "
		}

		converted[nextIndex] = uint16(value)

		nextIndex++
	}

	return converted, ""
}

func GetExtensions(extensions []string, specifications map[string][]interface{}, defaultPointsFormat []string, defaultCurves []string, navigator string) ([]tls.TLSExtension, uint16, uint16, error) {
	var builtExtensions []tls.TLSExtension
	var nextIndex int
	var minVers uint16 = tls.VersionTLS10
	var maxVers uint16 = tls.VersionTLS13

	switch navigator {
	case chrome:
		builtExtensions = make([]tls.TLSExtension, len(extensions)+1)
		builtExtensions[0] = &tls.UtlsGREASEExtension{}
		nextIndex = 1
	default:
		builtExtensions = make([]tls.TLSExtension, len(extensions))
	}

	for _, extension := range extensions {
		switch extension {
		case "0":
			builtExtensions[nextIndex] = &tls.SNIExtension{}

		case "5":
			builtExtensions[nextIndex] = &tls.StatusRequestExtension{}

		case "10":
			var finalCurves []tls.CurveID
			var i int
			switch navigator {
			case chrome:
				finalCurves = make([]tls.CurveID, len(defaultCurves)+1)
				finalCurves[0] = tls.CurveID(tls.GREASE_PLACEHOLDER)
				i = 1
			default:
				finalCurves = make([]tls.CurveID, len(defaultCurves))
			}
			for j := range defaultCurves {
				value, err := strconv.Atoi(defaultCurves[j])
				if err != nil {
					return nil, 0, 0, errors.New(defaultCurves[j] + " is not a valid curve")
				}
				finalCurves[j+i] = tls.CurveID(value)
			}
			builtExtensions[nextIndex] = &tls.SupportedCurvesExtension{Curves: finalCurves}

		case "11":
			var finalPointsFormat []uint8
			finalPointsFormat = make([]uint8, len(defaultPointsFormat))
			for j := range defaultPointsFormat {
				value, err := strconv.Atoi(defaultPointsFormat[j])
				if err != nil {
					return nil, 0, 0, errors.New(defaultPointsFormat[j] + " is not a valid curve")
				}
				finalPointsFormat[j] = uint8(value)
			}
			builtExtensions[nextIndex] = &tls.SupportedPointsExtension{SupportedPoints: finalPointsFormat}

		case "13":
			var supportedAlgorithms []tls.SignatureScheme
			if algorithms, ok := specifications["13"]; ok {
				supportedAlgorithms = make([]tls.SignatureScheme, len(algorithms))
				for i, el := range algorithms {
					supportedAlgorithms[i] = tls.SignatureScheme(el.(float64))
				}
			} else {
				supportedAlgorithms = GetSupportedAlgorithms(navigator)
			}
			builtExtensions[nextIndex] = &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: supportedAlgorithms}

		case "16":
			var finalALPN []string
			if elements, ok := specifications["16"]; ok {
				finalALPN = make([]string, len(elements))
				for i, alpn := range elements {
					finalALPN[i] = alpn.(string)
				}
			} else {
				finalALPN = []string{"h2", "http/1.1"}
			}
			builtExtensions[nextIndex] = &tls.ALPNExtension{AlpnProtocols: finalALPN}

		case "17":
			builtExtensions[nextIndex] = &tls.StatusRequestV2Extension{}

		case "18":
			builtExtensions[nextIndex] = &tls.SCTExtension{}

		case "21":
			builtExtensions[nextIndex] = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}

		case "22":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 22}

		case "23":
			builtExtensions[nextIndex] = &tls.UtlsExtendedMasterSecretExtension{}

		case "27":
			var certCompression []tls.CertCompressionAlgo
			if algorithms, ok := specifications["27"]; ok {
				certCompression = make([]tls.CertCompressionAlgo, len(algorithms))
				for i, algo := range algorithms {
					certCompression[i] = tls.CertCompressionAlgo(algo.(float64))
				}
			} else {
				certCompression = []tls.CertCompressionAlgo{tls.CertCompressionBrotli}
			}
			builtExtensions[nextIndex] = &tls.CompressCertificateExtension{Algorithms: certCompression}

		case "28":
			builtExtensions[nextIndex] = &tls.FakeRecordSizeLimitExtension{}

		case "35":
			builtExtensions[nextIndex] = &tls.SessionTicketExtension{}

		case "34":
			var supportedAlgorithms []tls.SignatureScheme
			if algorithms, ok := specifications["34"]; ok {
				supportedAlgorithms = make([]tls.SignatureScheme, len(algorithms))
				for i, algo := range algorithms {
					supportedAlgorithms[i] = tls.SignatureScheme(algo.(float64))
				}
			} else {
				supportedAlgorithms = []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
				}
			}
			builtExtensions[nextIndex] = &tls.DelegatedCredentialsExtension{AlgorithmsSignature: supportedAlgorithms}

		case "41":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 41}

		case "43":
			var supportedVersions []uint16
			if versions, ok := specifications["43"]; ok {
				supportedVersions = make([]uint16, len(versions))
				for i, v := range versions {
					specVersion := uint16(v.(float64))
					supportedVersions[i] = specVersion

					if specVersion == tls.GREASE_PLACEHOLDER {
						continue
					}

					if specVersion < minVers || minVers == 0 {
						minVers = specVersion
					}

					if specVersion > maxVers || minVers == 0 {
						maxVers = specVersion
					}
				}
			} else {
				supportedVersions, minVers, maxVers = GetSupportedVersion(navigator)
			}
			builtExtensions[nextIndex] = &tls.SupportedVersionsExtension{Versions: supportedVersions}

		case "44":
			builtExtensions[nextIndex] = &tls.CookieExtension{}

		case "45":
			var pskKeyExchange []uint8
			if keys, ok := specifications["45"]; ok {
				pskKeyExchange = make([]uint8, len(keys))
				for i, k := range keys {
					pskKeyExchange[i] = uint8(k.(float64))
				}
			} else {
				pskKeyExchange = []uint8{tls.PskModeDHE}
			}
			builtExtensions[nextIndex] = &tls.PSKKeyExchangeModesExtension{Modes: pskKeyExchange}

		case "49":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 49}

		case "50":
			var supportedAlgorithms []tls.SignatureScheme
			if algorithms, ok := specifications["50"]; ok {
				supportedAlgorithms = make([]tls.SignatureScheme, len(algorithms))
				for i, algo := range algorithms {
					supportedAlgorithms[i] = tls.SignatureScheme(algo.(float64))
				}
			} else {
				supportedAlgorithms = []tls.SignatureScheme{}
			}
			builtExtensions[nextIndex] = &tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{}}

		case "51":
			switch navigator {
			case chrome:
				builtExtensions[nextIndex] = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: tls.X25519},
				}}

			default: //firefox
				builtExtensions[nextIndex] = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				}}
			}

		case "30032":
			builtExtensions[nextIndex] = &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}

		case "13172":
			builtExtensions[nextIndex] = &tls.NPNExtension{}

		case "17513":
			var finalALPN []string
			if elements, ok := specifications["17513"]; ok {
				finalALPN = make([]string, len(elements))
				for i, alpn := range elements {
					finalALPN[i] = alpn.(string)
				}
			} else {
				finalALPN = []string{"h2"}
			}
			builtExtensions[nextIndex] = &tls.ApplicationSettingsExtension{SupportedALPNList: finalALPN}

		case "65281":
			var renegotiation tls.RenegotiationSupport
			if value, ok := specifications["65281"]; ok {
				renegotiation = tls.RenegotiationSupport(value[0].(float64))
			} else {
				renegotiation = tls.RenegotiateOnceAsClient
			}
			builtExtensions[nextIndex] = &tls.RenegotiationInfoExtension{Renegotiation: renegotiation}
		}

		nextIndex++
	}
	/*
		//TODO
		"22": &tls.GenericExtension{Id: 22}, // encrypt_then_mac
		"41": &tls.GenericExtension{Id: 41}, //FIXME pre_shared_key
		"30032": &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
	*/
	length := len(builtExtensions)
	for _, el := range builtExtensions {
		if el == nil {
			length--
		}
	}

	if length != len(builtExtensions) {
		newBuildExtensions := make([]tls.TLSExtension, length)

		index := 0
		for _, el := range builtExtensions {
			if el != nil {
				newBuildExtensions[index] = el
				index++
			}
		}

		return newBuildExtensions, minVers, maxVers, nil
	}

	return builtExtensions, minVers, maxVers, nil
}

func GetSupportedAlgorithms(navigator string) []tls.SignatureScheme {
	switch navigator {
	case firefox:
		return []tls.SignatureScheme{
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
		}
	default: //chrome
		return []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
		}
	case opera:
		return []tls.SignatureScheme{
			1027,
			1283,
			1539,
			2052,
			2053,
			2054,
			2057,
			2058,
			2059,
			1025,
			1281,
			1537,
			1026,
			771,
			769,
			770,
			515,
			513,
			514,
		}
	}
}

func GetSupportedVersion(navigator string) ([]uint16, uint16, uint16) {
	switch navigator {
	case chrome:
		return []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}, tls.VersionTLS12, tls.VersionTLS13
	default:
		return []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		}, tls.VersionTLS12, tls.VersionTLS13
	}
}
