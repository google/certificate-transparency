package ct

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/certificate-transparency/go/asn1"
	"github.com/google/certificate-transparency/go/testdata"
	"github.com/google/certificate-transparency/go/tls"
)

const (
	CertEntry    = "000000000149a6e03abe00000006513082064d30820535a003020102020c6a5d4161f5c9b68043270b0c300d06092a864886f70d0101050500305e310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313430320603550403132b476c6f62616c5369676e20457874656e6465642056616c69646174696f6e204341202d2047322054455354301e170d3134313131333031353830315a170d3136313131333031353830315a3082011331183016060355040f0c0f427573696e65737320456e74697479311230100603550405130936363636363636363631133011060b2b0601040182373c0201031302444531293027060b2b0601040182373c02010113186576206a7572697364696374696f6e206c6f63616c69747931263024060b2b0601040182373c02010213156576206a7572697364696374696f6e207374617465310b3009060355040613024a50310a300806035504080c0153310a300806035504070c014c311530130603550409130c657620616464726573732033310c300a060355040b0c034f5531310c300a060355040b0c034f5532310a3008060355040a0c014f3117301506035504030c0e637372636e2e73736c32342e6a7030820122300d06092a864886f70d01010105000382010f003082010a02820101008db9f0d6b359466dffe95ba43dc1a5680eedc8f3cabbc573a236a109bf6e58df816c7bb8156147ab526eceaffd0576e6e1c09ea33433e114d7e5038c697298c7957f01a7e1142320847cf234995bbe42798340cb99e6a7e2cfa950277aef6e02f4d96ddceb0af9541171b0f8f1aa4f0d02453e6e654b25a13f2aff4357cae8177d3bd21855686591a2309d9ff5dead8240304e22eafcc5508587e6b6ad1d00b53c28e5b936269afbf214b73edbdc8a48a86c1c23f3dce55fcce60502c0908bca9bdb22c16c0b34d11b4fd27e9d7bcb56c5ec0fc4d52500fb06b0af5c4112e421022b78b31030cb73e9fd92ffc65919fd8f35e604fcaf025b9c77e3e5dff749a70203010001a38202523082024e300e0603551d0f0101ff0404030205a0304c0603551d2004453043304106092b06010401a03201013034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f30480603551d1f0441303f303da03ba0398637687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f67732f67736f7267616e697a6174696f6e76616c63617467322e63726c30819c06082b0601050507010104818f30818c304a06082b06010505073002863e687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f67736f7267616e697a6174696f6e76616c63617467322e637274303e06082b060105050730018632687474703a2f2f6f637370322e676c6f62616c7369676e2e636f6d2f67736f7267616e697a6174696f6e76616c6361746732301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e637372636e2e73736c32342e6a70301d0603551d0e041604147f834b2903e35efff651619083a2efd69a6d70f4301f0603551d23041830168014ab30a406d972d0029ab2c7d3f4241be2fca5320230818a060a2b06010401d679020402047c047a0078007600b0cc83e5a5f97d6baf7c09cc284904872ac7e88b132c6350b7c6fd26e16c6c7700000149a6dc346b00000403004730450220469f4dc0553b7832bd56633c3b9d53faaec84df414b7a05ab1b2d544d146ac3e022100ee899419fd4f95544798f7883fe093692feb4c90e84d651600f7019166a43701300d06092a864886f70d010105050003820101007dcd3e228d68cdc0734c7629fd7d40cd742d0ed1d0d9f49a643af12dcdbc61394638b7c519bb7cae530ccdc3a5037d5cdd8a4d2c01abdc834daf1993f7a22ee2c223377a94da4e68ac69a0b50d2d473ec77651e001c5f71a23cc2defe7616fd6c6491aa7f9a2bb16b930ce3f8cc37cf6a47bfb04fd4eff7db8433cc6fdb05146a4a31fe65211875f2c51129bf0729ce2dc7ce1a5afc6eaa1eb3a36296cb9e091375edfc408c727f6d54bba408da60b46c496a364c504adf47ee0496a9260fe223c8b23c14832635c3dff0dba8a0c8cdd957a77f18443b7782a9b6c7636b7d66df426350b959537e911888e45b2c0b218e50d03fdcfa7f758e8e60dd1a1996bc00000"
	PrecertEntry = "00000000014b4981f0c800013760e2790f33a498f9b6c149fecfca3993954b536fbf36ad45d0a8415b79337d00047a30820476a00302010202100532298c396a3e25fcaa1977e827b5f3300d06092a864886f70d01010b0500306d310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311f301d060355040b1316464f52205445535420505552504f534553204f4e4c59312530230603550403131c47656f54727573742045562053534c2054455354204341202d204734301e170d3135303230323030303030305a170d3136303232373233353935395a3081c331133011060b2b0601040182373c02010313024742311b3019060b2b0601040182373c020102140a43616c69666f726e6961311e301c060b2b0601040182373c0201010c0d4d6f756e7461696e2056696577310b30090603550406130247423113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e2056696577311d301b060355040a0c1453796d616e74656320436f72706f726174696f6e3116301406035504030c0d736466656473662e747275737430820122300d06092a864886f70d01010105000382010f003082010a0282010100b19d97def39ff829c65ea099a3257298b33ff675451fdc5641a222347aee4a56201f4c1a406f2f19815d86dec1a611768e7d556c8e33a7f1b4c78db19cceae540e97ae1f0660b2ee4f8cff2045b84a9da228349744406eceaed0b08d46fdab3543b3d86ea708627a61a529b793a76adc6b776bc8d5b3d4fe21e2c4aa92cfd33b45e7412068e0683a2beffad1df2fc320b8ddbf02ffb603d2cf74798277fd9656b5acd45659b0e5d761e02dcf95c53095555a931ad5bfa9b4967c045d5f12de2d6b537cd93af2ad8b45e5540bd43279876d13e376fb649778e10dfa56165b901bd37e9dee4e46027b4c0732ca7ed64491862abaf6a24a4aaed8f49a0922ca4fb50203010001a38201d1308201cd30470603551d110440303e820d6b6a61736468662e7472757374820b73736466732e7472757374820d736466656473662e747275737482117777772e736466656473662e747275737430090603551d1304023000300e0603551d0f0101ff0404030205a0302b0603551d1f042430223020a01ea01c861a687474703a2f2f676d2e73796d63622e636f6d2f676d2e63726c3081a00603551d2004819830819530819206092b06010401f0220106308184303f06082b06010505070201163368747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f72792f6c6567616c304106082b0601050507020230350c3368747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f72792f6c6567616c301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d23041830168014b1699461abe6cb0c4ce759af5a498b1833c1e147305706082b06010505070101044b3049301f06082b060105050730018613687474703a2f2f676d2e73796d63642e636f6d302606082b06010505073002861a687474703a2f2f676d2e73796d63622e636f6d2f676d2e6372740000"
)

func TestUnmarshalMerkleTreeLeaf(t *testing.T) {
	var tests = []struct {
		in     string // hex string
		want   LogEntryType
		errstr string
	}{
		{CertEntry, X509LogEntryType, ""},
		{PrecertEntry, PrecertLogEntryType, ""},
		{"001234", 0, "LeafType: unhandled value"},
	}
	for _, test := range tests {
		inData, _ := hex.DecodeString(test.in)
		var got MerkleTreeLeaf
		_, err := tls.Unmarshal(inData, &got)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=%+v,nil; want error %q", test.in, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=nil,%q; want error %q", test.in, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=nil,%q; want type %v", test.in, err.Error(), test.want)
			continue
		}
		if got.Version != V1 {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=version=%v,nil; want version 1", test.in, got.Version)
		}
		if got.LeafType != TimestampedEntryLeafType {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=LeafType=%v,nil; want LeafType=%v", test.in, got.LeafType, TimestampedEntryLeafType)
		}
		if got.TimestampedEntry.EntryType != test.want {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=EntryType=%v,nil; want LeafType=%v", test.in, got.TimestampedEntry.EntryType, test.want)
		}
	}
}

func newVersionedTransType(v VersionedTransType) *VersionedTransType { return &v }

var aHash = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x01, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

func TestUnmarshalMarshalRoundTrip(t *testing.T) {
	var tests = []struct {
		data   string // hex encoded
		params string
		item   interface{}
	}{
		{"00000401020304", "", &ASN1Cert{[]byte{1, 2, 3, 4}}},
		{"00000401020304" + "00000a" + "0000020506" + "0000020708", "",
			&X509ChainEntry{
				LeafCertificate: ASN1Cert{[]byte{1, 2, 3, 4}},
				CertificateChain: []ASN1Cert{
					ASN1Cert{[]byte{5, 6}},
					ASN1Cert{[]byte{7, 8}},
				},
			},
		},
		{"00000401020304" + "000000", "",
			&X509ChainEntry{
				LeafCertificate:  ASN1Cert{[]byte{1, 2, 3, 4}},
				CertificateChain: []ASN1Cert{},
			},
		},
		{"00000401020304", "minlen:1,maxlen:16777215", &CMSPrecert{1, 2, 3, 4}},
		{"00000401020304" + "00000a" + "0000020506" + "0000020708", "",
			&PrecertChainEntryV2{
				PreCertificate: CMSPrecert{1, 2, 3, 4},
				PrecertificateChain: []ASN1Cert{
					ASN1Cert{[]byte{5, 6}},
					ASN1Cert{[]byte{7, 8}},
				},
			},
		},
		{"0009", "maxval:65535", newVersionedTransType(PrecertSCTWithProofV2)},
		{"040a0b0c0d", "minlen:2,maxlen:127", &LogIDV2{0x0a, 0x0b, 0x0c, 0x0d}},
		{"0000000000001001" + "20" + hex.EncodeToString(aHash) + "00000410101111" + "0000", "",
			&TimestampedCertificateEntryDataV2{
				Timestamp:      0x1001,
				IssuerKeyHash:  aHash,
				TBSCertificate: TBSCertificate{16, 16, 17, 17},
				SCTExtensions:  []SCTExtension{},
			},
		},
		{"0001" + "0000000000001001" + "20" + hex.EncodeToString(aHash) + "00000410101111" + "0000", "",
			&TransItem{
				VersionedType: X509EntryV2,
				X509EntryV2Data: &TimestampedCertificateEntryDataV2{
					Timestamp:      0x1001,
					IssuerKeyHash:  aHash,
					TBSCertificate: TBSCertificate{16, 16, 17, 17},
					SCTExtensions:  []SCTExtension{},
				},
			},
		},
		{"0001" + "000401020304", "",
			&SCTExtension{
				SCTExtensionType: 1,
				SCTExtensionData: []byte{1, 2, 3, 4}}},
		{"022a03" + "0000000022112233" + "0000" + "04030001ee", "",
			&SignedCertificateTimestampDataV2{
				LogID:         LogIDV2{0x2a, 0x03},
				Timestamp:     0x22112233,
				SCTExtensions: []SCTExtension{},
				Signature: tls.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,
						Signature: tls.ECDSA},
					Signature: []byte{0xee},
				},
			},
		},
		{"0001" + "000401020304", "",
			&STHExtension{
				STHExtensionType: 1,
				STHExtensionData: []byte{1, 2, 3, 4},
			},
		},
		{"1122334455667788" + "0000000000000100" + "02cafe" + "0000", "",
			&TreeHeadDataV2{
				Timestamp:     0x1122334455667788,
				TreeSize:      0x0100,
				RootHash:      NodeHash{Value: []byte{0xca, 0xfe}},
				STHExtensions: []STHExtension{},
			},
		},
		{"022a03" + ("1122334455667788" + "0000000000000100" + "02cafe" + "0000") + "04030001ee", "",
			&SignedTreeHeadDataV2{
				LogID: LogIDV2{0x2a, 0x03},
				TreeHead: TreeHeadDataV2{
					Timestamp:     0x1122334455667788,
					TreeSize:      0x0100,
					RootHash:      NodeHash{Value: []byte{0xca, 0xfe}},
					STHExtensions: []STHExtension{},
				},
				Signature: tls.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,
						Signature: tls.ECDSA},
					Signature: []byte{0xee},
				},
			},
		},
		{"0005" + "022a03" + ("1122334455667788" + "0000000000000100" + "02cafe" + "0000") + "04030047" + testdata.EcdsaSignedAbcdHex, "",
			&TransItem{
				VersionedType: SignedTreeHeadV2,
				SignedTreeHeadV2Data: &SignedTreeHeadDataV2{
					LogID: LogIDV2{0x2a, 0x03},
					TreeHead: TreeHeadDataV2{
						Timestamp:     0x1122334455667788,
						TreeSize:      0x0100,
						RootHash:      NodeHash{Value: []byte{0xca, 0xfe}},
						STHExtensions: []STHExtension{},
					},
					Signature: tls.DigitallySigned{
						Algorithm: tls.SignatureAndHashAlgorithm{
							Hash:      tls.SHA256,
							Signature: tls.ECDSA},
						Signature: testdata.FromHex(testdata.EcdsaSignedAbcdHex),
					},
				},
			},
		},
	}
	for _, test := range tests {
		inVal := reflect.ValueOf(test.item).Elem()
		pv := reflect.New(reflect.TypeOf(test.item).Elem())
		val := pv.Interface()
		inData, _ := hex.DecodeString(test.data)
		if _, err := tls.UnmarshalWithParams(inData, val, test.params); err != nil {
			t.Errorf("Unmarshal(%s)=nil,%q; want %+v", test.data, err.Error(), inVal)
		} else if !reflect.DeepEqual(val, test.item) {
			t.Errorf("Unmarshal(%s)=%+v,nil; want %+v", test.data, reflect.ValueOf(val).Elem(), inVal)
		}

		if data, err := tls.MarshalWithParams(inVal.Interface(), test.params); err != nil {
			t.Errorf("Marshal(%+v)=nil,%q; want %s", inVal, err.Error(), test.data)
		} else if !bytes.Equal(data, inData) {
			t.Errorf("Marshal(%+v)=%s,nil; want %s", inVal, hex.EncodeToString(data), test.data)
		}
	}
}

func TestLogIDV2FromOID(t *testing.T) {
	var tests = []struct {
		oid    asn1.ObjectIdentifier
		want   string // hex encoded
		errstr string
	}{
		{asn1.ObjectIdentifier{}, "", "invalid object identifier"},
		{asn1.ObjectIdentifier{1, 2, 3}, "2a03", ""},
		{asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9}, "2a03040506070809", ""},
		// 128 values, first 2 get squished into a single byte => len=127, which is OK
		{asn1.ObjectIdentifier{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8},
			"2a030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708", ""},
		{asn1.ObjectIdentifier{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
			1, 2, 3, 4, 5, 6, 7, 8, 9}, "", "too long"},
	}
	for _, test := range tests {
		got, err := LogIDV2FromOID(test.oid)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("LogIDV2FromOID(%v)=%v,nil; want error %q", test.oid, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("LogIDV2FromOID(%v)=nil,%q; want error %q", test.oid, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("LogIDV2FromOID(%v)=nil,%q; want %v", test.oid, err.Error(), test.want)
		} else if hex.EncodeToString(got) != test.want {
			t.Errorf("LogIDV2FromOID(%v)=%q,nil; want %v", test.oid, hex.EncodeToString(got), test.want)
		}
	}
}

func TestOIDFromLogIDV2(t *testing.T) {
	var tests = []struct {
		logID  LogIDV2
		want   asn1.ObjectIdentifier
		errstr string
	}{
		{logID: dehex("2a03"), want: asn1.ObjectIdentifier{1, 2, 3}},
		{
			logID: dehex("2a030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708"),
			want: asn1.ObjectIdentifier{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
				1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			logID: dehex("2a030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"0102030405060708090001020304050607080900" +
				"010203040506070809"),
			errstr: "log ID too long",
		},
		{logID: dehex(""), errstr: "malformed LogIDV2"},
	}
	for _, test := range tests {
		got, err := OIDFromLogIDV2(test.logID)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("OIDFromLogIDV2(%v)=%v,nil; want error %q", test.logID, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("OIDFromLogIDV2(%v)=nil,%q; want error %q", test.logID, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("OIDFromLogIDV2(%v)=nil,%q; want %q", test.logID, err.Error(), test.want)
		} else if !test.want.Equal(got) {
			t.Errorf("OIDFromLogIDV2(%v)=%q,nil; want %q", test.logID, got, test.want)
		}
	}
}

type testTransItemHolder struct {
	Val TransItem `json:"val"`
}

func TestJSONUnmarshalTransItem(t *testing.T) {
	var tests = []struct {
		json   string
		item   TransItem
		errstr string
	}{
		{json: bv64("0001" + "0000000000001001" + "20" + hex.EncodeToString(aHash) + "00000410101111" + "0000"),
			item: TransItem{
				VersionedType: X509EntryV2,
				X509EntryV2Data: &TimestampedCertificateEntryDataV2{
					Timestamp:      0x1001,
					IssuerKeyHash:  aHash,
					TBSCertificate: TBSCertificate{16, 16, 17, 17},
					SCTExtensions:  []SCTExtension{},
				},
			},
		},
		// Extra keys can be present in the JSON but are ignored.
		{json: fmt.Sprintf("{\"val\":\"%s\",\"extra\":\"%s\"}",
			b64("0001"+"0000000000001001"+"20"+hex.EncodeToString(aHash)+"00000410101111"+"0000"),
			b64("01020304")),
			item: TransItem{
				VersionedType: X509EntryV2,
				X509EntryV2Data: &TimestampedCertificateEntryDataV2{
					Timestamp:      0x1001,
					IssuerKeyHash:  aHash,
					TBSCertificate: TBSCertificate{16, 16, 17, 17},
					SCTExtensions:  []SCTExtension{},
				},
			},
		},
		{json: `{"val": "not base 64 encoded"}`, errstr: "failed to unbase64"},
		{json: `{"val": 99}`, errstr: "failed to json.Unmarshal"},
		{json: `{"val": "abcd"}`, errstr: "failed to tls.Unmarshal"},
		{json: bv64("0001" + "0000000000001001" + "20" + hex.EncodeToString(aHash) + "00000410101111" + "0000eeff"), errstr: "trailing data"},
	}
	for _, test := range tests {
		var item testTransItemHolder
		err := json.Unmarshal([]byte(test.json), &item)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("json.Unmarshal('%s')=%+v,nil; want error %q", test.json, item, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("json.Unmarshal('%s')=nil,%q; want error %q", test.json, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("json.Unmarshal('%s')=nil,%q; want %v", test.json, err.Error, test.item)
		} else if !reflect.DeepEqual(item.Val, test.item) {
			t.Errorf("json.Unmarshal('%s')=%v,nil; want %v", test.json, item, test.item)
		}
	}
}

func TestJSONMarshalTransItem(t *testing.T) {
	var tests = []struct {
		item   TransItem
		json   string
		errstr string
	}{
		{
			item: TransItem{
				VersionedType: X509EntryV2,
				X509EntryV2Data: &TimestampedCertificateEntryDataV2{
					Timestamp:      0x1001,
					IssuerKeyHash:  aHash,
					TBSCertificate: TBSCertificate{16, 16, 17, 17},
					SCTExtensions:  []SCTExtension{},
				},
			},
			json: bv64("0001" + "0000000000001001" + "20" + hex.EncodeToString(aHash) + "00000410101111" + "0000"),
		},
		{
			item: TransItem{
				VersionedType: 99,
				X509EntryV2Data: &TimestampedCertificateEntryDataV2{
					Timestamp:      0x1001,
					IssuerKeyHash:  aHash,
					TBSCertificate: TBSCertificate{16, 16, 17, 17},
					SCTExtensions:  []SCTExtension{},
				},
			},
			errstr: "unchosen field is non-nil",
		},
		{item: TransItem{VersionedType: 99}, errstr: "unhandled value for selector"},
		{item: TransItem{VersionedType: X509EntryV2}, errstr: "chosen field is nil"},
	}
	for _, test := range tests {
		var item testTransItemHolder
		item.Val = test.item
		data, err := json.Marshal(item)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("json.Marshal(%+v)=%s,nil; want error %q", test.item, hex.EncodeToString(data), test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("json.Marshal(%+v)=nil,%q; want error %q", test.item, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("json.Marshal(%+v)=nil,%q; want %s", test.item, err.Error(), test.json)
		} else if string(data) != test.json {
			t.Errorf("json.Marshal(%+v)=%s,nil; want %s", test.item, data, test.json)
		}
	}
}

var dehex = testdata.FromHex

func b64(hexData string) string {
	return base64.StdEncoding.EncodeToString(dehex(hexData))
}

func bv64(hexData string) string {
	return fmt.Sprintf(`{"val":"%s"}`, b64(hexData))
}
