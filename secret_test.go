package multikey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodePEM(t *testing.T) {
	// TODO
}

func TestDecodePEM(t *testing.T) {
	// TODO
}

func TestEncodeSimple(t *testing.T) {
	// TODO
}

func TestDecodeSimple(t *testing.T) {
	// TODO
}

func TestEncodeDecodePEM(t *testing.T) {
	tests := []struct {
		testName      string
		testSecret    *Secret
		expectErr     bool
		expectedError string
	}{
		{
			testName: "positive test",
			testSecret: &Secret{
				shards: []*encryptedShard{
					{
						KeyID: "some key id",
						Value: "asdfghjkl",
					},
					{
						KeyID: "some key id",
						Value: "asdfghjkl",
					},
				},
			},
			expectErr: false,
		},
		{
			testName: "positive test helper",
			testSecret: &Secret{
				shards: []*encryptedShard{
					{
						KeyID:  "some key id",
						Value:  "asdfghjkl",
						Helper: "asdfghjkl",
					},
				},
			},
			expectErr: false,
		},
	}

	for _, test := range tests {
		enc, err := test.testSecret.EncodePEM()
		if test.expectErr {
			assert.EqualError(t, err, test.expectedError, test.testName)
			continue
		}
		dec, err := DecodePEM(enc)
		if test.expectErr {
			assert.EqualError(t, err, test.expectedError, test.testName)
			continue
		}
		assert.EqualValues(t, dec, test.testSecret, test.testName)
	}
}
