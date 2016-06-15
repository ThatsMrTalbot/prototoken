package prototoken

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/ThatsMrTalbot/prototoken/pb"
	. "github.com/smartystreets/goconvey/convey"
)

func TestToken(t *testing.T) {
	Convey("Given a token", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		expected := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}

		token, err := GenerateToken(expected, private)
		So(err, ShouldBeNil)

		Convey("When a token is validated with the correct key", func() {
			public := NewHMACPublicKey([]byte("SomeSecretKey"))
			result := new(pb.ExampleToken)
			err := ValidateToken(token, public, result)

			Convey("Then the token should be valid", func() {
				So(err, ShouldBeNil)
				So(result, ShouldResemble, expected)
			})
		})

		Convey("When a token is validated with the incorrect key", func() {
			public := NewHMACPublicKey([]byte("InvalidKey"))
			result := new(pb.ExampleToken)
			err := ValidateToken(token, public, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token is validated with a nil key", func() {
			result := new(pb.ExampleToken)
			err := ValidateToken(token, nil, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil key", t, func() {
		value := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}
		Convey("When a token is generated", func() {
			_, err := GenerateToken(value, nil)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil value", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		Convey("When a token is generated", func() {
			_, err := GenerateToken(nil, private)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestTokenString(t *testing.T) {
	Convey("Given a token string", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		expected := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}

		token, err := GenerateString(expected, private)
		So(err, ShouldBeNil)

		Convey("When a token is validated with the correct key", func() {
			result := new(pb.ExampleToken)
			public := NewHMACPublicKey([]byte("SomeSecretKey"))
			_, err := ValidateString(token, public, result)

			Convey("Then the token should be valid", func() {
				So(err, ShouldBeNil)
				So(result, ShouldResemble, expected)
			})
		})

		Convey("When a token is validated with the incorrect key", func() {
			public := NewHMACPublicKey([]byte("InvalidKey"))
			result := new(pb.ExampleToken)
			_, err := ValidateString(token, public, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token is validated with a nil key", func() {
			result := new(pb.ExampleToken)
			_, err := ValidateString(token, nil, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil key", t, func() {
		value := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}
		Convey("When a string token is generated", func() {
			_, err := GenerateString(value, nil)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil value", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		Convey("When a string token is generated", func() {
			_, err := GenerateString(nil, private)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given an invalid token string", t, func() {
		public := NewHMACPublicKey([]byte("SomeSecretKey"))

		Convey("When a token is validated", func() {
			result := new(pb.ExampleToken)
			_, err := ValidateString("INVALID STRING", public, result)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestTokenBytes(t *testing.T) {
	Convey("Given token bytes", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		expected := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}

		token, err := GenerateBytes(expected, private)
		So(err, ShouldBeNil)

		Convey("When a token is validated with the correct key", func() {
			result := new(pb.ExampleToken)
			public := NewHMACPublicKey([]byte("SomeSecretKey"))
			_, err := ValidateBytes(token, public, result)

			Convey("Then the token should be valid", func() {
				So(err, ShouldBeNil)
				So(result, ShouldResemble, expected)
			})
		})

		Convey("When a token is validated with the incorrect key", func() {
			public := NewHMACPublicKey([]byte("InvalidKey"))
			result := new(pb.ExampleToken)
			_, err := ValidateBytes(token, public, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When a token is validated with a nil key", func() {
			result := new(pb.ExampleToken)
			_, err := ValidateBytes(token, nil, result)

			Convey("Then the token should not be valid", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil key", t, func() {
		value := &pb.ExampleToken{
			Some:    "abc",
			Example: 123,
			Values:  true,
		}
		Convey("When a byte token is generated", func() {
			_, err := GenerateBytes(value, nil)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a nil value", t, func() {
		private := NewHMACPrivateKey([]byte("SomeSecretKey"))
		Convey("When a byte token is generated", func() {
			_, err := GenerateBytes(nil, private)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given invalid token bytes", t, func() {
		public := NewHMACPublicKey([]byte("SomeSecretKey"))

		Convey("When a token is validated", func() {
			result := new(pb.ExampleToken)
			_, err := ValidateBytes([]byte("INVALID STRING"), public, result)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestRSA(t *testing.T) {
	Convey("Given an RSA private key", t, func() {
		key, err := rsa.GenerateKey(rand.Reader, 512)
		So(err, ShouldBeNil)

		private := NewRSAPrivateKey(key)

		Convey("When signing a byte slice", func() {
			data := make([]byte, 20)

			_, err := rand.Reader.Read(data)
			So(err, ShouldBeNil)

			sig, err := private.Generate(data)
			So(err, ShouldBeNil)

			Convey("The signature should be valid", func() {
				public := NewRSAPublicKey(&key.PublicKey)
				err := public.Validate(data, sig)
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given a small RSA private key", t, func() {
		key, err := rsa.GenerateKey(rand.Reader, 100)
		So(err, ShouldBeNil)

		private := NewRSAPrivateKey(key)

		Convey("When signing a byte slice", func() {
			data := make([]byte, 20)

			_, err := rand.Reader.Read(data)
			So(err, ShouldBeNil)

			_, err = private.Generate(data)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestCompare(t *testing.T) {
	Convey("Given byte slices with the same data", t, func() {
		d1, d2 := []byte("some_data"), []byte("some_data")
		Convey("When compared", func() {
			match := (&hmacKey{}).compareSlice(d1, d2)
			Convey("Then the slices should match", func() {
				So(match, ShouldBeTrue)
			})
		})
	})

	Convey("Given byte slices with different data", t, func() {
		d1, d2 := []byte("some_data"), []byte("some_other_data")
		Convey("When compared", func() {
			match := (&hmacKey{}).compareSlice(d1, d2)
			Convey("Then the slices should not match", func() {
				So(match, ShouldBeFalse)
			})
		})
	})
}
