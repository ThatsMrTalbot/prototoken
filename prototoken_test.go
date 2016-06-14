package prototoken

import (
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
	})
}
