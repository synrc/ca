defmodule CA.KnownCurves do
  @moduledoc "CA/ECC library."
  require CA.Curve
  require CA.Point

  @secp256k1 {1, 3, 132, 0, 10}
  @secp384r1 {1, 3, 132, 0, 34}
  @secp521r1 {1, 3, 132, 0, 35}
  @prime256v1 {1, 2, 840, 10045, 3, 1, 7}
  @secp521r1name :secp521r1 
  @secp384r1name :secp384r1
  @secp256k1name :secp256k1
  @prime256v1name :prime256v1

  def getCurveByOid(oid) do
    case oid do
      @secp256k1 -> secp256k1()
      @secp384r1 -> secp384r1()
      @secp521r1 -> secp521r1()
      @prime256v1 -> prime256v1()
    end
  end

  def getCurveByName(name) do
    case name do
      @secp256k1name -> secp256k1()
      @secp384r1name -> secp384r1()
      @secp521r1name -> secp521r1()
      @prime256v1name -> prime256v1()
    end
  end

  def secp521r1() do
    %CA.Curve{
      name: @secp256k1name,
      A: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      B: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf,
      P: 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
      N: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b,
      G: %CA.Point{
        x: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        y: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7
      },
      oid: @secp521r1
    }
  end

  def secp256k1() do
    %CA.Curve{
      name: @secp256k1name,
      A: 0x0000000000000000000000000000000000000000000000000000000000000000,
      B: 0x0000000000000000000000000000000000000000000000000000000000000007,
      P: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
      N: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      G: %CA.Point{
        x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
      },
      oid: @secp256k1
    }
  end

  def prime256v1() do
    %CA.Curve{
      name: @prime256v1name,
      A: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
      B: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
      P: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
      N: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
      G: %CA.Point{
        x: 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        y: 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
      },
      oid: @prime256v1
    }
  end

  def secp384r1() do
    %CA.Curve{
      name: @secp384r1name,
      A: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
      B: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
      P: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
      N: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
      G: %CA.Point{
        x: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        y: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
      },
      oid: @secp384r1
    }
  end
end
