defmodule CA.KnownCurves do
  require CA.Curve
  require CA.Point

  @secp384r1 {1, 3, 132, 0, 34}
  @secp256k1 {1, 3, 132, 0, 10}
  @prime256v1 {1, 2, 840, 10045, 3, 1, 7}
  @secp384r1name :secp384r1
  @secp256k1name :secp256k1
  @prime256v1name :prime256v1

  def getCurveByOid(oid) do
    case oid do
      @secp256k1 -> secp256k1()
      @secp384r1 -> secp384r1()
      @prime256v1 -> prime256v1()
    end
  end

  def getCurveByName(name) do
    case name do
      @secp256k1name -> secp256k1()
      @secp384r1name -> secp384r1()
      @prime256v1name -> prime256v1()
    end
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
