using System;
using UA.Cryptography;
using UA.Cryptography.EC;
using UA.Cryptography.Internal;

namespace UA.Cryptography
{
    public sealed class Signer
    {
        private F2mFieldElement _fe;
        private BigInteger _e;

        private Key _key;

        public Signer(Key key)
        {
            if (null == key)
                throw new ArgumentNullException("key");

            _key = key;
        }

        public BigInteger[] SignHash(BigInteger h)
        {
            if (null == _key.PrivateKey)
                throw new InvalidOperationException("null == _key.PrivateKey");

            computePreSignature();

            var h__element = new F2mFieldElement(_key.Curve.M, _key.Curve.K1, _key.Curve.K2, _key.Curve.K3, h);

            var r = h__element.Multiply(_fe).ToBigInteger();
            var s = _key.PrivateKey.Multiply(r).Add(_e).Mod(_key.Curve.N);

            return new[] { s, r };
        }

        public bool verifySignature(BigInteger h, BigInteger s, BigInteger r)
        {
            var sP = _key.BasePoint.Multiply(s);
            var rQ = _key.PublicKey.Multiply(r);

            var r__ = sP.Add(rQ);

            var h__element = new F2mFieldElement(_key.Curve.M, _key.Curve.K1, _key.Curve.K2, _key.Curve.K3, h);

            var y2 = h__element.Multiply(r__.X);

            if (y2.ToBigInteger().Equals(r))
                return true;

            return false;
        }

        public void computePreSignature()
        {
            while (true)
            {
                var e = RNG.GetRandomInteger(_key.Curve.M);
                var r = _key.BasePoint.Multiply(e);

                if (0 != r.X.ToBigInteger().SignValue)
                {
                    _fe = (F2mFieldElement)r.X;
                    _e = e;
                    break;
                }
            }
        }
    }
}
