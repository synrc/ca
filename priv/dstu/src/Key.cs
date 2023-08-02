using UA.Cryptography;
using UA.Cryptography.EC;
using UA.Cryptography.Internal;

namespace UA.Cryptography
{
    public class Key
    {
        public F2mCurve Curve { get; private set; }
        public F2mPoint BasePoint { get; private set; }
        public F2mPoint PublicKey { get; private set; }
        public BigInteger PrivateKey { get; private set; }

        public Key(F2mCurve curve, F2mPoint basePoint, F2mPoint publicKey, BigInteger priveteKey)
        {
            PublicKey = publicKey;
            PrivateKey = priveteKey;
            BasePoint = basePoint;
            Curve = curve;
        }

        public Key(F2mCurve curve, F2mPoint basePoint, F2mPoint publicKey)
        {
            PublicKey = publicKey;
            BasePoint = basePoint;
            Curve = curve;
        }

        public static Key Generate(F2mCurve curve)
        {
            var basePoint = computeBasePoint(curve);

            var privateKey = RNG.GetRandomInteger(curve.M);

            var p1 = basePoint.Negate();
            var publicKey = (F2mPoint)p1.Multiply(privateKey);

            return new Key(curve, basePoint, publicKey, privateKey);
        }

        static F2mPoint computeBasePoint(F2mCurve curve)
        {
            while (true)
            {
                var p = computeRandomPoint(curve);
                var n = curve.N;
                var r = p.Multiply(n);

                if (r.X != null || r.Y != null)
                    continue;

                return p;
            }
        }

        static F2mPoint computeRandomPoint(F2mCurve curve)
        {
            BigInteger u = RNG.GetRandomInteger(curve.M);
            var u__element = new F2mFieldElement(curve.M, curve.K1, curve.K2, curve.K3, u);
            var a__element = new F2mFieldElement(curve.M, curve.K1, curve.K2, curve.K3, curve.A.ToBigInteger());
            var b__element = new F2mFieldElement(curve.M, curve.K1, curve.K2, curve.K3, curve.B.ToBigInteger());

            var au__element = u__element.Multiply(u__element).Multiply(a__element);
            var w__element = u__element.Multiply(u__element).Multiply(u__element).Add(au__element).Add(b__element);
            var z__element = quadraticEquation(curve, u__element.ToBigInteger(), w__element.ToBigInteger());
            var point = new F2mPoint(curve, u__element, z__element);

            return point;
        }

        static F2mFieldElement quadraticEquation(F2mCurve curve, BigInteger u, BigInteger w)
        {
            var w__element = new F2mFieldElement(curve.M, curve.K1, curve.K2, curve.K3, w);
            var u__element = new F2mFieldElement(curve.M, curve.K1, curve.K2, curve.K3, u);
            var u2__element = u__element.Invert().Square();
            var v = (F2mFieldElement)w__element.Multiply(u2__element);
            var tr__element = trace(v);
            var t__element = halfTrace(v);
            var z__element = (F2mFieldElement)t__element.Multiply(u__element);
            return z__element;
        }

        static F2mFieldElement trace(F2mFieldElement x)
        {
            F2mFieldElement t = x;

            for (int i = 1; i < x.M; i++)
            {
                t = (F2mFieldElement)t.Square().Add(x);
            }

            return t;
        }

        static F2mFieldElement halfTrace(F2mFieldElement x)
        {
            F2mFieldElement t = x;

            for (int i = 1; i <= ((x.M - 1) / 2); i++)
            {
                t = (F2mFieldElement)t.Square().Square().Add(x);
            }

            return t;
        }
    }
}
