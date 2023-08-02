using System;

namespace UA.Cryptography.EC
{
	public abstract class ECCurve
	{
		internal ECFieldElement a, b;

		public abstract int FieldSize { get; }
		public abstract ECFieldElement FromBigInteger(BigInteger x);
		public abstract ECPoint CreatePoint(BigInteger x, BigInteger y, bool withCompression);
		public abstract ECPoint Infinity { get; }

		public ECFieldElement A
		{
			get { return a; }
		}

		public ECFieldElement B
		{
			get { return b; }
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			ECCurve other = obj as ECCurve;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			ECCurve other)
		{
			return a.Equals(other.a) && b.Equals(other.b);
		}

		public override int GetHashCode()
		{
			return a.GetHashCode() ^ b.GetHashCode();
		}
	}

    public class F2mCurve : ECCurve
    {
        private readonly int m;
        private readonly int k1;
        private readonly int k2;
        private readonly int k3;
		private BigInteger n;
		private readonly BigInteger h;
		private readonly F2mPoint infinity;
		private sbyte mu = 0;
		private BigInteger[] si = null;

		public F2mCurve(
			int			m,
			int			k,
			BigInteger	a,
			BigInteger	b)
			: this(m, k, 0, 0, a, b, null, null)
		{
		}

		public F2mCurve(
			int			m, 
			int			k, 
			BigInteger	a, 
			BigInteger	b,
			BigInteger	n,
			BigInteger	h)
			: this(m, k, 0, 0, a, b, n, h)
		{
		}

		public F2mCurve(
			int			m,
			int			k1,
			int			k2,
			int			k3,
			BigInteger	a,
			BigInteger	b)
			: this(m, k1, k2, k3, a, b, null, null)
		{
		}

		public F2mCurve(
			int			m, 
			int			k1, 
			int			k2, 
			int			k3,
			BigInteger	a, 
			BigInteger	b,
			BigInteger	n,
			BigInteger	h)
		{
			this.m = m;
			this.k1 = k1;
			this.k2 = k2;
			this.k3 = k3;
			this.n = n;
			this.h = h;
			this.infinity = new F2mPoint(this, null, null);

			if (k1 == 0)
                throw new ArgumentException("k1 must be > 0");

			if (k2 == 0)
            {
                if (k3 != 0)
                    throw new ArgumentException("k3 must be 0 if k2 == 0");
            }
            else
            {
                if (k2 <= k1)
                    throw new ArgumentException("k2 must be > k1");

				if (k3 <= k2)
                    throw new ArgumentException("k3 must be > k2");
            }

			this.a = FromBigInteger(a);
            this.b = FromBigInteger(b);
        }

		public override ECPoint Infinity
		{
			get { return infinity; }
		}

		public override int FieldSize
		{
			get { return m; }
		}

		public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new F2mFieldElement(this.m, this.k1, this.k2, this.k3, x);
        }

		public override ECPoint CreatePoint(
			BigInteger	X1,
			BigInteger	Y1,
			bool		withCompression)
		{
			// TODO Validation of X1, Y1?
			return new F2mPoint(
				this,
				FromBigInteger(X1),
				FromBigInteger(Y1),
				withCompression);
		}

		public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

			F2mCurve other = obj as F2mCurve;

			if (other == null)
                return false;

			return Equals(other);
        }

		protected bool Equals(
			F2mCurve other)
		{
			return m == other.m
				&& k1 == other.k1
				&& k2 == other.k2
				&& k3 == other.k3
				&& base.Equals(other);
		}

		public override int GetHashCode()
        {
            return base.GetHashCode() ^ m ^ k1 ^ k2 ^ k3;
        }

		public int M
        {
			get { return m; }
        }

        public bool IsTrinomial()
        {
            return k2 == 0 && k3 == 0;
        }

		public int K1
        {
			get { return k1; }
        }

		public int K2
        {
			get { return k2; }
        }

		public int K3
        {
			get { return k3; }
        }

		public BigInteger N
		{
			get { return n; }
            set { n = value; }
		}

		public BigInteger H
		{
			get { return h; }
		}
	}
}
