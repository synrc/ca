using System;

namespace UA.Cryptography.EC
{
	public abstract class ECPoint
	{
		internal readonly ECCurve			curve;
		internal readonly ECFieldElement	x, y;
		internal readonly bool				withCompression;

		protected internal ECPoint(
			ECCurve			curve,
			ECFieldElement	x,
			ECFieldElement	y,
			bool			withCompression)
		{
			if (curve == null)
				throw new ArgumentNullException("curve");

			this.curve = curve;
			this.x = x;
			this.y = y;
			this.withCompression = withCompression;
		}

		public ECCurve Curve
		{
			get { return curve; }
		}

		public ECFieldElement X
		{
			get { return x; }
		}

		public ECFieldElement Y
		{
			get { return y; }
		}

		public bool IsInfinity
		{
			get { return x == null && y == null; }
		}

		public bool IsCompressed
		{
			get { return withCompression; }
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			ECPoint o = obj as ECPoint;

			if (o == null)
				return false;

			if (this.IsInfinity)
				return o.IsInfinity;

			return x.Equals(o.x) && y.Equals(o.y);
		}

		public override int GetHashCode()
		{
			if (this.IsInfinity)
				return 0;

			return x.GetHashCode() ^ y.GetHashCode();
		}


		public abstract ECPoint Add(ECPoint b);
		public abstract ECPoint Subtract(ECPoint b);
		public abstract ECPoint Negate();
		public abstract ECPoint Twice();
		public abstract ECPoint Multiply(BigInteger b);

	}

	public class F2mPoint
        : ECPoint
	{
		public F2mPoint(
			ECCurve			curve,
			ECFieldElement	x,
			ECFieldElement	y)
			:  this(curve, x, y, false)
		{
		}

		public F2mPoint(
			ECCurve			curve,
			ECFieldElement	x,
			ECFieldElement	y,
			bool			withCompression)
			: base(curve, x, y, withCompression)
		{
			if ((x != null && y == null) || (x == null && y != null))
			{
				throw new ArgumentException("Exactly one of the field elements is null");
			}

			if (x != null)
			{
				F2mFieldElement.CheckFieldElements(this.x, this.y);
				F2mFieldElement.CheckFieldElements(this.x, this.curve.A);
			}
		}

		[Obsolete("Use ECCurve.Infinity property")]
		public F2mPoint(
			ECCurve curve)
			: this(curve, null, null)
		{
		}

        public override ECPoint Multiply(
            BigInteger k)
        {
            if (this.IsInfinity)
                return this;

            if (k.SignValue == 0)
                return this.curve.Infinity;

            return Multiply(this, k);
        }

        public ECPoint Multiply(ECPoint p, BigInteger k)
        {
            // TODO Probably should try to add this
            //BigInteger e = k.Mod(new BigInteger("173", 10)); // n == order of p

            ECPoint r = Curve.Infinity;

            for (int t = k.BitLength - 1; t >= 0; --t)
            {
                r = r.Twice();

                if (k.TestBit(t))
                    r = r.Add(p);
            }

            return r;



            //BigInteger e = k;
            //BigInteger h = e.Multiply(BigInteger.Three);

            //ECPoint neg = p.Negate();
            //ECPoint R = p;

            //for (int i = h.BitLength - 2; i > 0; --i)
            //{
            //    R = R.Twice();

            //    bool hBit = h.TestBit(i);
            //    bool eBit = e.TestBit(i);

            //    if (hBit != eBit)
            //    {
            //        R = R.Add(hBit ? p : neg);
            //    }
            //}

            //return R;
        }

		protected internal bool YTilde
		{
			get
			{
				return this.X.ToBigInteger().SignValue != 0
					&& this.Y.Multiply(this.X.Invert()).ToBigInteger().TestBit(0);
			}
		}

		private static void CheckPoints(
			ECPoint	a,
			ECPoint	b)
		{
			if (!a.curve.Equals(b.curve))
				throw new ArgumentException("Only points on the same curve can be added or subtracted");
		}

		public override ECPoint Add(ECPoint b)
		{
			CheckPoints(this, b);
			return AddSimple((F2mPoint) b);
		}

		internal F2mPoint AddSimple(F2mPoint b)
		{
			if (this.IsInfinity)
				return b;

			if (b.IsInfinity)
				return this;

			F2mFieldElement x2 = (F2mFieldElement) b.X;
			F2mFieldElement y2 = (F2mFieldElement) b.Y;

			if (this.x.Equals(x2))
			{
				if (this.y.Equals(y2))
					return (F2mPoint) this.Twice();

				return (F2mPoint) this.curve.Infinity;
			}

			ECFieldElement xSum = this.x.Add(x2);

			F2mFieldElement lambda
				= (F2mFieldElement)(this.y.Add(y2)).Divide(xSum);

			F2mFieldElement x3
				= (F2mFieldElement)lambda.Square().Add(lambda).Add(xSum).Add(this.curve.A);

			F2mFieldElement y3
				= (F2mFieldElement)lambda.Multiply(this.x.Add(x3)).Add(x3).Add(this.y);

			return new F2mPoint(curve, x3, y3, withCompression);
		}

		public override ECPoint Subtract(
			ECPoint b)
		{
			CheckPoints(this, b);
			return SubtractSimple((F2mPoint) b);
		}

		internal F2mPoint SubtractSimple(
			F2mPoint b)
		{
			if (b.IsInfinity)
				return this;

			return AddSimple((F2mPoint) b.Negate());
		}

		public override ECPoint Twice()
		{
			if (this.IsInfinity)
				return this;

			if (this.x.ToBigInteger().SignValue == 0)
				return this.curve.Infinity;

			F2mFieldElement lambda = (F2mFieldElement) this.x.Add(this.y.Divide(this.x));
			F2mFieldElement x2 = (F2mFieldElement)lambda.Square().Add(lambda).Add(this.curve.A);
			ECFieldElement ONE = this.curve.FromBigInteger(BigInteger.One);
			F2mFieldElement y2 = (F2mFieldElement)this.x.Square().Add(
				x2.Multiply(lambda.Add(ONE)));

			return new F2mPoint(this.curve, x2, y2, withCompression);
		}

		public override ECPoint Negate()
		{
			return new F2mPoint(curve, this.x, this.x.Add(this.y), withCompression);
		}
	}
}
