using System;
using System.Security.Cryptography;
using UA.Cryptography;

namespace UA.Cryptography.Internal
{
    public static class RNG
    {
        public static BigInteger GetRandomInteger(int m)
        {
            var b = new byte[(m + 7) / 8 + 10];
            var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            rngCryptoServiceProvider.GetBytes(b);

            // Ой ужас, нужно обязательно исправить это позорище!!!
            var bi = new BigInteger(b);
            string s = bi.ToString(2);
            s = s.TrimStart('-');
            s = s.Substring(0, m);

            var res = new BigInteger(s, 2);

            return res;
        }
    }
}
