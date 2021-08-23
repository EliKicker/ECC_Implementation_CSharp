using ECC_Implementation.encryptionmethods;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace ECC_Implementation
{
    class ECC
    {

        BigInteger p, a, b, Gx, Gy, n, h;

        public ECC(EncryptionMethod m)
        {
            BigInteger[] cnfg = m.getConfig();
            p = cnfg[0];
            a = cnfg[1];
            b = cnfg[2];
            Gx = cnfg[3];
            Gy = cnfg[4];
            n = cnfg[5];
            h = cnfg[6];
        }

        public BigInteger[] genKeys()
        {
            BigInteger[] output = new BigInteger[3];

            output[0] = genPrivateKey();

            BigInteger[] P = point_mult(output[0], new BigInteger[] { Gx, Gy });
            output[1] = P[0];
            output[2] = P[1];
            return output;
        }

        private BigInteger genPrivateKey()
        {
            Random r = new Random();
            BigInteger max = n;
            BigInteger min = BigInteger.Parse("2");
            BigInteger range = max - min;
            int len = (int)max.GetByteCount();
            byte[] data = new byte[len];
            r.NextBytes(data);
            BigInteger output = new BigInteger(data);
            return Euklidian_mod(BigInteger.Add(output, min), p);
        }

        public BigInteger[] point_mult(BigInteger private_key, BigInteger[] G)
        {
            BigInteger[] res = null;
            List<int> i = new List<int>();
            var s = ToBinaryString(private_key);

            for (int j = 0; j < s.Length; j++)
            {
                i.Add(int.Parse(s[j].ToString()));
            }
            
            foreach (int bit in i)
            {
                res = point_add(res, res);
                
                if (bit == 1)
                {
                    res = point_add(res, G);
                }
            }
            return res;
        }

        private BigInteger[] point_add(BigInteger[] P1, BigInteger[] P2)
        {
            if (P1 == null)
            {
                return P2;
            }

            if (P2 == null)
            {
                return P1;
            }

            BigInteger P1x = P1[0];
            BigInteger P1y = P1[1];
            BigInteger P2x = P2[0];
            BigInteger P2y = P2[1];

            if (P1x.CompareTo(P2x) == 0 && P1y.CompareTo(P2y) != 0)
            {
                return null;
            }

            BigInteger s;
            if (P1x.CompareTo(P2x) == 0)
            {
                s = Euklidian_mod(BigInteger.Multiply(BigInteger.Add(BigInteger.Multiply(BigInteger.Pow(P1x, 2), BigInteger.Parse("3")), a), mod_inv(BigInteger.Multiply(P1y, BigInteger.Parse("2")), p)[1]), p);
            }
            else
            {
                s = Euklidian_mod(BigInteger.Multiply(BigInteger.Subtract(P1y, P2y), mod_inv(BigInteger.Subtract(P1x, P2x), p)[1]), p);
            }

            BigInteger[] output = new BigInteger[2];

            output[0] = Euklidian_mod(BigInteger.Subtract(BigInteger.Subtract(BigInteger.Pow(s, 2), P1x), P2x), p);
            output[1] = Euklidian_mod(BigInteger.Subtract(BigInteger.Multiply(s, BigInteger.Subtract(P1x, output[0])), P1y), p);
            return output;
        }

        private string ToBinaryString(BigInteger num)
        {
            StringBuilder output = new StringBuilder();
            int i = 0;
            BigInteger TWO = BigInteger.Parse("2");

            while (num.CompareTo(BigInteger.Zero) > 0)
            {
                if (BigInteger.ModPow(num, 1, 2).CompareTo(BigInteger.One) == 0)
                {
                    output.Append("1");
                    num = BigInteger.Divide(BigInteger.Subtract(num, BigInteger.One), TWO);
                }
                else
                {
                    output.Append("0");
                    num = BigInteger.Divide(num, TWO);
                }
                i++;
            }

            char[] chrs = output.ToString().ToCharArray();
            Array.Reverse(chrs);
            return new string(chrs);
        }

        private BigInteger Euklidian_mod(BigInteger a, BigInteger b)
        {
            BigInteger m = BigInteger.ModPow(a, 1, b);

            if (m.Sign == -1)
            {
                m = (b.Sign == -1) ? BigInteger.Subtract(m, b) : BigInteger.Add(m, b);
            }
            return m;
        }

        private BigInteger[] mod_inv(BigInteger a, BigInteger b)
        {
            if (b.CompareTo(BigInteger.Zero) == 0) return new BigInteger[]
            {
                a, BigInteger.One, BigInteger.Zero
            };

            BigInteger[] vals = mod_inv(b, Euklidian_mod(a, b));
            BigInteger d = vals[0];
            BigInteger p = vals[2];
            BigInteger q = BigInteger.Subtract(vals[1], BigInteger.Multiply(BigInteger.Divide(a, b), vals[2]));

            return new BigInteger[]
            {
                d, p, q
            };
        }
    }
}
