using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class brainpoolP224r1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", NumberStyles.HexNumber);
        BigInteger a = BigInteger.Parse("068a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43", NumberStyles.HexNumber);
        BigInteger b = BigInteger.Parse("02580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b", NumberStyles.HexNumber);
        BigInteger Gx = BigInteger.Parse("0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d", NumberStyles.HexNumber);
        BigInteger Gy = BigInteger.Parse("058aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd", NumberStyles.HexNumber);
        BigInteger n = BigInteger.Parse("0d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", NumberStyles.HexNumber);
        BigInteger h = BigInteger.Parse("01", NumberStyles.HexNumber);

        public BigInteger[] getConfig()
        {
            return new BigInteger[] { p, a, b, Gx, Gy, n, h };
        }

        public Hash getHash()
        {
            return new SHA256();
        }
    }
}
