using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class brainpoolP160r1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0e95e4a5f737059dc60dfc7ad95b3d8139515620f", NumberStyles.HexNumber);
        BigInteger a = BigInteger.Parse("0340e7be2a280eb74e2be61bada745d97e8f7c300", NumberStyles.HexNumber);
        BigInteger b = BigInteger.Parse("01e589a8595423412134faa2dbdec95c8d8675e58", NumberStyles.HexNumber);
        BigInteger Gx = BigInteger.Parse("0bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3", NumberStyles.HexNumber);
        BigInteger Gy = BigInteger.Parse("01667cb477a1a8ec338f94741669c976316da6321", NumberStyles.HexNumber);
        BigInteger n = BigInteger.Parse("0e95e4a5f737059dc60df5991d45029409e60fc09", NumberStyles.HexNumber);
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
