using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class secp256k1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", NumberStyles.HexNumber);
        BigInteger a = BigInteger.Parse("00000000000000000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        BigInteger b = BigInteger.Parse("00000000000000000000000000000000000000000000000000000000000000007", NumberStyles.HexNumber);
        BigInteger Gx = BigInteger.Parse("079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", NumberStyles.HexNumber);
        BigInteger Gy = BigInteger.Parse("0483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", NumberStyles.HexNumber);
        BigInteger n = BigInteger.Parse("0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", NumberStyles.HexNumber);
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
