using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class secp256r1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", NumberStyles.AllowHexSpecifier);
        BigInteger a = BigInteger.Parse("0ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", NumberStyles.AllowHexSpecifier);
        BigInteger b = BigInteger.Parse("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", NumberStyles.AllowHexSpecifier);
        BigInteger Gx = BigInteger.Parse("06b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", NumberStyles.AllowHexSpecifier);
        BigInteger Gy = BigInteger.Parse("04fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", NumberStyles.AllowHexSpecifier);
        BigInteger n = BigInteger.Parse("0ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", NumberStyles.AllowHexSpecifier);
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
