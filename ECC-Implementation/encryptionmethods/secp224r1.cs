using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class secp224r1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0ffffffffffffffffffffffffffffffff000000000000000000000001", NumberStyles.HexNumber);
        BigInteger a = BigInteger.Parse("0fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", NumberStyles.HexNumber);
        BigInteger b = BigInteger.Parse("0b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", NumberStyles.HexNumber);
        BigInteger Gx = BigInteger.Parse("0b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", NumberStyles.HexNumber);
        BigInteger Gy = BigInteger.Parse("0bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", NumberStyles.HexNumber);
        BigInteger n = BigInteger.Parse("0ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", NumberStyles.HexNumber);
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
