using ECC_Implementation.hashes;
using System.Globalization;
using System.Numerics;

namespace ECC_Implementation.encryptionmethods
{
    class secp384r1 : EncryptionMethod
    {

        BigInteger p = BigInteger.Parse("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", NumberStyles.HexNumber);
        BigInteger a = BigInteger.Parse("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", NumberStyles.HexNumber);
        BigInteger b = BigInteger.Parse("0b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", NumberStyles.HexNumber);
        BigInteger Gx = BigInteger.Parse("0aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", NumberStyles.HexNumber);
        BigInteger Gy = BigInteger.Parse("03617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", NumberStyles.HexNumber);
        BigInteger n = BigInteger.Parse("0ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", NumberStyles.HexNumber);
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
