using ECC_Implementation.encryptionmethods;
using System;
using System.Numerics;

namespace ECC_Implementation
{
    class Program
    {
        static void Main(string[] args)
        {
            EncryptionMethod enc_method = new secp256r1();
            ECC ecc1 = new ECC(enc_method);
            ECC ecc2 = new ECC(enc_method);
            BigInteger[] keys_1 = ecc1.genKeys();
            BigInteger[] keys_2 = ecc2.genKeys();

            Console.WriteLine("Private Key: \n" + keys_1[0].ToString() + "\nPublic Key: \n" + keys_1[1].ToString() + "\n" + keys_1[2].ToString());
            Console.WriteLine("\n\nPrivate Key: \n" + keys_2[0].ToString() + "\nPublic Key: \n" + keys_2[1].ToString() + "\n" + keys_2[2].ToString());

            BigInteger[] shared_secret_1 = ecc1.point_mult(keys_1[0], new BigInteger[] { keys_2[1], keys_2[2] });
            BigInteger[] shared_secret_2 = ecc2.point_mult(keys_2[0], new BigInteger[] { keys_1[1], keys_1[2] });

            Console.WriteLine("\n\n\nShared Secret: \n" + shared_secret_1[0] + "\n" + shared_secret_1[1]);
            Console.WriteLine("\n\nShared Secret: \n" + shared_secret_2[0] + "\n" + shared_secret_2[1]);
        }
    }
}
