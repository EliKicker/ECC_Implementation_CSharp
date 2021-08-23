using System;
using System.Text;
using System.Windows;

namespace ECC_Implementation.hashes
{
    class SHA256 : Hash
    {

        public byte[] getSHA(string input)
        {
            System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create();
            return sha256.ComputeHash(Encoding.ASCII.GetBytes(input));
        }

        public string hash(string msg)
        {
            try
            {
                return BitConverter.ToString(getSHA(msg)).Replace("-", "").ToLower();
            } catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
            }
            return null;
        }
    }
}
