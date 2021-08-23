using ECC_Implementation.hashes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace ECC_Implementation.encryptionmethods
{
    interface EncryptionMethod
    {
        BigInteger[] getConfig();

        Hash getHash();
    }
}
