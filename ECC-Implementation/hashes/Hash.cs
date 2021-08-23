using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ECC_Implementation.hashes
{
    interface Hash
    {
        public String hash(String msg);

        public byte[] getSHA(string input);
    }
}
