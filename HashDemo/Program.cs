using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace HashDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            // This hash value is produced from "This is the original message!"
            // using SHA1Managed
            byte[] sentHashValue = {59,4,248,102,77,97,142,201,210,
                                       12,224,93,25,41,100,197,213,134,130,135};

            // This is the string to be compared
            string messageString = "This is the original message!";

            byte[] compareHashValue;

            // convert string to array of bytes
            UnicodeEncoding ue = new UnicodeEncoding();
            byte[] messageBytes = ue.GetBytes(messageString);

            // create SHA1ManagedHash instance and create hash
            SHA1Managed sha = new SHA1Managed();
            compareHashValue = sha.ComputeHash(messageBytes);

            // compare values of byte arrays
            bool same = true;
            for (int i = 0; i < sentHashValue.Length; i++)
            {
                if (sentHashValue[i] != compareHashValue[i])
                {
                    same = false;
                }
            }

            // display result
            if (same)
            {
                Console.WriteLine("The hash codes match");
            }
            else
            {
                Console.WriteLine("The hash codes do not match");
            }
        }
    }
}
