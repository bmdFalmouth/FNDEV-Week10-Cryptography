using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace DigitalSigningDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create digital signature algortihm object
            // This will generate private/public key pair
            RSACryptoServiceProvider signer = new RSACryptoServiceProvider();

            // array to hold signature - will be shared
            byte[] signature = null;
            // string to hold public key - will be shared
            string publicKey = null;

            using(FileStream file = new FileStream(@"info.txt", FileMode.Open, 
                FileAccess.Read))
            {
                // read file to be used to create signature into a byte array
                BinaryReader reader = new BinaryReader(file);
                byte[] data = reader.ReadBytes((int)file.Length);

                // create signature by signing data - generates a digital signature by first
                // generating the hash the data and then generate a signature based on the
                // hash and the private key
                // file, signature and public key are then shared with the recipient
                signature = signer.SignData(data,new SHA1CryptoServiceProvider());
                
                // export public key
                publicKey = signer.ToXmlString(false);

                reader.Close();
                file.Close();
            }

            // Create digital signature algortihm object
            // which will use the public key exported by the signer
            RSACryptoServiceProvider verifier = new RSACryptoServiceProvider();
            verifier.FromXmlString(publicKey);

            using (FileStream file2 = new FileStream(@"info.txt", FileMode.Open,
                FileAccess.Read))
            {
                // read file to be used to verify the signature into a byte array
                BinaryReader reader2 = new BinaryReader(file2);
                byte[] data2 = reader2.ReadBytes((int)file2.Length);

                // verify the signature based on the contents of the file
                // verification will only succeed if the signature was generated from this
                // file using the correct private key, thus confirming the identity of the
                // signer
                if (verifier.VerifyData(data2, new SHA1CryptoServiceProvider(), signature))
                {
                    Console.WriteLine("Verified");
                }
                else
                {
                    Console.WriteLine("NOT verified");
                }

                reader2.Close();
                file2.Close();
            }
        }
    }
}
