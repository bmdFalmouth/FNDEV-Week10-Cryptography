using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace HMACDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            String originalFile = "mydata.txt";
            String codedFile = "codeddata.bin";

            // generate random key
            byte[] key = new byte[16];     // 
            RNGCryptoServiceProvider generator = new RNGCryptoServiceProvider();
            generator.GetBytes(key);

            // encode file
            EncodeFile(key, originalFile, codedFile);

            // pause - tampering may occur!
            Console.WriteLine("Press ENTER to continue - hope nobody tampers with the coded file now!");
            Console.ReadLine();

            // decode file and check for tampering
            DecodeFile(key, codedFile);
        }

        static void EncodeFile(byte[] key, String sourceFile, string destFile)
        {
            // initialize keyed hash object
            HMACSHA1 hms = new HMACSHA1(key);

            // open filestreams to read in original file and write out coded file
            using(FileStream inStream = new FileStream(sourceFile,FileMode.Open))
            using (FileStream outStream = new FileStream(destFile, FileMode.Create))
            {
                // array to hold keyed hash value of original file
                byte[] hashValue = hms.ComputeHash(inStream);

                // reset instream ready to read original file contents from start
                inStream.Position = 0;

                // write keyed hash value to coded file
                outStream.Write(hashValue, 0, hashValue.Length);

                // copy data from original file to output file, 1K at a time
                int bytesRead;
                byte[] buffer = new byte[1024];
                do
                {
                    bytesRead = inStream.Read(buffer, 0, 1024);
                    outStream.Write(buffer, 0, bytesRead);
                } while (bytesRead > 0);
                hms.Clear();

                inStream.Close();
                outStream.Close();
            }

        }

        static bool DecodeFile(byte[] key, String sourceFile)
        {
            // initialize keyed hash object
            HMACSHA1 hms = new HMACSHA1(key);

            // byte array to read keyed hash value from coded file
            byte[] storedHash = new byte[hms.HashSize / 8];

            // open file stream to read coded file
            using (FileStream inStream = new FileStream(sourceFile, FileMode.Open))
            {
                // read stored hash value from coded file
                inStream.Read(storedHash, 0, storedHash.Length);

                // compute hash value from data in coded file
                byte[] computedHash = hms.ComputeHash(inStream);

                inStream.Close();

                // compare hash value stored in file with hash computed from data in file
                // these should match - if not, the file has been modified after coding
                for (int i = 0; i < storedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i])
                    {
                        Console.WriteLine(
                            "Hash values differ! Encoded file has been tampered with");
                        return false;
                    }
                }
                Console.WriteLine("Hash values agree -- no tampering occurred");
                return true;
            }
        }

    }
}
