using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using MyRSAUtility;

namespace AsymmetricEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {

            try
            {
                // create network stream
                using (TcpClient tcp = new TcpClient("localhost", 11000))
                {
                    NetworkStream netStream = tcp.GetStream();

                    // encrypt using public key and write to network stream
                    using (BinaryWriter sWriter = new BinaryWriter(netStream))
                    {
                        string testMessage = "This is a very important message!";

                        // encode message as byte array
                        Encoding enc = Encoding.UTF8;
                        byte[] testMessageBytes = enc.GetBytes(testMessage);

                        // get stored public key and encrypt
                        RSACryptoServiceProvider rsaEncrypt = RSAUtility.GetPublic();
                        byte[] encrypted = rsaEncrypt.Encrypt(testMessageBytes, false);

                        // write encrypted byte array
                        sWriter.Write(encrypted);

                        Console.WriteLine("The message was sent...");
                        sWriter.Close();
                    }
                    tcp.Close();
                }
            }
            catch
            {
                Console.WriteLine("The connection failed");
            }
            Console.WriteLine();

        }
    }
}
