using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using MyRSAUtility;

namespace AsymmetricDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            RSAUtility.Generate();

            try
            {
                // create TCP listener
                TcpListener tcpListen = new TcpListener(IPAddress.Any, 11000);
                tcpListen.Start();

                // check for a connection every two seconds
                while (!tcpListen.Pending())
                {
                    Console.WriteLine("Still listening. Will try again in 2 seconds.");
                    Thread.Sleep(5000);
                }

                // create network stream when data available
                using (TcpClient tcp = tcpListen.AcceptTcpClient())
                {
                    NetworkStream netStream = tcp.GetStream();

                    // read from network stream and decrypt
                    using (BinaryReader bReader = new BinaryReader(netStream))
                    {
                        // read data from stream in 8-byte chunks into temporary buffer
                        // resize message byte array each time and copy buffer into this
                        // after the previous chunk
                        byte[] buffer = new byte[8];
                        byte[] encrypted = new byte[8];
                        int count = 0;
                        int bytesRead = 0;
                        do
                        {
                            bytesRead = bReader.Read(buffer, 0, 8);                           
                            Array.Resize(ref encrypted, count+bytesRead);
                            Array.Copy(buffer, 0, encrypted, count, bytesRead);
                            count += bytesRead;
                        } while (bytesRead > 0);

                        // get private key and decrypt data
                        RSACryptoServiceProvider rsaDecrypt = RSAUtility.GetPrivate();
                        //RSACryptoServiceProvider rsaDecrypt = new RSACryptoServiceProvider();  // test - won't work as this will generate new private key                       
                        byte[] decrypted = rsaDecrypt.Decrypt(encrypted, false);

                        // convert byte array to string for output
                        Encoding enc = Encoding.UTF8;
                        string receivedMessage = enc.GetString(decrypted);

                        Console.WriteLine("Message received was: {0}", receivedMessage);

                        Console.ReadLine();

                        bReader.Close();
                    }
                    tcp.Close();
                }
            }
            catch
            {
                Console.WriteLine("The listener failed");
            }
            Console.WriteLine();
        }
    }
}
