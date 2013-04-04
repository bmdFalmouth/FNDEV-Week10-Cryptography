using System;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Text;

namespace SymmetricDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // create TCP listener
                TcpListener tcpListen = new TcpListener(IPAddress.Any, 11000);
                tcpListen.Start();

                // check for a connection every two seconds
                while (!tcpListen.Pending())
                {
                    Console.WriteLine("Still listening. Will try again in 2 seconds.");
                    Thread.Sleep(2000);
                }

                using (TcpClient tcp = tcpListen.AcceptTcpClient())
                {
                    NetworkStream netStream = tcp.GetStream();

                    // create RijndaelManaged instance and encrypt
                    RijndaelManaged rm = new RijndaelManaged();

                    // set key and IV
                    //byte[] Key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    //             0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
                    //byte[] IV = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    //             0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

                    // alternatively, generate key and IV from a shared secret (password)
                    // password and salt are inputs to key generation, which makes dictionary
                    // attacks more difficult than if the input was just the password
                    string password = "Pa$$w0rd";
                    byte[] salt = Encoding.ASCII.GetBytes("This is my salt");
                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt);
                    byte[] Key = key.GetBytes(rm.KeySize / 8);
                    byte[] IV = key.GetBytes(rm.BlockSize / 8);

                    CryptoStream cryptStream = new CryptoStream(netStream,
                        rm.CreateDecryptor(Key, IV),
                        CryptoStreamMode.Read);

                    using (StreamReader sReader = new StreamReader(cryptStream))
                    {
                        Console.WriteLine("The decrypted message is: {0}",
                            sReader.ReadToEnd());
                        sReader.Close();
                    }
                    tcp.Close();
                    Console.ReadKey();
                }
            }
            catch
            {
                Console.WriteLine("The listener failed");
            }

        }
    }
}
