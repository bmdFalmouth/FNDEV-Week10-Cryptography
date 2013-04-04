using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;


namespace MyRSAUtility
{
    public class RSAUtility
    {
        // file to store public key
        public static string PUBLICKEY_FILENAME = @"publickey.xml";
        // secure key container name for private key
        public static string KEYCONTAINER_NAME = "mykeys";

        // generates a new public/private key pair
        // stores private key in key container
        // saves public key as XML file
        public static void Generate()
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = KEYCONTAINER_NAME;

            // generate keys and persist in CSP
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
            rsa.PersistKeyInCsp = true;

            // store public key as XML
            string strKeyInfo = rsa.ToXmlString(true);
            using (FileStream stm = new FileStream(PUBLICKEY_FILENAME,
                FileMode.OpenOrCreate, FileAccess.Write))
            {
                StreamWriter writer = new StreamWriter(stm, Encoding.Unicode);
                writer.Write(strKeyInfo);
                writer.Close();
            }
        }
        
        // gets public key info from XML file and return RSACryptoServiceProvider which uses this key
        public static RSACryptoServiceProvider GetPublic()
        {
            string strKeyInfo;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            using (FileStream stm = new FileStream(PUBLICKEY_FILENAME,
               FileMode.Open, FileAccess.Read))
            {
                StreamReader reader = new StreamReader(stm, Encoding.Unicode);
                strKeyInfo = reader.ReadToEnd();
                reader.Close();
            }

            rsa.FromXmlString(strKeyInfo);
            return rsa;
        }

        // gets keys from key container and return RSACryptoServiceProvider which uses this key pair
        public static RSACryptoServiceProvider GetPrivate()
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = KEYCONTAINER_NAME;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
            rsa.PersistKeyInCsp = true;
            return rsa;
        }

    }
}
