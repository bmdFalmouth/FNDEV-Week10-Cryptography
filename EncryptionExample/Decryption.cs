
using System;
using System.Security.Cryptography;
using System.IO;

namespace EncryptionExample
{


	public class Decryption
	{
		public const int BUFFER_SIZE = 512;

		public void DoDecryption ()
		{
			// Use key container to hold keys		
			CspParameters param = new CspParameters ();
			param.KeyContainerName = "DescrytpionExample";
			
			RSACryptoServiceProvider RSA = new RSACryptoServiceProvider (param);
			// load the pubic and private keys from a file
			RSA.FromXmlString(ReadKeyFromFile());
			
			using(FileStream istream = new FileStream("encrypted.enc", FileMode.Open)){
				byte[] IVSize = new byte[4];
				byte[] keySize = new byte[4];
				
				// read the first 8 byte to determine
				// the array size for IV and Key
				istream.Read(IVSize, 0, 4);
				istream.Read(keySize, 0, 4);
				
				int IVArrayLength = BitConverter.ToInt32(IVSize, 0);
				int keyArrayLength = BitConverter.ToInt32(keySize, 0);
				
				byte[] iv = new byte[IVArrayLength];
				byte[] key = new byte[keyArrayLength];
				
				istream.Read(iv, 0, IVArrayLength);
				istream.Read(key, 0, keyArrayLength);
				
				// descrypt the iv and key using
				// the private key
				iv = RSA.Decrypt(iv, false);
				key = RSA.Decrypt(key, false);
				
				// recreate the symmetric decrypter
				// using the iv and key retrieved.
				TripleDES TDES = new TripleDESCryptoServiceProvider();
				CryptoStream cstream = new CryptoStream(istream,
				                                        TDES.CreateDecryptor(key, iv),
				                                        CryptoStreamMode.Read);
				
				// decrypt the file
				DecryptFile(cstream);
				cstream.Close();
			}
		}

		private void DecryptFile(Stream cstream){
			using(FileStream ostream = new FileStream("decrypted.gif", FileMode.Create)){
				byte[] buffer = new byte[BUFFER_SIZE];
				int count = 0;
				
				while( (count = cstream.Read(buffer, 0, BUFFER_SIZE)) > 0){
					ostream.Write(buffer, 0, count);
				}
				ostream.Flush();
				ostream.Close();
			}
		}
		
		private string ReadKeyFromFile ()
		{
			string key = "";
			using (StreamReader reader = new StreamReader ("asymkey.key")) {
				key = reader.ReadToEnd ();
			}
			
			return key;
		}
	}
}
