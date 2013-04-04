
using System;
using System.Security.Cryptography;
using System.IO;

namespace EncryptionExample
{
	public class Encryption
	{
		
		public const int BUFFER_SIZE = 512;
		
		public void DoEncryption()
		{
			// create a symmetric encryptor
			TripleDESCryptoServiceProvider TDES = new TripleDESCryptoServiceProvider ();
			// create IV and Key need for symmetric encryption
			TDES.GenerateIV();
			TDES.GenerateKey();
			
			// create an asymmetric encryptor
			RSACryptoServiceProvider RSA = new RSACryptoServiceProvider ();
			string AsymKeys = RSA.ToXmlString (true);
			
			// export the public and private keys to a file
			WriteKeyToFile(AsymKeys);
			
			// asymmetric encryption is good for
			// small data, hence, we use it to encrypted
			// IV and Key for symmetric encryption
			byte[] encryptedIV = RSA.Encrypt(TDES.IV, false);
			byte[] encryptedKey = RSA.Encrypt(TDES.Key, false);
			
			// convert the length of IV and Key (e.g. number of bytes used)
			// into a byte, e.g. 4 to 0000 0100
			// as default length of a Integer in .NET is 32,
			// the result byte length should be 4 bytes, i.e. 32/8
			byte[] IVSize = BitConverter.GetBytes(encryptedIV.Length);
			byte[] keySize = BitConverter.GetBytes(encryptedKey.Length);
			
			// write out the IV length, the key length,
			// the encrypted iv, the encrypted key and the actual
			// date to a file using the symmetric encryptor.
			using(FileStream ostream = new FileStream("encrypted.enc", FileMode.Create)){
				ostream.Write(IVSize, 0, IVSize.Length);
				ostream.Write(keySize, 0, keySize.Length);
				ostream.Write(encryptedIV, 0, encryptedIV.Length);
				ostream.Write(encryptedKey, 0, encryptedKey.Length);
				
				CryptoStream cstream = new CryptoStream(ostream,
				                                       TDES.CreateEncryptor(),
				                                        CryptoStreamMode.Write);
				
				// encrypt the data using the crypto stream
				EncryptFile(cstream);
				
				// close streams
				cstream.Close();
				ostream.Close();
			}
			      
		}
		
		private void EncryptFile(Stream ostream){
			using(FileStream istream = new FileStream("gcal-logo.gif", FileMode.Open)){
				byte[] buffer = new byte[BUFFER_SIZE];
				int count = 0;
				while( (count = istream.Read(buffer, 0, BUFFER_SIZE)) > 0 ){
					ostream.Write(buffer, 0, count);
				}
				istream.Close();
			}
			      
		}

		private void WriteKeyToFile (string AsymKey)
		{
			using (StreamWriter writer = new StreamWriter ("asymkey.key")) {
				writer.Write (AsymKey);
				writer.Flush ();
				writer.Close ();
			}
		}
	}
}
