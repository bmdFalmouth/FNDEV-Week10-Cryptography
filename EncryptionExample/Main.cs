using System;

namespace EncryptionExample
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			Encryption encryption = new Encryption();
			encryption.DoEncryption();
			
			Decryption decryption = new Decryption();
			decryption.DoDecryption();
		}
	}
}
