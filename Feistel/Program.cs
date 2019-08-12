using System;
using System.Configuration;
using System.IO;

namespace Feistel
{
    class Program
    {
        static void Main(string[] args)
        {
            var plainText = File.ReadAllText(ConfigurationSettings.AppSettings["plainTextFileName"].ToString()); ;

            var f1 = new FeistelCipher(4, FeistelType.ClassicFeistel, CipherMode.None);
            var cipherText1 = f1.CryptText(plainText, CryptType.Encrypt);
            var plainTextAgain1 = f1.CryptText(cipherText1, CryptType.Decrypt);
            var result1 = plainText.Equals(plainTextAgain1);
            Console.WriteLine("Cipher: Classic Feistel. Mode: None\nplain text: {0}\nafter encoding: {1}\nafter decoding: {2}\nequals: {3}\n\n", plainText, cipherText1, plainTextAgain1, result1);

            var f2 = new FeistelCipher(4, FeistelType.Variant1, CipherMode.None);
            var cipherText2 = f2.CryptText(plainText, CryptType.Encrypt);
            var plainTextAgain2 = f2.CryptText(cipherText2, CryptType.Decrypt);
            var result2 = plainText.Equals(plainTextAgain2);
            Console.WriteLine("Cipher: Variant 1. Mode: None\nplain text: {0}\nafter encoding: {1}\nafter decoding: {2}\nequals: {3}\n\n", plainText, cipherText2, plainTextAgain2, result2);

            var f3 = new FeistelCipher(4, FeistelType.Variant1, CipherMode.CBC);
            var cipherText3 = f3.CryptText(plainText, CryptType.Encrypt);
            var plainTextAgain3 = f3.CryptText(cipherText3, CryptType.Decrypt);
            var result3 = plainText.Equals(plainTextAgain3);
            Console.WriteLine("Cipher: Variant 1. Mode: CBC\nplain text: {0}\nafter encoding: {1}\nafter decoding: {2}\nequals: {3}\n\n", plainText, cipherText3, plainTextAgain3, result3);

            var f4 = new FeistelCipher(4, FeistelType.Variant1, CipherMode.CFB);
            var cipherText4 = f4.CryptText(plainText, CryptType.Encrypt);
            var plainTextAgain4 = f4.CryptText(cipherText4, CryptType.Decrypt);
            var result4 = plainText.Equals(plainTextAgain4);
            Console.WriteLine("Cipher: Variant 1. Mode: CFB\nplain text: {0}\nafter encoding: {1}\nafter decoding: {2}\nequals: {3}\n\n", plainText, cipherText4, plainTextAgain4, result4);

            Console.ReadKey();
        }
    }
}
