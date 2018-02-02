using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GPG_Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            EncryptAndSign();
        }
        private static void EncryptAndSign()
        {
            //generate private and public keys

            // KeysGenerator k = new KeysGenerator();
            //username, password
            //k.GenerateKey("derrick", "abucheri", "C:\\Users\\RiFF\\Desktop\\GeneratedKeys");

            /////////////

            //PgpEncryptionKeys encryptionKeys = new PgpEncryptionKeys(PublicKeyFileName, PrivateKeyFileName, "PasswordOfMyPrivateKey");

            //PgpEncrypt encrypter = new PgpEncrypt(encryptionKeys);

            //using (Stream outputStream = File.Create(EncryptedFileName))
            //{
            //    encrypter.EncryptAndSign(outputStream, new FileInfo(FileToEncrypt));
            //}

            //encrypt
            //////////////////////
            //PgpEncryptionKeys encryptionKeys = new PgpEncryptionKeys("C:\\Users\\RiFF\\Desktop\\GeneratedKeyspub.asc", "C:\\Users\\RiFF\\Desktop\\GeneratedKeyssecret.asc", "abucheri");

            //PgpEncrypt encrypter = new PgpEncrypt(encryptionKeys);

            //using (Stream outputStream = File.Create("C:\\Users\\RiFF\\Desktop\\encryptedd.txt"))
            //{
            //    encrypter.EncryptAndSign(outputStream, new FileInfo("C:\\Users\\RiFF\\Desktop\\HHAHAH.txt"));
            //}
            //decrypt
            ////////////////////////
              PGPDecrypt.Decrypt("C:\\Users\\RiFF\\Desktop\\encryptedd.txt", "C:\\Users\\RiFF\\Desktop\\GeneratedKeyssecret.asc", "abucheri", "C:\\Users\\RiFF\\Desktop\\output.txt");









            ////
            // DecryptEncryptedFile d = new DecryptEncryptedFile();
            //failed!!!!!!!!!!!!
            //DecryptEncryptedFile.Decrypt("C:\\Users\\RiFF\\Desktop\\encryptedd.txt", "C:\\Users\\RiFF\\Desktop\\GeneratedKeyssecret.asc", "abucheri", "C:\\Users\\RiFF\\Desktop");
        }

    }
}
