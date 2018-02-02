using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GPG_Encryption
{
    public class PGPEncryptDecrypt
    {
        /**

        * A simple routine that opens a key ring file and loads the first available key suitable for

        * encryption.

        *

        * @param in

        * @return

        * @m_out

        * @

*/
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            //

            // we just loop through the collection till we find a key suitable for encryption, in the real

            // world you would probably want to be a bit smarter about this.

            //

            //

            // iterate through the key rings.

            //

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {

                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {

                    if (k.IsEncryptionKey)
                    {

                        return k;

                    }

                }

            }

            throw new ArgumentException("Can't find encryption key in key ring.");

        }

        /**

        * Search a secret key ring collection for a secret key corresponding to

        * keyId if it exists.

        *

        * @param pgpSec a secret key ring collection.

        * @param keyId keyId we want.

        * @param pass passphrase to decrypt secret key with.

        * @return

*/
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {

            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
            {

                return null;

            }

            return pgpSecKey.ExtractPrivateKey(pass);

        }

        /**

        * decrypt the passed in message stream

*/
        private static void DecryptFile(Stream inputStream, Stream keyIn, char[] passwd, string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {

                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);

                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();

                //

                // the first object might be a PGP marker packet.

                //

                if (o is PgpEncryptedDataList)
                {

                    enc = (PgpEncryptedDataList)o;

                }

                else
                {

                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                }

                //

                // find the secret key

                //

                PgpPrivateKey sKey = null;

                PgpPublicKeyEncryptedData pbe = null;

                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(

                PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {

                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);

                    if (sKey != null)
                    {

                        pbe = pked;

                        break;

                    }

                }

                if (sKey == null)
                {

                    throw new ArgumentException("secret key for message not found.");

                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {

                    PgpCompressedData cData = (PgpCompressedData)message;

                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();

                }

                if (message is PgpLiteralData)
                {

                    PgpLiteralData ld = (PgpLiteralData)message;

                    //string outFileName = ld.FileName;

                    //if (outFileName.Length == 0)
                    //{

                    // outFileName = defaultFileName;

                    //}

                    Stream fOut = File.Create(pathToSaveFile);

                    Stream unc = ld.GetInputStream();

                    Streams.PipeAll(unc, fOut);

                    fOut.Close();

                }

                else if (message is PgpOnePassSignatureList)
                {

                    throw new PgpException("encrypted message contains a signed message – not literal data.");

                }

                else
                {

                    throw new PgpException("message is not a simple encrypted file – type unknown.");

                }

                if (pbe.IsIntegrityProtected())
                {

                    if (!pbe.Verify())
                    {

                        Console.WriteLine("message failed integrity check");

                    }

                    else
                    {

                        Console.WriteLine("message integrity check passed");

                    }

                }

                else
                {

                    Console.WriteLine("no message integrity check");

                }

            }

            catch (PgpException e)
            {

                Console.WriteLine(e);

                Exception underlyingException = e.InnerException;

                if (underlyingException != null)
                {

                    Console.WriteLine(underlyingException.Message);

                    Console.WriteLine(underlyingException.StackTrace);

                }//

               // System.Windows.Forms.MessageBox.Show(e.ToString());

            }

        }

        private static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {

            if (armor)
            {

                outputStream = new ArmoredOutputStream(outputStream);

            }

            try
            {

                MemoryStream bOut = new MemoryStream();

                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(

                CompressionAlgorithmTag.Zip);

                PgpUtilities.WriteFileToLiteralData(

                comData.Open(bOut),

                PgpLiteralData.Binary,

                new FileInfo(fileName));

                comData.Close();

                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(

                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                cPk.AddMethod(encKey);

                byte[] bytes = bOut.ToArray();

                Stream cOut = cPk.Open(outputStream, bytes.Length);

                cOut.Write(bytes, 0, bytes.Length);

                cOut.Close();

                if (armor)
                {

                    outputStream.Close();

                }

            }

            catch (PgpException e)
            {

                Console.WriteLine(e);

                Exception underlyingException = e.InnerException;

                if (underlyingException != null)
                {

                    Console.WriteLine(underlyingException.Message);

                    Console.WriteLine(underlyingException.StackTrace);

                }

            }

        }

        public static void Encrypt(string filePath, string publicKeyFile, string OutputFilePath)
        {

            Stream keyIn, fos;

            keyIn = File.OpenRead(publicKeyFile);

            fos = File.Create(OutputFilePath);

            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);

            keyIn.Close();

            fos.Close();

        }

        public static void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {

            Stream fin = File.OpenRead(filePath);

            Stream keyIn = File.OpenRead(privateKeyFile);

            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), pathToSaveFile);

            fin.Close();

            keyIn.Close();

        }

        public static void GenerateKey(string username, string password, string keyStoreUrl)
        {

            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");

            // new RsaKeyPairGenerator();

            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            FileStream out1 = new FileInfo(string.Format("{0}_PrivateKey.txt", keyStoreUrl)).OpenWrite();
            FileStream out2 = new FileInfo(string.Format("{0}_PublicKey.txt", keyStoreUrl)).OpenWrite();

            ExportKeyPair(out1, out2, kp.Public, kp.Private, PublicKeyAlgorithmTag.RsaGeneral, SymmetricKeyAlgorithmTag.Cast5, username, password.ToCharArray(), true);

            out1.Close();
            out2.Close();

            /*

            IAsymmetricCipherKeyPairGenerator dsaKpg = GeneratorUtilities.GetKeyPairGenerator("DSA");
            DsaParametersGenerator pGen = new DsaParametersGenerator();
            pGen.Init(1024, 80, new SecureRandom());
            DsaParameters dsaParams = pGen.GenerateParameters();
            DsaKeyGenerationParameters kgp = new DsaKeyGenerationParameters(new SecureRandom(), dsaParams);
            dsaKpg.Init(kgp);

            //
            // this takes a while as the key generator has to Generate some DSA parameters
            // before it Generates the key.
            //
            AsymmetricCipherKeyPair dsaKp = dsaKpg.GenerateKeyPair();

            IAsymmetricCipherKeyPairGenerator elgKpg = GeneratorUtilities.GetKeyPairGenerator("ELGAMAL");

            ElGamalParametersGenerator eGen = new ElGamalParametersGenerator();

            eGen.Init(1024,80,new SecureRandom());

            ElGamalParameters elParams = eGen.GenerateParameters();

            ElGamalKeyGenerationParameters elKgp = new ElGamalKeyGenerationParameters(new SecureRandom(), elParams);

            elgKpg.Init(elKgp);

            //
            // this is quicker because we are using preGenerated parameters.
            //
            AsymmetricCipherKeyPair elgKp = elgKpg.GenerateKeyPair();

            FileStream out3 = new FileInfo(string.Format("{0}_PrivateKey_ELGMAL.txt", keyStoreUrl)).OpenWrite();
            FileStream out4 = new FileInfo(string.Format("{0}_PublicKey_ELGMAL.txt", keyStoreUrl)).OpenWrite();

            ExportKeyPair(out3, out4, dsaKp, elgKp, username, password.ToCharArray(), true);

            out3.Close();
            out4.Close();

            */
        }

        private static void ExportKeyPair(
        Stream secretOut,
        Stream publicOut,
        AsymmetricKeyParameter publicKey,
        AsymmetricKeyParameter privateKey,
        PublicKeyAlgorithmTag PublicKeyAlgorithmTag,
        SymmetricKeyAlgorithmTag SymmetricKeyAlgorithmTag,
        string identity,
        char[] passPhrase,
        bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification,
            PublicKeyAlgorithmTag,
            publicKey,
            privateKey,
            DateTime.Now,
            identity,
            SymmetricKeyAlgorithmTag,
            passPhrase,
            null,
            null,
            new SecureRandom()
            // ,"BC"
            );

            secretKey.Encode(secretOut);

            secretOut.Close();

            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Close();
        }

        //public void SignAndEncryptFile(string actualFileName, string embeddedFileName,
        //Stream keyIn, long keyId, string OutputFileName,
        //char[] password, bool armor, bool withIntegrityCheck, PgpPublicKey encKey)
        //{
        //    const int BUFFER_SIZE = 1 < < 16; // should always be power of 2 Stream outputStream = File.Open(OutputFileName, FileMode.Create); if (armor) outputStream = new ArmoredOutputStream(outputStream); // Init encrypted data generator PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom()); encryptedDataGenerator.AddMethod(encKey); Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]); // Init compression PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip); Stream compressedOut = compressedDataGenerator.Open(encryptedOut); // Init signature PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn)); PgpSecretKey pgpSecKey = pgpSecBundle.GetSecretKey(keyId); if (pgpSecKey == null) throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId"); PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(password); PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1); signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey); foreach (string userId in pgpSecKey.PublicKey.GetUserIds()) { PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator(); spGen.SetSignerUserId(false, userId); signatureGenerator.SetHashedSubpackets(spGen.Generate()); // Just the first one! break; } signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut); // Create the Literal Data generator output stream PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator(); FileInfo embeddedFile = new FileInfo(embeddedFileName); FileInfo actualFile = new FileInfo(actualFileName); // TODO: Use lastwritetime from source file Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, embeddedFile.Name, actualFile.LastWriteTime, new byte[BUFFER_SIZE]); // Open the input file FileStream inputStream = actualFile.OpenRead(); byte[] buf = new byte[BUFFER_SIZE]; int len; while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
        //    {
        //        literalOut.Write(buf, 0, len);
        //        signatureGenerator.Update(buf, 0, len);
        //    }

        //    literalOut.Close();
        //    literalDataGenerator.Close();
        //    signatureGenerator.Generate().Encode(compressedOut);
        //    compressedOut.Close();
        //    compressedDataGenerator.Close();
        //    encryptedOut.Close();
        //    encryptedDataGenerator.Close();
        //    inputStream.Close();

        //    if (armor)
        //        outputStream.Close();
        //}

        private static void ExportKeyPair(
        Stream secretOut,
        Stream publicOut,
        AsymmetricCipherKeyPair dsaKp,
        AsymmetricCipherKeyPair elgKp,
        string identity,
        char[] passPhrase,
        bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpKeyPair dsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.Dsa, dsaKp, DateTime.UtcNow);

            PgpKeyPair elgKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ElGamalEncrypt, elgKp, DateTime.UtcNow);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, dsaKeyPair,
            identity, SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, new SecureRandom());

            keyRingGen.AddSubKey(elgKeyPair);

            keyRingGen.GenerateSecretKeyRing().Encode(secretOut);

            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }

            keyRingGen.GeneratePublicKeyRing().Encode(publicOut);

            if (armor)
            {
                publicOut.Close();
            }
        }

    }
}
