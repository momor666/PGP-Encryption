using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GPG_Encryption
{
    public class DecryptEncryptedFile
    {
        public static void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {

            Stream fin = File.OpenRead(filePath);

            Stream keyIn = File.OpenRead(privateKeyFile);

            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), pathToSaveFile);

            fin.Close();

            keyIn.Close();

        }
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
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {

            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
            {

                return null;

            }

            return pgpSecKey.ExtractPrivateKey(pass);

        }
    }
}
