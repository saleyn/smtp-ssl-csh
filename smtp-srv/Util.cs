using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace smtp
{
  public class Util
  {
        public static RSACryptoServiceProvider LoadCertificateFile(string filename)
        {
            using (System.IO.FileStream fs = System.IO.File.OpenRead(filename))
            {
                byte[] data = new byte[fs.Length];
                byte[] res = null;
                fs.Read(data, 0, data.Length);
                if (data[0] != 0x30)
                {
                    res = GetPem("RSA PRIVATE KEY", data);
                    //var x509 = new X509Certificate2(data);
                    //return (RSACryptoServiceProvider)x509.PrivateKey;
                }
                try
                {
                    RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(res);
                    return rsa;
                }
                catch (Exception)
                {}
                return null;
            }
        }

        public static void MakeCert(string filename, bool bin_privkey=false)
        {
          var ecdsa = ECDsa.Create(); // generate asymmetric key pair
          var req   = new CertificateRequest("cn=mqt", ecdsa, HashAlgorithmName.SHA256);
          var cert  = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

          if (filename == null)
            filename = "c:/temp/mycert.cer"; // private key
            
          var privkey = Path.Combine(Path.GetDirectoryName(filename), Path.GetFileNameWithoutExtension(filename) + ".pvk");
            
          // Create PFX (PKCS #12) with private key
          if (bin_privkey)
            File.WriteAllBytes(privkey, cert.Export(X509ContentType.Pfx));
          else
            File.WriteAllText(
              privkey,
              "-----BEGIN RSA PRIVATE KEY-----\r\n"
              + Convert.ToBase64String(cert.Export(X509ContentType.Pfx), Base64FormattingOptions.InsertLineBreaks)
              + "\r\n-----END RSA PRIVATE KEY-----");

          // Create Base 64 encoded CER (public key only)
          File.WriteAllText(
            filename,
            "-----BEGIN CERTIFICATE-----\r\n"
            + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
            + "\r\n-----END CERTIFICATE-----");
        }
        static byte[] GetPem(string type, byte[] data)
        {
          string pem = Encoding.UTF8.GetString(data);
          string header = String.Format("-----BEGIN {0}-----\\n", type);
          string footer = String.Format("-----END {0}-----", type);
          int start = pem.IndexOf(header) + header.Length;
          int end = pem.IndexOf(footer, start);
          string base64 = pem.Substring(start, (end - start));
          return Convert.FromBase64String(base64);
        }

        public static byte[] GetBytesFromPEM(string pemString, bool is_priv_key)
        {
            string header; string footer;
            if (is_priv_key)
            {
                header = "-----BEGIN RSA PRIVATE KEY-----";
                footer = "-----END RSA PRIVATE KEY-----";
            } else {
                header = "-----BEGIN CERTIFICATE-----";
                footer = "-----END CERTIFICATE-----";
            }

            int start = pemString.IndexOf(header) + header.Length;
            int end   = pemString.IndexOf(footer, start) - start;
            return Convert.FromBase64String(pemString.Substring(start, end));
        }
        
        public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
          byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;
        
          // --------- Set up stream to decode the asn.1 encoded RSA private key ------
          MemoryStream mem = new MemoryStream(privkey);
          BinaryReader binr = new BinaryReader(mem);  //wrap Memory Stream with BinaryReader for easy reading
          byte bt = 0;
          ushort twobytes = 0;
          int elems = 0;
          try
          {
            twobytes = binr.ReadUInt16();
            if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
              binr.ReadByte();    //advance 1 byte
            else if (twobytes == 0x8230)
              binr.ReadInt16();    //advance 2 bytes
            else
              return null;
        
            twobytes = binr.ReadUInt16();
            if (twobytes != 0x0102) //version number
              return null;
            bt = binr.ReadByte();
            if (bt != 0x00)
              return null;
        
        
            //------ all private key components are Integer sequences ----
            elems = GetIntegerSize(binr);
            MODULUS = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            E = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            D = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            P = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            Q = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            DP = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            DQ = binr.ReadBytes(elems);
        
            elems = GetIntegerSize(binr);
            IQ = binr.ReadBytes(elems);
        
            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            CspParameters CspParameters = new CspParameters();
            CspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(1024, CspParameters);
            RSAParameters RSAparams = new RSAParameters();
            RSAparams.Modulus = MODULUS;
            RSAparams.Exponent = E;
            RSAparams.D = D;
            RSAparams.P = P;
            RSAparams.Q = Q;
            RSAparams.DP = DP;
            RSAparams.DQ = DQ;
            RSAparams.InverseQ = IQ;
            RSA.ImportParameters(RSAparams);
            return RSA;
          }
          catch (Exception)
          {
            return null;
          }
          finally
          {
            binr.Close();
          }
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
            if (bt == 0x82)
            {
                highbyte = binr.ReadByte();	// data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;		// we already have the data size
            }

            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }
        
  }
}