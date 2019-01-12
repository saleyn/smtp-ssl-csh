using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text.RegularExpressions;

// Create certificate:
// > openssl x509 -text -noout -in cert.pem
// > openssl pkcs12 -inkey key.pem -in cert.pem -export -out mycert.p12

// Alternative
// > makecert.exe -r -pe -n "CN=localhost" -sky exchange -sv c:/temp/mycert.pfx c:/temp/mycert.cer

namespace smtp
{
    public class SslSmtpServer
    {
        static X509Certificate2 serverCertificate = null;

        // The certificate parameter specifies the name of the file 
        // containing the machine certificate.
        public static void RunServer(string certificate, IPAddress addr, int port)
        {
            //var privkey_file = Path.Combine(Path.GetDirectoryName(certificate), Path.GetFileNameWithoutExtension(certificate) + ".pfx");
            serverCertificate = new X509Certificate2(certificate);
            //var pk = new X509Certificate2(File.ReadAllBytes(privkey_file));
            //serverCertificate.PrivateKey = pk.PrivateKey;
            //var pk = LoadCertificateFile(privkey_file);
            //var keybuf = GetBytesFromPEM(privkey_file, true);
            //serverCertificate.PrivateKey = DecodeRSAPrivateKey(keybuf);
            //serverCertificate.PrivateKey = LoadCertificateFile(privkey_file);
            //serverCertificate.PrivateKey = LoadCertificateFile(privkey_file);

            // Create a TCP/IP (IPv4) socket and listen for incoming connections.
            TcpListener listener = new TcpListener(addr, port);
            listener.Start();
            while (true)
            {
                Console.WriteLine($"Waiting for a client to connect on {addr}:{port}...");
                // Application blocks while waiting for an incoming connection.
                // Type CNTL-C to terminate the server.
                TcpClient client = listener.AcceptTcpClient();
                ProcessClient(client);
            }
        }

        static void ProcessClient(TcpClient client)
        {
            // A client has connected. Create the 
            // SslStream using the client's network stream.
            var sslStream = new SslStream(client.GetStream(), false);
            
            Console.WriteLine($"====> Client connected ({client.Client.RemoteEndPoint.ToString()})");
            
            // Authenticate the server but don't require the client to authenticate.
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate,
                                               clientCertificateRequired:  false,
                                               enabledSslProtocols:        SslProtocols.Tls,
                                               checkCertificateRevocation: true);

                // Display the properties and settings for the authenticated stream.
                //DisplaySecurityLevel(sslStream);
                //DisplaySecurityServices(sslStream);
                //DisplayCertificateInformation(sslStream);
                //DisplayStreamProperties(sslStream);

                // Set timeouts for the read and write to 5 seconds.
                sslStream.ReadTimeout  = 5000;
                sslStream.WriteTimeout = 5000;
                
                WriteMessage(sslStream, "220 localhost SMTP Proxy\r\n");
                
                var msg = String.Empty;
                while (true)
                {
                    try { msg = ReadMessage(sslStream); } catch (Exception) { break; }

                    //Console.Write(msg);
                    
                    if (msg.Length <= 0) continue;
                    
                    if (msg.StartsWith("QUIT"))
                    {
                        WriteMessage(sslStream, "221 Service closing transmission channel\r\n");
                        break; //exit while
                    }

                    //message has successfully been received
                    if (msg.StartsWith("EHLO") || msg.StartsWith("HELO"))
                    {
                        WriteMessage(sslStream, "250 OK\r\n");
                        //WriteMessage(sslStream, "250 SMTPUTF8\r\n");
                        continue;
                    }
                    if (msg.StartsWith("RCPT TO"))
                    {
                        WriteMessage(sslStream, "250 OK\r\n");
                        continue;
                    }

                    if (msg.StartsWith("MAIL FROM"))
                    {
                        //Console.Write(msg);
                        WriteMessage(sslStream, "250 OK\r\n");
                        continue;
                    }

                    if (msg.StartsWith("DATA"))
                    {
                        WriteMessage(sslStream, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
                        var s = new StringBuilder();
                        do
                        {
                            msg = ReadMessage(sslStream);
                            s.Append(msg);
                            //Console.WriteLine(Decode(msg));
                        }
                        while (!msg.Contains("\r\n.\r\n"));

                        //Console.WriteLine($"Client sent: {msg}");
                        WriteMessage(sslStream, "250 OK\r\n");
                        
                        var sr = MimeParser.ParseMessage(new StringReader(s.ToString()));
                        
                        Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} From: {sr.From}, Subject: {sr.Subject}");
                        Console.WriteLine(sr.Body);
                        continue;
                    }
                }

                sslStream.Close();
                client.Close();
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }

                Console.WriteLine("Authentication failed - closing the connection.");
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                // The client stream will be closed with the sslStream
                // because we specified this behavior when creating
                // the sslStream.
                sslStream.Close();
                client.Close();
                Console.WriteLine("====> Client disconnected");
            }
        }

        public static string Decode(string s)
        {
            var rr = Regex.Matches(s,@"(?:=\?)([^\?]+)(?:\?B\?)([^\?]*)(?:\?=)");
            if (rr.Count == 0)
                return s;
            var charset = rr[0].Groups[1].Value;
            if (charset == "UTF8") charset = "UTF-8";
            var data = rr[0].Groups[2].Value;
            var b = Convert.FromBase64String(data);
            var res = Encoding.GetEncoding(charset).GetString(b);
            return res;
        }
        
        static void WriteMessage(SslStream sock, string msg)
        {
            var data = Encoding.ASCII.GetBytes(msg);
            sock.Write(data);
        }
        
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client.
            // The client signals the end of the message using the
            // "<EOF>" marker.
            byte[] buffer = new byte[1024];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.ASCII.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF or an empty message.
                if (messageData.ToString().IndexOf("\r\n") != -1)
                    break;
            } while (bytes != 0);

            return messageData.ToString();
        }

        static void DisplaySecurityLevel(SslStream stream)
        {
            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm,
                              stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm,
                              stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}",
                              stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }

        static void DisplaySecurityServices(SslStream stream)
        {
            Console.WriteLine("Is authenticated: {0} as server? {1}",
                              stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
        }

        static void DisplayStreamProperties(SslStream stream)
        {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead,
                              stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
        }

        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}",
                              stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine(
                    "Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }

            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine(
                    "Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        private static void DisplayUsage()
        {
            Console.WriteLine("To start the server specify:");
            Console.WriteLine("serverSync certificateFile.cer");
            Environment.Exit(1);
        }

        public static int Main(string[] args)
        {
            string certificate = null;
            if (args == null || args.Length < 1)
            {
                certificate = "c:/temp/mycert.p12";
                if (!File.Exists(certificate))
                    Util.MakeCert(certificate, false);
                Console.WriteLine($"Certificate not provided, using: {certificate}");
                //DisplayUsage();
                //return 1;
            }
            else
            {
                certificate = args[0];
            }

            var port = (args.Length == 2) ? int.Parse(args[1]) : 25;

            SslSmtpServer.RunServer(certificate, IPAddress.Loopback, port);
            return 0;
        }
    }
}