using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.IO;

namespace smtp
{
  public class MailListener : TcpListener
{
    private TcpClient client;
    private NetworkStream stream;
    private System.IO.StreamReader reader;
    private System.IO.StreamWriter writer;
    private Thread thread = null;

    public bool IsThreadAlive
    {
        get { return thread.IsAlive; }
    }

    public MailListener(IPAddress localaddr, int port)
        : base(localaddr, port)
    {
    }

    public new void Start()
    {
        base.Start();

        client = AcceptTcpClient();
        client.ReceiveTimeout = 5000;
        stream = client.GetStream();
        reader = new System.IO.StreamReader(stream);
        writer = new System.IO.StreamWriter(stream);
        writer.NewLine = "\r\n";
        writer.AutoFlush = true;

        thread = new System.Threading.Thread(new ThreadStart(RunThread));
        thread.Start();
    }

    protected void RunThread()
    {
        string line = null;

        writer.WriteLine("220 localhost -- Fake proxy server");

        try
        {
            while (reader != null)
            {
                line = reader.ReadLine();
                Console.Error.WriteLine("Read line {0}", line);

                switch (line)
                {
                    case "DATA":
                        writer.WriteLine("354 Start input, end data with <CRLF>.<CRLF>");
                        StringBuilder data = new StringBuilder();
                        String subject = "";
                        line = reader.ReadLine();

                        if (line != null && line != ".")
                        {
                            const string SUBJECT = "Subject: ";
                            if (line.StartsWith(SUBJECT))
                            {
                                subject = line.Substring(SUBJECT.Length);
                            }
                            else
                            {
                                data.AppendLine(line);
                            }

                            for (line = reader.ReadLine(); line != null && line != "."; line = reader.ReadLine())
                            {
                                data.AppendLine(line);
                            }
                        }

                        String message = data.ToString();
                        Console.Error.WriteLine("Received ­ email with subject: {0} and message: {1}", subject, message);
                        writer.WriteLine("250 OK");
                        break;

                    case "QUIT":
                        writer.WriteLine("250 OK");
                        reader = null;
                        break;

                    default:
                        writer.WriteLine("250 OK");
                        break;
                }
            }
        }
        catch (IOException)
        {
            Console.WriteLine("Connection lost.");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
        finally
        {
            client.Close();
            Stop();
        }
    }
}
  
  class Program
  {
      static void MainX(string[] args)
      {
          Console.WriteLine("Hello World!");
          System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient("localhost");
      }
  }
}