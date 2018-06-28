
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
namespace hacbuild
{
    class Program
    {

        // Static stuff used in the program
        public static Random Rand = new Random();
        public static SHA256 SHA256 = SHA256CryptoServiceProvider.Create();
        public static Aes AES128CBC = Aes.Create();
        

        // Entrypoint
        static void Main(string[] args)
        {
            Console.WriteLine("HACbuild - {0}", Assembly.GetExecutingAssembly().GetName().Version);

            if(LoadKeys() )
            {
                Console.WriteLine("XCI Header Key loaded successfully:\n{0}", BitConverter.ToString(XCIManager.XCI_GAMECARDINFO_KEY));

                byte[] keyHash = Program.SHA256.ComputeHash(XCIManager.XCI_GAMECARDINFO_KEY);

                if (Enumerable.SequenceEqual<byte>(keyHash, XCIManager.XCI_GAMECARD_KEY_SHA256))
                {
                    Console.WriteLine("XCI Header Key is correct!");
                } else { 
                    Console.WriteLine("[WARN] Invalid XCI Header Key");
                }

            } else
            {
                Console.WriteLine("[WARN] Could not load XCI Header Key");
            }

            // Configure AES
            AES128CBC.BlockSize = 128;
            AES128CBC.Mode = CipherMode.CBC;
            AES128CBC.Padding = PaddingMode.Zeros;

            if (args.Length < 3)
            {
                PrintUsage();
                return;
            }

            // TODO Decent command line argument parsing (this is... ugly).
            switch(args[0])
            {
                case "read":
                    switch(args[1])
                    {
                        case "xci":
                            Console.WriteLine("Reading {0}", args[2]);
                            XCIManager.xci_header header =  XCIManager.GetXCIHeader(args[2]);
                            XCIManager.gamecard_info gcInfo = XCIManager.DecryptGamecardInfo(header);


                            Console.WriteLine(header.ToString());
                            Console.WriteLine(gcInfo.ToString());

                            // TODO Move somewhere else - dump to ini
                            string folder = Path.GetDirectoryName(Path.GetFullPath(args[2])); // Is GetFullPath needed?
                            string iniPath = Path.Combine(folder, Path.GetFileNameWithoutExtension(args[2]) ) + ".ini";

                            IniFile ini = new IniFile(iniPath);

                            ini.Write("PackageID", header.PackageID.ToString(), "XCI_Header");
                            ini.WriteBytes("GamecardIV", header.GamecardIV, "XCI_Header");
                            ini.Write("KEKIndex", header.KEK.ToString(), "XCI_Header");
                            ini.WriteBytes("InitialDataHash", header.InitialDataHash, "XCI_Header");

                            ini.Write("Version", gcInfo.Version.ToString(), "GameCard_Info");
                            ini.Write("AccessControlFlags", gcInfo.AccessControlFlags.ToString(), "GameCard_Info");
                            ini.Write("ReadWaitTime", gcInfo.ReadWaitTime.ToString(), "GameCard_Info");
                            ini.Write("ReadWaitTime2", gcInfo.ReadWaitTime2.ToString(), "GameCard_Info");
                            ini.Write("WriteWriteTime", gcInfo.WriteWriteTime.ToString(), "GameCard_Info");
                            ini.Write("WriteWriteTime2", gcInfo.WriteWriteTime2.ToString(), "GameCard_Info");
                            ini.Write("FirmwareMode", gcInfo.FirmwareMode.ToString(), "GameCard_Info");
                            ini.Write("CUPVersion", gcInfo.CUPVersion.ToString(), "GameCard_Info");
                            ini.Write("CUPID", gcInfo.CUPID.ToString(), "GameCard_Info");
                            // end dump to ini



                            break;
                        default:
                            Console.WriteLine("Usage: hacbuild.exe read xci <IN>");
                            break;
                    }
                    break;

                case "hfs0":
                    HFS0Manager.BuildHFS0(args[1], args[2]);
                    break;
                case "xci":
                    XCIManager.BuildXCI(args[1], args[2]);
                    break;
                case "xci_auto":
                    string inPath = Path.Combine(Environment.CurrentDirectory,  args[1]);
                    string outPath = Path.Combine(Environment.CurrentDirectory, args[2]);
                    string tmpPath = Path.Combine(inPath, "root_tmp");
                    Directory.CreateDirectory(tmpPath);

                    HFS0Manager.BuildHFS0(Path.Combine(inPath, "secure"), Path.Combine(tmpPath, "secure"));
                    HFS0Manager.BuildHFS0(Path.Combine(inPath, "normal"), Path.Combine(tmpPath, "normal"));
                    HFS0Manager.BuildHFS0(Path.Combine(inPath, "update"), Path.Combine(tmpPath, "update"));
                    if(Directory.Exists(Path.Combine(inPath, "logo")))
                        HFS0Manager.BuildHFS0(Path.Combine(inPath, "logo"), Path.Combine(tmpPath, "logo"));
                    HFS0Manager.BuildHFS0(tmpPath, Path.Combine(inPath, "root.hfs0"));

                    XCIManager.BuildXCI(inPath, outPath);

                    File.Delete(Path.Combine(inPath, "root.hfs0"));
                    Directory.Delete(tmpPath, true);
                    break;
                default:
                    PrintUsage();
                    break;
            }


   

           
        }
        static bool LoadKeys()
        {
            bool ret = false;
            try
            {
                StreamReader file = new StreamReader("keys.txt");

                string line;
                while((line = file.ReadLine()) != null) 
                {
                    string[] parts = line.Split('=');
                    if (parts.Length < 2) continue;

                    string name = parts[0].Trim(" \0\n\r\t".ToCharArray());
                    string key = parts[1].Trim(" \0\n\r\t".ToCharArray());

                    //Console.WriteLine("{0} = {1}", name, key);

                    if (name == "xci_header_key")
                    {
                        XCIManager.XCI_GAMECARDINFO_KEY = Utils.StringToByteArray(key);
                        ret = true;
                    }
                }

            } catch(Exception ex)
            {
                Console.WriteLine("[ERR] keys.txt is either missing or unaccessible.");
                ret = false;
            }
            return ret;
           
        }
        static void PrintUsage()
        {
            Console.WriteLine("Usage: hacbuild.exe hfs0/xci input_folder output_file");
            Console.WriteLine("OR");
            Console.WriteLine("Usage: hacbuild.exe xci_auto input_folder output_file");
            Console.WriteLine("OR");
            Console.WriteLine("Usage: hacbuild.exe read xci input_file");
        }


    }
}
