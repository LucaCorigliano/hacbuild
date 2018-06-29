using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace hacbuild
{
    internal static class XCIManager
    {

        // Important notes
        // - What the hell is package id ?
        

        internal const UInt64 HFS0_START = 0xf000;                  // Offset (in bytes) for /root.hfs0 in a xci file
        internal const int XCI_SIGNATURE_SIZE = 0x100;              // RSA Signature at the start of a xci file
        internal const int XCI_IV_SIZE = 0x10;                      // Length of the AES-128-CBC IV for GameInfo Encryption/Decryption
        internal const int XCI_HASH_SIZE = 0x20;                    // Length of SHA256 hashes
        internal const int XCI_GAMECARD_INFO_LENGTH = 0x70;         // Length of GameCard Info
        internal const int XCI_GAMECARD_INFO_PADDING_LENGTH = 0x38; // Length of the empty data at the end of GameInfo

        // Decryption key of GameInfo 
        // Google it : "XCI Header Key"
        internal static byte[] XCI_GAMECARDINFO_KEY = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        // THIS IS NOT THE KEY, JUST A SHA256 HASH TO CHECK THE VALIDITY
        internal static byte[] XCI_GAMECARD_KEY_SHA256 = new byte[] { 0x2E, 0x36, 0xCC, 0x55, 0x15, 0x7A, 0x35, 0x10, 0x90, 0xA7, 0x3E, 0x7A, 0xE7, 0x7C, 0xF5, 0x81, 0xF6, 0x9B, 0x0B, 0x6E, 0x48, 0xFB, 0x06, 0x6C, 0x98, 0x48, 0x79, 0xA6, 0xED, 0x7D, 0x2E, 0x96 };

        /* ///////////////////// ////////////////////// */


        // This is prone to failure if the cartridge has a value that it's not in this enum.
        // TODO There should be some code to handle this
        internal enum CartridgeType : byte
        {
            CARTSIZE_1GB = 0xFA,
            CARTSIZE_2GB = 0xF8,
            CARTSIZE_4GB = 0xF0,
            CARTSIZE_8GB = 0xE0,
            CARTSIZE_16GB = 0xE1,
            CARTSIZE_32GB = 0xE2
        }


        // GameCard info when decrypted
        internal struct gamecard_info
        {
            internal UInt64 Version;
            internal UInt32 AccessControlFlags;
            internal UInt32 ReadWaitTime;
            internal UInt32 ReadWaitTime2;
            internal UInt32 WriteWriteTime;
            internal UInt32 WriteWriteTime2;
            internal UInt32 FirmwareMode;
            internal UInt32 CUPVersion;
            internal UInt32 UnkEmpty;
            internal UInt64 UpdatePartitionHash;
            internal UInt64 CUPID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_GAMECARD_INFO_PADDING_LENGTH)]
            internal byte[] Padding;

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendFormat("GamecardInfo [Decrypted]:\n\n");
  
                sb.AppendFormat("Version: 0x{0:X}\n", Version);
                sb.AppendFormat("AccessControlFlags: 0x{0:X}\n", AccessControlFlags);
                sb.AppendFormat("ReadWaitTime: 0x{0:X}\n", ReadWaitTime);
                sb.AppendFormat("ReadWaitTime2: 0x{0:X}\n", ReadWaitTime2);
                sb.AppendFormat("WriteWriteTime: 0x{0:X}\n", WriteWriteTime);
                sb.AppendFormat("WriteWriteTime2: 0x{0:X}\n", WriteWriteTime2);
                sb.AppendFormat("FirmwareMode: 0x{0:X}\n", FirmwareMode);
                sb.AppendFormat("CUPVersion: 0x{0:X}\n", CUPVersion);
                sb.AppendFormat("UnkEmpty: 0x{0:X}\n", UnkEmpty);
                sb.AppendFormat("UpdatePartitionHash: 0x{0:X}\n", UpdatePartitionHash); // TODO This needs to be filled
                sb.AppendFormat("CUPID: 0x{0:X}\n", CUPID);

                return sb.ToString();
            }
        }

        // XCI Header 
        internal struct xci_header
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_SIGNATURE_SIZE)]
            internal byte[] Signature; // This is ignored, so we can generate a random one or ignore it [v]
            internal UInt32 Magic; // HEAD  [v]
            internal UInt32 SecureOffset; // /secure partition HFS0 <====== [v]
            internal UInt32 BackupAreaAddress; // backup start index [v]
            internal byte KEK; // Title KEK Index [?] <== check how it varies from game to game
            internal CartridgeType CartType; // [?] Proper calculation is needed
            internal byte HeaderVersion; // [v]
            internal byte Flag; // [v] This seems static
            internal UInt64 PackageID; // [x]
            internal UInt64 CardSize;  // [?] <== compare with other games
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_IV_SIZE)]
            internal byte[] GamecardIV; // [?] <== What's the key?
            internal UInt64 HFS0Offset;  // [v] Pointer to /root.hfs0 start
            internal UInt64 HFS0HeaderSize; // [v] HFS0 Header size
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_HASH_SIZE)]
            internal byte[] HFS0HeaderHash; // [v] HFS0 Header hash
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_HASH_SIZE)]
            internal byte[] InitialDataHash; // [x]
            internal UInt32 SecureModeFlag; // [v]
            internal UInt32 TitleKeyFlag; // [v]
            internal UInt32 KeyFlag; // [v]
            internal UInt32 NormalAreaEndAddress; // [v] /normal.hfs0 end
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = XCI_GAMECARD_INFO_LENGTH)]
            internal byte[] GamecardInfo; // [x] Gamecard info

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();

                sb.AppendFormat("Signature: {0}\n", BitConverter.ToString(Signature));
                sb.AppendFormat("Magic: {0}\n", Encoding.ASCII.GetString(BitConverter.GetBytes(Magic)));
                sb.AppendFormat("SecureOffset: 0x{0:X} * 0x200\n", SecureOffset);
                sb.AppendFormat("BackupOffset: 0x{0:X} * 0x200\n", BackupAreaAddress);
                sb.AppendFormat("KEK Index: 0x{0:X}\n", KEK);
                sb.AppendFormat("CartType: {0}\n", CartType.ToString());
                sb.AppendFormat("HeaderVersion: 0x{0:X}\n", HeaderVersion);
                sb.AppendFormat("Flag: 0x{0:X}\n", Flag);
                sb.AppendFormat("PackageID: {0}\n", BitConverter.ToString(BitConverter.GetBytes(PackageID)));
                sb.AppendFormat("CardSize: 0x{0} * 0x200\n", CardSize);
                sb.AppendFormat("IV (raw-data): {0}\n", BitConverter.ToString(GamecardIV));
                sb.AppendFormat("HFS0Offset: 0x{0:X}\n", HFS0HeaderSize);
                sb.AppendFormat("HFS0HeaderSize: 0x{0:X}\n", HFS0HeaderSize);
                sb.AppendFormat("HFS0HeaderHash: {0}\n", BitConverter.ToString(HFS0HeaderHash));
                sb.AppendFormat("InitialDataHash: {0}\n", BitConverter.ToString(InitialDataHash));
                sb.AppendFormat("SecureModeFlag: 0x{0:X}\n", SecureModeFlag);
                sb.AppendFormat("TitleKeyFlag: 0x{0:X}\n", TitleKeyFlag);
                sb.AppendFormat("KeyFlag: 0x{0:X}\n", KeyFlag);
                sb.AppendFormat("NormalAreaEndAddress: 0x{0:X}\n", NormalAreaEndAddress);
                sb.AppendFormat("GamecardInfo [Encrypted]: {0}\n", BitConverter.ToString(GamecardInfo));
                return sb.ToString();
            }
        }


        // Methods
        internal static gamecard_info DecryptGamecardInfo(xci_header header)
        {
            // REVERSE THA IV
            byte[] iv_flipped = new byte[XCIManager.XCI_IV_SIZE];
            Array.Copy(header.GamecardIV, iv_flipped, XCIManager.XCI_IV_SIZE);
            Array.Reverse(iv_flipped);

            // GameCardInfo Decrypt
            var decrypt = Program.AES128CBC.CreateDecryptor(XCIManager.XCI_GAMECARDINFO_KEY, iv_flipped);
            var gcInfoStream = new MemoryStream(header.GamecardInfo);
            var gcCryptoStream = new CryptoStream(gcInfoStream, decrypt, CryptoStreamMode.Read);

            // Create the struct
            XCIManager.gamecard_info gamecardInfoStruct = Utils.FromStream<XCIManager.gamecard_info>(gcCryptoStream);

            // Clean stuff up
            gcInfoStream.Close();
            gcCryptoStream.Close();
            decrypt.Dispose();

            return gamecardInfoStruct;
        }



        internal static bool BuildXCI(string inDir, string outFile)
        {
            // root.hfs0 contains secure/update/normal which are hfs0 on their owno
            string rootPath = Path.Combine(inDir, "root.hfs0");
            // gameData.ini contains vital data to build the XCI
            string iniPath = Path.Combine(inDir, "game_info.ini");
            

            if(!File.Exists(rootPath))
            {
                Console.WriteLine("[ERR] {0} does not exist.", rootPath);
                return false;
            }


           

            xci_header header = new xci_header();
            gamecard_info gcInfo = new gamecard_info();

            // Static stuff
            header.Magic = 0x44414548; // HEAD < -- XCI Header
            header.BackupAreaAddress = 0xFFFFFFFF; // This is probably reserved for future use 
            header.HeaderVersion = (byte)0x0; // This is probably reserved for future use
            header.Flag = 0;  // This is probably reserved for future use
            header.SecureModeFlag = 1; // Secure mode enabled
            header.TitleKeyFlag = 2;
            header.KeyFlag = 0;

            // Fake RSA signature
            byte[] fakeSignature = new byte[XCI_SIGNATURE_SIZE];
            Program.Rand.NextBytes(fakeSignature);
            header.Signature = fakeSignature;


            // Ini loaded stuff
            if (File.Exists(iniPath))
            {
                IniFile iniFile = new IniFile(iniPath);
                // Header
                header.KEK = byte.Parse(iniFile.Read("KEKIndex", "XCI_Header"));
                header.GamecardIV = iniFile.ReadBytes("GamecardIV", "XCI_Header");
                header.InitialDataHash = iniFile.ReadBytes("InitialDataHash", "XCI_Header");
                header.PackageID = UInt64.Parse(iniFile.Read("PackageID", "XCI_Header"));
                // Gamecard Info
                gcInfo.Version = UInt64.Parse(iniFile.Read("Version", "GameCard_Info"));
                gcInfo.AccessControlFlags = UInt32.Parse(iniFile.Read("AccessControlFlags", "GameCard_Info"));
                gcInfo.ReadWaitTime = UInt32.Parse(iniFile.Read("ReadWaitTime", "GameCard_Info"));
                gcInfo.ReadWaitTime2 = UInt32.Parse(iniFile.Read("ReadWaitTime2", "GameCard_Info"));
                gcInfo.WriteWriteTime = UInt32.Parse(iniFile.Read("WriteWriteTime", "GameCard_Info"));
                gcInfo.WriteWriteTime2 = UInt32.Parse(iniFile.Read("WriteWriteTime2", "GameCard_Info"));
                gcInfo.FirmwareMode = UInt32.Parse(iniFile.Read("FirmwareMode", "GameCard_Info"));
                gcInfo.CUPVersion = UInt32.Parse(iniFile.Read("CUPVersion", "GameCard_Info"));
                gcInfo.CUPID = UInt64.Parse(iniFile.Read("CUPID", "GameCard_Info"));

            }
            else
            {
                Console.WriteLine("[WARN] {0} does not exist. Data will be randomized (and the XCI could not work)", iniPath);
                // Header
                header.KEK = 0;
                Program.Rand.NextBytes(header.GamecardIV);
                header.PackageID = Utils.LongRandom(0, 100000000000000000, Program.Rand);

                // Gamecard Info - Taken from Cave Story (and pretty much universal)
                gcInfo.Version = 1;
                gcInfo.AccessControlFlags = 10551313;
                gcInfo.ReadWaitTime = 5000 ;
                gcInfo.ReadWaitTime2 = 0;
                gcInfo.WriteWriteTime = 0;
                gcInfo.WriteWriteTime2 = 0;
                gcInfo.FirmwareMode = 790784;
                gcInfo.CUPVersion = 450;
                gcInfo.CUPID = 72057594037930006;
            }

            // Read root.hfs0 raw (for header size and hash)
            byte[] rootHeader = HFS0Manager.GetHFS0Header(rootPath); 
            header.HFS0HeaderSize = Convert.ToUInt64( rootHeader.Length);

            // hfs0 should be 0x200 aligned in order to properly work. // TODO should it?
            if(header.HFS0HeaderSize % 0x200 != 0)
            {
                Console.WriteLine("[WARN] root.hfs0 is not 0x200 aligned.");
            }

            // Calculating SHA256 of root.hfs0 header
            header.HFS0HeaderHash = Program.SHA256.ComputeHash(rootHeader);
      

            // Read root.hfs0 (for partition details)
            HFS0Manager.hfs0_header rootHeaderManaged = new HFS0Manager.hfs0_header();
            List<HFS0Manager.hfs0_file_entry> rootFileEntries = new List<HFS0Manager.hfs0_file_entry>();
            List<string> rootStringTable = new List<string>();
            HFS0Manager.GetHFS0Managed(rootPath, ref rootHeaderManaged, ref rootFileEntries, ref rootStringTable);

            int partitionIndex = 0;
            foreach(var fileName in rootStringTable)
            {



                if (fileName == "secure")
                {
                    UInt64 secureOffset = Convert.ToUInt64(HFS0_START + header.HFS0HeaderSize + rootFileEntries[partitionIndex].Offset);
                    if (secureOffset % 0x200 != 0)
                    {
                        Console.WriteLine("[WARN] secure.hfs0 is not 0x200 aligned.");
                    }
                    // This is fine since we force partition order
                    header.SecureOffset = header.NormalAreaEndAddress = Convert.ToUInt32(secureOffset / 0x200);
                }

                partitionIndex++;
            }
            header.HFS0Offset = HFS0_START;

            UInt64 CardSize = Convert.ToUInt64(HFS0_START + (ulong)(new FileInfo(rootPath).Length));
            if (CardSize % 0x200 != 0)
            {
                Console.WriteLine("[WARN] card size is not 0x200 aligned.");
            }

            header.CardSize = CardSize / 0x200 - 1 ; // Excludes signature
 

       
            if (header.CardSize * 0x200l  > 16l * 1024l * 1024l * 1024l  )
                header.CartType = CartridgeType.CARTSIZE_32GB;
            else if(header.CardSize * 0x200l > 8l * 1024l * 1024l * 1024l )
                 header.CartType = CartridgeType.CARTSIZE_16GB;
            else if (header.CardSize * 0x200l  > 4l * 1024l * 1024l * 1024l )
                header.CartType = CartridgeType.CARTSIZE_8GB;
            else if (header.CardSize * 0x200l > 2l * 1024l * 1024l * 1024l )
                header.CartType = CartridgeType.CARTSIZE_4GB;
            else 
                header.CartType = CartridgeType.CARTSIZE_2GB;


            // Write encrypted gamecardinfo header
            byte[] rawGameCardInfo =  Utils.StructureToByteArray(gcInfo);

            // REVERSE THA IV
            byte[] iv_flipped = new byte[XCIManager.XCI_IV_SIZE];
            Array.Copy(header.GamecardIV, iv_flipped, XCIManager.XCI_IV_SIZE);
            Array.Reverse(iv_flipped);

            // GameCardInfo Encrypt
            var encrypt = Program.AES128CBC.CreateEncryptor(XCIManager.XCI_GAMECARDINFO_KEY, iv_flipped);
            var gcInfoStream = new MemoryStream(rawGameCardInfo);
            var gcCryptoStream = new CryptoStream(gcInfoStream, encrypt, CryptoStreamMode.Read);

            // Create the struct
            byte[] rawEncryptedGameCardInfo = new byte[XCI_GAMECARD_INFO_LENGTH];
            gcCryptoStream.Read(rawEncryptedGameCardInfo, 0, XCI_GAMECARD_INFO_LENGTH);

            // Clean stuff up
            gcInfoStream.Close();
            gcCryptoStream.Close();
            encrypt.Dispose();

            header.GamecardInfo = rawEncryptedGameCardInfo;

            FileStream fs;
            BinaryWriter bw;
            // Opening output file
            try
            {

                fs = new FileStream(outFile, FileMode.Create, FileAccess.Write);
                bw = new BinaryWriter(fs);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERR] Cannot create {0}.\n{1}", outFile, ex.Message);
                return false;
            }

            // Writing header
            bw.Write(Utils.StructureToByteArray(header));

            // Writing padding
            int toWrite00 = 0x6E00;

            for (int i = 0; i < toWrite00; i++)
            {
                bw.Write((byte)0x0);
            }
            int toWriteFF = 0x8000;

            for (int i = 0; i < toWriteFF; i++)
            {
                bw.Write((byte)0xFF);
            }

            // Writing data
            FileStream stream = new FileStream(rootPath, FileMode.Open, FileAccess.Read);
            byte[] buffer = new Byte[1024 * 5];
            int count = 0;
            while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                bw.Write(buffer, 0, count);
            stream.Close();




            return true;
        }

        internal static xci_header GetXCIHeader(string inFile)
        {
            // TODO Check magic
            FileStream fs = new FileStream(inFile, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            xci_header header = Utils.FromBinaryReader<xci_header>(br);
           
            
            br.Close();
            fs.Close();
            return header;
        }
    }
}
