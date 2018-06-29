using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

// THIS ASSUMES YOUR PC IS LITTLE-ENDIAN
namespace hacbuild
{
    static class HFS0Manager
    {
        internal const int HFS0_HEADER_LENGTH = 16;
        internal const int HFS0_ENTRY_LENGTH = 0x40;
        internal const int HFS0_HASH_LENGTH = 0x20;
        internal struct hfs0_header
        {
            internal UInt32 Magic; // HFS0
            internal UInt32 NumberOfFiles;
            internal UInt32 StringTableSize;
            internal UInt32 Reserved; // 0 
        }
        internal struct hfs0_file_entry
        {
            internal UInt64 Offset;
            internal UInt64 Size;
            internal UInt32 StringTableOffset;
            internal UInt32 HashedSize; // 0 or 200 (how much of the file is hashed)
            internal UInt64 Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = HFS0_HASH_LENGTH)]
            internal byte[] FileHash; 
        }

        internal static  void GetHFS0Managed(string inFile, ref hfs0_header header, ref List<hfs0_file_entry> entries, ref List<string> stringTable)
        {
            // TODO Check file integrity
            FileStream fs = new FileStream(inFile, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            header = Utils.FromBinaryReader<hfs0_header>(br);

            int offset = HFS0_HEADER_LENGTH;
            // Deserialize structs
            for(int i = 0; i < header.NumberOfFiles; i++)
            {
                fs.Seek(offset, SeekOrigin.Begin);
                hfs0_file_entry entry = Utils.FromBinaryReader<hfs0_file_entry>(br);
                entries.Add(entry);
                offset += HFS0_ENTRY_LENGTH;

            }
            // Parse string table
            for (int i = 0; i < header.NumberOfFiles; i++)
            {
                var entry = entries[i];
                fs.Seek(offset + entry.StringTableOffset, SeekOrigin.Begin);
                byte b = 0x0;
                List<byte> stringBytes = new List<byte>();
                while((b = br.ReadByte()) > 0)
                {
                    stringBytes.Add(b);
                }
                stringTable.Add(Encoding.ASCII.GetString(stringBytes.ToArray()));
            }

            br.Close();
            fs.Close();

        }
        internal static byte[] GetHFS0Header(string inFile)
        {
            FileStream fs = new FileStream(inFile, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            byte[] fileCountBytes = new byte[4];
            fs.Seek(4, SeekOrigin.Begin); // Skip magic
            br.Read(fileCountBytes, 0, 4);
            int fileCount = BitConverter.ToInt32(fileCountBytes, 0);
            byte[] stringTableLengthBytes = new byte[4];
            fs.Seek(8, SeekOrigin.Begin); // Skip fileCount
            br.Read(stringTableLengthBytes, 0, 4);
            int stringTableLength = BitConverter.ToInt32(stringTableLengthBytes, 0);

            int totalLength =  HFS0_HEADER_LENGTH + (HFS0_ENTRY_LENGTH * fileCount) + stringTableLength;
            fs.Seek(0, SeekOrigin.Begin); // Skip fileCount
            byte[] header = new byte[totalLength];
             br.Read(header, 0, totalLength);
            br.Close();
            fs.Close();
            return header;

        }
        internal static bool BuildHFS0(string inDir, string outFile)
        {
            Console.WriteLine("Building {0} from folder {1}...", outFile, inDir);
        

            hfs0_header header = new hfs0_header();
            header.Magic = 0x30534648; // HFS0

            List<hfs0_file_entry> fileEntries = new List<hfs0_file_entry>() ;
            List<string> stringTable = new List<string>();
            char[] objPath = new char[256];
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

            // Opening input directory
            if (!Directory.Exists(inDir))
            {
                Console.WriteLine("[ERR] Input folder {0} does not exist.", inDir);
                return false;
            }

            List<string> inputFiles = new List<string>();
            foreach(string file in Directory.GetFiles(inDir))
            {
                inputFiles.Add(Path.GetFileName(file));
            }

  




            // Handling root partitions for correct partition order
            if(inputFiles.Count >= 3 && inputFiles.Count <= 4 && inputFiles.Contains("secure") && inputFiles.Contains("normal") && inputFiles.Contains("update"))
            {
                if(inputFiles.Contains("logo"))
                {
                    Console.WriteLine("Treating {0} as CARD2 root hfs0", outFile);
                    inputFiles = new List<string>();
                    inputFiles.Add("update");
                    inputFiles.Add("normal");
                    inputFiles.Add("secure");
                    inputFiles.Add("logo");
                } else if(inputFiles.Count == 3)
                {
                    Console.WriteLine("Treating {0} as CARD1 root hfs0", outFile);
                    inputFiles = new List<string>();
                    inputFiles.Add("update");
                    inputFiles.Add("normal");
                    inputFiles.Add("secure");
                }
            }

            // Number of files in HFS0 archive
            header.NumberOfFiles = Convert.ToUInt32( inputFiles.Count);

            header.StringTableSize = 0;

            UInt64 fileEntry_relativeOffset = 0;
            // Building stringtable

            

            foreach (string file in inputFiles)
            {
                var absPath = Path.Combine(inDir, file);
                stringTable.Add(file);

                FileStream inputFS = new FileStream(absPath, FileMode.Open, FileAccess.Read);
                BinaryReader inputFSReader = new BinaryReader(inputFS);
                hfs0_file_entry fileEntry = new hfs0_file_entry();

                fileEntry.Offset = Convert.ToUInt64(fileEntry_relativeOffset);
                fileEntry.Size = Convert.ToUInt64(inputFS.Length);

                UInt64 paddedSize = Convert.ToUInt64( Math.Ceiling((double)fileEntry.Size / (double)0x200) * 0x200);
                fileEntry_relativeOffset += paddedSize;




                if (fileEntry.Size > 0x200)
                    fileEntry.HashedSize = 0x200;
                else
                    fileEntry.HashedSize = Convert.ToUInt32(fileEntry.Size);

                byte[] dataToHash = new byte[fileEntry.HashedSize];
                inputFSReader.Read(dataToHash, 0, dataToHash.Length);

                inputFSReader.Close();
                inputFS.Close();

                fileEntry.StringTableOffset = header.StringTableSize;
                fileEntry.FileHash = Program.SHA256.ComputeHash(dataToHash);


                header.StringTableSize += Convert.ToUInt32(file.Length + 1);

                fileEntries.Add(fileEntry);
            }

            // Calculate padding fo alignment
            uint bytesWrittenUntilNow = HFS0_HEADER_LENGTH + (HFS0_ENTRY_LENGTH * header.NumberOfFiles) + header.StringTableSize;
            uint bytesWrittenUntilNowPadded = Convert.ToUInt32(Math.Ceiling((double)bytesWrittenUntilNow / (double)0x200) * 0x200);
            uint bytesWrittenUntilNowDif = bytesWrittenUntilNowPadded - bytesWrittenUntilNow;

            header.StringTableSize += bytesWrittenUntilNowDif;

            bw.Write(Utils.StructureToByteArray(header));
            foreach(hfs0_file_entry fileEntry in fileEntries)
            {
                bw.Write(Utils.StructureToByteArray(fileEntry));
            }
            foreach(string str in stringTable)
            {
                bw.Write(str.ToCharArray());
                bw.Write((byte)0x00);
            }
            // Fill padding
            for (int i = 0; i < bytesWrittenUntilNowDif; i++)
            {
                bw.Write((byte)0x0);
            }
            foreach (string file in inputFiles)
            {
                var absPath = Path.Combine(inDir, file);
                FileStream stream = new FileStream(absPath, FileMode.Open, FileAccess.Read);
                byte[] buffer = new Byte[1024 * 5];
                int count = 0;
                while((count = stream.Read(buffer, 0, buffer.Length)) > 0)
                    bw.Write(buffer, 0, count);

                uint paddedLength = Convert.ToUInt32(Math.Ceiling((double)stream.Length / (double)0x200) * 0x200);

                uint difference = paddedLength - (uint)stream.Length;

                for(int i = 0; i < difference; i++)
                {
                    bw.Write((byte)0x0);
                }
                stream.Close();
            }
            bw.Close();
            fs.Close();



            Console.WriteLine("Operation successful");
                return true;
        }
    }
}
