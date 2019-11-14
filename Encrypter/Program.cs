namespace Encrypter
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    internal sealed class Program
    {
        private const int KEYLENGTH = 256;

        internal static void Main(string[] args)
        {
            if (args.Length < 2 || args.Length > 3)
            {
                Console.WriteLine("Usage:\nEncrypter filepath password [iteration=80000]");
                return;
            }

            string path = args[0];
            if (!File.Exists(path))
            {
                Console.WriteLine($"This file is not exists: {path}");
                return;
            }

            int iteration = 80000;
            if (args.Length > 2)
            {
                if (!int.TryParse(args[2], out iteration))
                {
                    Console.WriteLine($"This is not valid iteration: {args[2]}");
                    return;
                }
            }

            var pass = args[1];
            if (pass.Length < 3)
            {
                Console.WriteLine($"This password is too short: {pass}");
                return;
            }

            var content = File.ReadAllBytes(path);
            try
            {
                if (path.EndsWith(".nc"))
                {
                    File.WriteAllBytes(path.Substring(0, path.Length - 3), Decrypt(content, pass, iteration));
                }
                else
                {
                    File.WriteAllBytes($"{path}.nc", Encrypt(content, pass, iteration));
                }
            }
            catch
            {
                Console.WriteLine("Wrong password!");
            }
        }

        private static byte[] Decrypt(byte[] encodedBytes, string pass, int iterations)
        {
            if (encodedBytes == null || encodedBytes.Length == 0) { throw new ArgumentNullException(nameof(encodedBytes)); }
            if (string.IsNullOrEmpty(pass)) { throw new ArgumentNullException(nameof(pass)); }

            var saltBytes = encodedBytes.Take(KEYLENGTH / 8).ToArray();
            var ivBytes = encodedBytes.Skip(KEYLENGTH / 8).Take(KEYLENGTH / 8).ToArray();
            var textBytes = encodedBytes.Skip((KEYLENGTH / 8) * 2).Take(encodedBytes.Length - ((KEYLENGTH / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(pass, saltBytes, iterations))
            {
                var keyBytes = password.GetBytes(KEYLENGTH / 8);
                using (var symKey = new RijndaelManaged())
                {
                    symKey.BlockSize = 256;
                    symKey.Mode = CipherMode.CBC;
                    symKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symKey.CreateDecryptor(keyBytes, ivBytes))
                    {
                        using (var ms = new MemoryStream(textBytes))
                        {
                            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[textBytes.Length];
                                var decryptedByteCount = cs.Read(plainTextBytes, 0, plainTextBytes.Length);
                                return plainTextBytes.Take(decryptedByteCount).ToArray();
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Encrypt(byte[] textBytes, string pass, int iterations)
        {
            if (textBytes == null || textBytes.Length == 0) { throw new ArgumentNullException(nameof(textBytes)); }
            if (string.IsNullOrEmpty(pass)) { throw new ArgumentNullException(nameof(pass)); }

            var saltBytes = GenerateEntropy();
            var ivBytes = GenerateEntropy();
            using (var password = new Rfc2898DeriveBytes(pass, saltBytes, iterations))
            {
                var keyBytes = password.GetBytes(KEYLENGTH / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivBytes))
                    {
                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(textBytes, 0, textBytes.Length);
                                cs.FlushFinalBlock();

                                var cipherTextBytes = saltBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivBytes).ToArray();
                                return cipherTextBytes.Concat(ms.ToArray()).ToArray();
                            }
                        }
                    }
                }
            }
        }

        private static byte[] GenerateEntropy()
        {
            var entropy = new byte[32];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(entropy);
            }

            return entropy;
        }
    }
}
