using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.DirectoryServices.Protocols;

namespace S4UTomato
{
    public class Ldap
    {
        public static SearchResultEntryCollection GetSearchResultEntries(LdapConnection connection, string distinguishedName, string ldapFilter, System.DirectoryServices.Protocols.SearchScope searchScope, string[] attributeList)
        {
            SearchRequest searchRequest = new SearchRequest(distinguishedName, ldapFilter, searchScope, attributeList);
            // The SecurityDescriptorFlagControl class is used to pass flags to the server to control various security descriptor behaviors.
            searchRequest.Controls.Add(new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl));
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
            return searchResponse.Entries;
        }

        // Code taken from Rubeus
        public static DirectoryEntry LocateAccount(string username, string domain, string domainController)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;

            try
            {
                directoryObject = Networking.GetLdapSearchRoot(null, "", domainController, domain);
                userSearcher = new DirectorySearcher(directoryObject);
                userSearcher.PageSize = 1;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("[-] Error creating the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("[-] Error creating the domain searcher: {0}", ex.Message);
                }
                return null;
            }

            // check to ensure that the bind worked correctly
            try
            {
                string dirPath = directoryObject.Path;
                Console.WriteLine("[*] Searching for the target computer account");
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("[-] Error validating the domain searcher: {0}", ex.Message);
                return null;
            }

            try
            {
                string userSearchFilter = String.Format("(samAccountName={0})", username);
                userSearcher.Filter = userSearchFilter;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return null;
            }

            try
            {
                SearchResult user = userSearcher.FindOne();

                if (user == null)
                {
                    Console.WriteLine("[!] Target account not found");
                }

                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                Console.WriteLine("[*] Target user found: {0}", distinguishedName);

                return user.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("[-] Error executing the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("[-] Error executing the domain searcher: {0}", ex.Message);
                }
                return null;
            }
        }
    }


}
