using System;
using System.IO;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;


namespace ConsoleTestApp
{
    class Program
    {
        public static IConfiguration Configuration { get; private set; }

        public class LdapDirectoryConfiguration
        {
            public string[] Server { get; set; }
            public int PortNumber { get; set; } = 389;
            public AuthType AuthType { get; set; }
            public string BindDn { get; set; }
            public string BindPasswordUserSecret { get; set; }
            public System.Net.NetworkCredential NetworkCredential
            {
                get
                {
                    if (!string.IsNullOrEmpty(BindDn))
                    {
                        return new System.Net.NetworkCredential(BindDn, Configuration[BindPasswordUserSecret]);
                    }
                    else
                    {
                        return null;
                    }
                }
            }
            public LdapDirectoryIdentifier LdapDirectoryIdentifier
            {
                get
                {
                    return new LdapDirectoryIdentifier(Server, PortNumber, false, false);
                }
            }
        }

        public static bool VerifyServerCertificateCallback(LdapConnection connection, X509Certificate certificate)
        {
            Console.WriteLine();
            return true;
        }

        static void Main(string[] args)
        {
            Configuration = new ConfigurationBuilder()
                         .SetBasePath(Directory.GetCurrentDirectory())
                         .AddJsonFile("appsettings.json", true)
                         .AddEnvironmentVariables()
                         .AddUserSecrets("consoletestapp-eb00853f-de89-4222-a3ec-7083267dd9d0")
                         .Build();

            //  var ldapident = new LdapDirectoryIdentifier("bl18-05.internal.uzgent.be", 389, false, false);

            //var ldapident = new LdapDirectoryIdentifier("ai.internal.uzgent.be", 389, false, false);

            var directoryConfigurations = Configuration.GetSection("DirectoryConfigurations").Get<Dictionary<string, LdapDirectoryConfiguration>>();
            var activeConfiguration = directoryConfigurations["AD"];

            var ldapDirectoryIdentifier = activeConfiguration.LdapDirectoryIdentifier;
            var networkCredential = activeConfiguration.NetworkCredential;
            var authType = activeConfiguration.AuthType;


            LdapConnection ldapConnection = new LdapConnection(ldapDirectoryIdentifier, networkCredential, authType);

            ldapConnection.SessionOptions.ProtocolVersion = 3;

            ldapConnection.SessionOptions.StartTransportLayerSecurity(new DirectoryControlCollection());
            ldapConnection.Bind(networkCredential);


            //var sRequest = new SearchRequest("ou=persoon,dc=internal,dc=uzgent,dc=be", "uzguid=bve", SearchScope.OneLevel, new String[] { "dn", "cn", "mobile", "jpegPhoto" });
            var sRequest = new SearchRequest("OU=LDAP,OU=UZUsers,DC=ai,DC=internal,DC=uzgent,DC=be", "employeeNumber=32233", SearchScope.Subtree, new String[] { "dn", "cn", "mobile", "jpegPhoto" });

            var sResponse = ldapConnection.SendRequest(sRequest) as SearchResponse;

            foreach (SearchResultEntry entry in sResponse.Entries)
            {

                string foundDN = entry.DistinguishedName;

                Console.WriteLine("Found: " + foundDN);

                Console.WriteLine("  |-> " + entry.Attributes["cn"][0].ToString());

                Console.WriteLine("  |-> " + entry.Attributes["mobile"]?[0].ToString() ?? "");

                var pic = entry.Attributes["jpegPhoto"]?.GetValues(typeof(byte[]))[0];

            }
        }
    }
}
