using System;
using System.Collections;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.DirectoryServices.ProtocolsX
{

    class Program
    {
  
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

             //var ldapident = new LdapDirectoryIdentifier("uzgldap389.internal.uzgent.be", 389, false, false);
            var ldapident = new LdapDirectoryIdentifier("ai.internal.uzgent.be", 389, false, false);



            var nc = new System.Net.NetworkCredential("employeeNumber=32233,ou=persoon,dc=internal,dc=uzgent,dc=be", "xxx");



            //LdapConnection lc = new LdapConnection(ldapident, nc, AuthType.Basic);
            LdapConnection lc = new LdapConnection(ldapident, null, AuthType.Negotiate);

            lc.SessionOptions.ProtocolVersion = 3;
          //  lc.SessionOptions.SaslMethod = "GSSAPI";
           var xx = lc.SessionOptions.SaslMethod;
            lc.Bind();
            //    lc.SessionOptions.DomainName = "uzge"
            //      lc.SessionOptions.DomainName = "uzgxldap389";

            //   lc.SessionOptions.StartTransportLayerSecurity(null);
            //var x = DsmlNonHttpUri;
            

            //var sRequest = new SearchRequest("ou=persoon,dc=internal,dc=uzgent,dc=be", "uzguid=bve", SearchScope.OneLevel, new String[] { "dn", "cn", "mobile", "jpegPhoto" });
            var sRequest = new SearchRequest("OU=LDAP,OU=UZUsers,DC=ai,DC=internal,DC=uzgent,DC=be", "employeeNumber=32233", SearchScope.Subtree, new String[] { "dn", "cn", "mobile", "jpegPhoto" });

            var sResponse = lc.SendRequest(sRequest) as SearchResponse;

            var x = lc.SessionOptions.DomainName;


            foreach (SearchResultEntry entry in sResponse.Entries) {

                string foundDN = entry.DistinguishedName;

                Console.WriteLine("Found: " + foundDN);

                Console.WriteLine("  |-> " + entry.Attributes["cn"][0].ToString());

                Console.WriteLine("  |-> " + entry.Attributes["mobile"]?[0].ToString()??"");

                var pic = entry.Attributes["jpegPhoto"]?.GetValues(typeof(byte[]))[0];

            }

        }
    }//    
}
