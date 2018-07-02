using System;

namespace System.DirectoryServices.Protocols
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            /* 
                        var ldapident = new LdapDirectoryIdentifier("uzgldap389", 389, false, false);

                        var nc = new System. Net.NetworkCredential("employeeNumber=32233,ou=persoon,dc=internal,dc=uzgent,dc=be", "xxx");

                        LdapConnection lc = new LdapConnection(ldapident, nc, AuthType.Basic);
                        lc.SessionOptions.ProtocolVersion = 3;
                        //var x = DsmlNonHttpUri;

                        var sRequest = new SearchRequest("ou=persoon,dc=internal,dc=uzgent,dc=be", "uzguid=bve", SearchScope.OneLevel, new String[] { "dn", "cn","mobile","jpegPhoto" });
                        var sResponse = lc.SendRequest(sRequest) as SearchResponse;

                        foreach (SearchResultEntry entry in sResponse.Entries) {
                            string foundDN = entry.DistinguishedName;
                            Console.WriteLine("Found: " + foundDN);
                            Console.WriteLine("  |-> " + entry.Attributes["cn"][0].ToString());
                            Console.WriteLine("  |-> " + entry.Attributes["mobile"][0].ToString());
                            var pic = entry.Attributes["jpegPhoto"].GetValues(typeof(byte[]))[0];
                        }
            */
            //"ssss", new object[] { null, "", "abc", "\0" }, new byte[] { 4, 0, 4, 0, 4, 3, 97, 98, 99, 4, 1, 0 } };
        var result =     BerConverter.Encode("ssss", new object[] { null, "", "abc", "\0" });



        }
    }//    
}
