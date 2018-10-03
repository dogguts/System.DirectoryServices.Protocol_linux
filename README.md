## Summary

**Proof-Of-Concept** port of core-fx "System.DirectoryServices.Protocols" to Linux (using libldap)

The ideal port would be fully managed of course, but unfortunately isn't here (yet?), so for the time being...


## Nuget

[https://www.nuget.org/packages/S.DS.P.linux](https://www.nuget.org/packages/S.DS.P.linux/)


## Prerequisites

* Linux (obviously)

* .NET Core 2.1(+)

* libldap

## What isn't working / known issues
* Most of the SessionOptions aren't implemented
* Referrals are not implemented
* Only Anonymous and Basic authentication are work
* No LDAPS, but StartTransportLayerSecurity works


## Tested

* Debian 9-x64, .NET Core SDK 2.1.300, libldap-2.4-2
* Directories: 
 * 389 Directory Server (1.3.4.0)
 * Active Directory (2012 R2)


## Disclaimer

Quick (and somewhat dirty) port that suits my personal needs and might serve yours.
**Use at your onwn risk**





## Relevant github issue

[Support System.DirectoryServices.Protocols on Linux/Mac #24843](https://github.com/dotnet/corefx/issues/24843)

