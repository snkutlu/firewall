# these tests only for windows
require 'spec_helper'


# expected_rules = [
#   %r{firewall add rule name="prepend" description="prepend" dir=in protocol=tcp localip=any localport=7788 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="block-192.168.99.99" description="block-192.168.99.99" dir=in protocol=tcp localip=any localport=any interfacetype=any remoteip=192.168.99.99 remoteport=any action=block},
#   %r{firewall add rule name="allow world to winrm" description="allow world to winrm" dir=in protocol=tcp localip=any localport=5989 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="ssh22" description="ssh22" dir=in protocol=tcp localip=any localport=22 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="ssh2222" description="ssh2222" dir=in protocol=tcp localip=any localport=2200,2222 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="temp1" description="temp1" dir=in protocol=tcp localip=any localport=1234 interfacetype=any remoteip=any remoteport=any action=block},
#   %r{firewall add rule name="temp2" description="temp2" dir=in protocol=tcp localip=any localport=1235 interfacetype=any remoteip=any remoteport=any action=block},
#   %r{firewall add rule name="addremove2" description="addremove2" dir=in protocol=tcp localip=any localport=1236 interfacetype=any remoteip=any remoteport=any action=block},
#   %r{firewall add rule name="duplicate0" description="same comment" dir=in protocol=tcp localip=any localport=1111 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="duplicate0" description="same comment" dir=in protocol=tcp localip=any localport=5431,5432 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="duplicate1" description="same comment" dir=in protocol=tcp localip=any localport=1111 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="duplicate1" description="same comment" dir=in protocol=tcp localip=any localport=5431,5432 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="ipv6-source" description="ipv6-source" dir=in protocol=tcp localip=any localport=80 interfacetype=any remoteip=2001:db8::ff00:42:8329 remoteport=any action=allow},
#   %r{firewall add rule name="range" description="range" dir=in protocol=tcp localip=any localport=1000-1100 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{firewall add rule name="array" description="array" dir=in protocol=tcp localip=any localport=1234,5000-5100,5678 interfacetype=any remoteip=any remoteport=any action=allow},
#   %r{set currentprofile logging allowedconnections disable},
#   %r{set currentprofile logging droppedconnections enable}
# ]

expected_rules = [
  "prepend",
  "block-192.168.99.99/32",
  "allow world to winrm",
  "ssh22",
  "ssh2222",
  "temp1",
  "temp2",
  "addremove2",
  "duplicate0",
  "duplicate1",
  "ipv6-source",
  "range",
  "array",
  "HTTP HTTPS",
  "ICMP from any",
  "RDesktop"
]

#describe file("#{ENV['HOME']}/windows-chef.rules"), if: windows? do
#  expected_rules.each do |r|
#    its(:content) { should match(r) }
#  end
#end

expected_rules.each do |r|
  describe command("netsh advfirewall firewall show rule name=\"#{r}\""), if: windows? do
    its(:stdout) { should match("Rule Name:\s+#{r}") }
  end
end

describe command('netsh advfirewall firewall show rule name="duplicate0"'), if: windows? do
  its(:stdout) { should match('LocalPort:\s+1111') }
end

describe command('netsh advfirewall firewall show rule name="duplicate1"'), if: windows? do
  its(:stdout) { should match('LocalPort:\s+1111') }
end

describe command('netsh advfirewall firewall show rule name=all | find /c "Rule Name"'), if: windows? do
  its(:stdout) { should match('19') }
end

describe command('netsh advfirewall show currentprofile logging | findstr LogDroppedConnections'), if: windows? do
  its(:stdout) { should match('Enable') }
end

describe command('netsh advfirewall show currentprofile logging | findstr LogAllowedConnections'), if: windows? do
  its(:stdout) { should match('Disable') }
end

describe command('netsh advfirewall show currentprofile firewallpolicy | findstr "Firewall Policy"'), if: windows? do
  its(:stdout) { should match('BlockInbound,BlockOutbound') }
end
