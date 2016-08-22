# Windows platform defult settings: block undefined inbould traffic, allow all outgoing traffic
default['firewall']['windows']['defaults'] = {
  policy: {
    input: 'blockinbound',
    output: 'allowoutbound'
  }
}

# Defaults to keep existing rules already defined in Windows Firewall by installed applications or manually
# If this is not wanted, set this to false in your wrapper cookbook. etc
default['firewall']['windows']['keep_existing_rules'] = true
