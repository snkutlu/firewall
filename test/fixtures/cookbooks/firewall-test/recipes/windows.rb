node.override['firewall']['windows']['defaults'] = {
  policy: {
    input: 'blockinbound',
    output: 'blockoutbound'
  }
}

node.override['firewall']['windows']['keep_existing_rules'] = false

firewall_rule 'logging' do
  command :log
  logging :droppedconnections
end

firewall_rule 'DNS_TCP' do
  port 53
  protocol :tcp
  direction :out
  command :allow
end

firewall_rule 'DNS_UDP' do
  port 53
  protocol :udp
  direction :out
  command :allow
end

firewall_rule 'RDesktop' do
  port 3389
  protocol :tcp
  direction :in
  command :allow
end
