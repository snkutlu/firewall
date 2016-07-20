firewall_rule 'logging' do
  command :log
  logging :droppedconnections
end

node.override['firewall']['windows']['defaults'] = {
  policy: {
    input: 'blockinbound',
    output: 'blockoutbound'
  }
}
