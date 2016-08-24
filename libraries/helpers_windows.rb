module FirewallCookbook
  module Helpers
    module Windows
      include FirewallCookbook::Helpers
      include Chef::Mixin::ShellOut

      def fixup_cidr(str)
        newstr = str.clone
        newstr.gsub!('0.0.0.0/0', 'any') if newstr.include?('0.0.0.0/0')
        newstr.gsub!('/0', '') if newstr.include?('/0')
        newstr
      end

      def windows_rules_filename
        "#{ENV['HOME']}/windows-chef.rules"
      end

      def active?
        @active ||= begin
          cmd = shell_out!('netsh advfirewall show currentprofile')
          cmd.stdout =~ /^State\sON/
        end
      end

      def enable!
        shell_out!('netsh advfirewall set currentprofile state on')
      end

      def disable!
        shell_out!('netsh advfirewall set currentprofile state off')
      end

      def reset!
        shell_out!('netsh advfirewall reset')
      end

      def delete_all_rules!
        shell_out!('netsh advfirewall firewall delete rule name=all')
      end

      def to_type(new_resource)
        cmd = new_resource.command
        type = if cmd == :reject || cmd == :deny
                 :block
               elsif cmd == :log
                 :log
               else
                 :allow
               end
        type
      end

      def build_rule(name, parameters)
        # Build firewall command to execute the rule
        rule = ''
        unless parameters['firewall_command'] == 'do_nothing'
          partial_command = parameters.sort.map { |k, v| "#{k}=#{v}" unless v == '' || k == 'firewall_command' }.join(' ')
          partial_command = "new #{partial_command}" if parameters['firewall_command'] == 'set'
          rule = "firewall #{parameters['firewall_command']} rule name=\"#{name}\" #{partial_command}"
        end
        rule
      end

      def execute_rule(rule)
        unless rule.empty?
          Chef::Log.debug "Firewall debug: Executing command: netsh advfirewall #{rule}"
          shell_out!("netsh advfirewall #{rule}")
        end
      end

      def execute_rules(rule_hash)
        rule_hash.each do |name, parameters|
          execute_rule(build_rule(name, parameters))
        end
      end

      def parse_desired_rule_parameters(new_resource)
        parameters = {}
        unless to_type(new_resource) == :log
          parameters['description'] = "\"#{new_resource.description}\""
          parameters['dir'] = new_resource.direction.to_s

          new_resource.program && parameters['program'] = "\"#{new_resource.program}\""
          new_resource.service && parameters['service'] = new_resource.service
          parameters['protocol'] = if new_resource.protocol == :icmp
                                     'icmpv4'
                                   else
                                     new_resource.protocol.to_s
                                   end

          if parameters['protocol'] =~ /icmp/
            if new_resource.icmp_type
              parameters['protocol'] = "\"#{parameters['protocol']}:#{new_resource.icmp_type}"
              if new_resource.icmp_code
                parameters['protocol'] << ",#{new_resource.icmp_code}\""
              else
                parameters['protocol'] << '"'
              end
            end
          end

          if new_resource.direction == :out
            parameters['localip'] = new_resource.source ? fixup_cidr(new_resource.source) : 'any'
            parameters['localport'] = if parameters['protocol'] =~ /icmp/
                                        ''
                                      else
                                        new_resource.source_port ? port_to_s(new_resource.source_port) : 'any'
                                      end
            parameters['interfacetype'] = new_resource.interface ? new_resource.interface : 'any'
            parameters['remoteip'] = new_resource.destination ? fixup_cidr(new_resource.destination) : 'any'
            parameters['remoteport'] = if parameters['protocol'] =~ /icmp/
                                         ''
                                       else
                                         new_resource.dest_port ? port_to_s(new_resource.dest_port) : 'any'
                                       end
          else
            parameters['localip'] = new_resource.destination ? fixup_cidr(new_resource.destination) : 'any'
            parameters['localport'] = if parameters['protocol'] =~ /icmp/
                                        ''
                                      else
                                        dport_calc(new_resource) ? port_to_s(dport_calc(new_resource)) : 'any'
                                      end
            parameters['interfacetype'] = new_resource.dest_interface ? new_resource.dest_interface : 'any'
            parameters['remoteip'] = new_resource.source ? fixup_cidr(new_resource.source) : 'any'
            parameters['remoteport'] = if parameters['protocol'] =~ /icmp/
                                         ''
                                       else
                                         new_resource.source_port ? port_to_s(new_resource.source_port) : 'any'
                                       end
          end

          parameters['action'] = to_type(new_resource).to_s
        end
        parameters
      end

      def build_firewall_rule_hash(firewall_rule, desired_rules, current_rules)
        type = to_type(firewall_rule)
        rule_name = type == :log ? firewall_rule.logging.to_s : firewall_rule.name

        # If it is a logging rule handle properly
        if type == :log
          desired_rules[type.to_s][rule_name]['action'] = 'enable'
        elsif desired_rules[type.to_s].key?(rule_name)
          Chef::Log.warn "Firewall rule named #{rule_name} already exists"
        else
          desired_rules[type.to_s][rule_name] = parse_desired_rule_parameters(firewall_rule)
          desired_rules[type.to_s][rule_name]['firewall_command'] = if !current_rules.key?(rule_name)
                                                                      'add'
                                                                    elsif rule_up_to_date?(desired_rules[type.to_s][rule_name], current_rules[rule_name], rule_name)
                                                                      'do_nothing'
                                                                    else
                                                                      'set'
                                                                    end
        end
      end

      def rule_exists?(name)
        @exists ||= begin
          cmd = shell_out!("netsh advfirewall firewall show rule name=\"#{name}\"", returns: [0, 1])
          cmd.stdout !~ /^No rules match the specified criteria/
        end
      end

      def retrieve_current_profile
        shell_out!('netsh advfirewall show currentprofile').stdout.match(/(\w+)\s+Profile Settings:/)[1]
      end

      def retrieve_current_logging
        logging = {}
        cmd = shell_out!('netsh advfirewall show currentprofile logging')
        cmd.stdout.chomp.split(/\r\n/).each do |line|
          logging['allowedconnections'] = Regexp.last_match(1).downcase if line =~ /^LogAllowedConnections\s+(\w+)$/
          logging['droppedconnections'] = Regexp.last_match(1).downcase if line =~ /^LogDroppedConnections\s+(\w+)$/
        end
        logging
      end

      def retrieve_current_policy
        policy = {}
        cmd = shell_out!('netsh advfirewall show currentprofile firewallpolicy')
        cmd.stdout.chomp.split(/\r\n/).each do |line|
          if line =~ /^Firewall Policy\s+(\w+),(\w+)$/
            policy['input'] = Regexp.last_match(1).downcase
            policy['output'] = Regexp.last_match(2).downcase
          end
        end
        policy
      end

      def show_all_rules!
        cmd = shell_out!('netsh advfirewall firewall show rule name=all')
        cmd.stdout.each_line do |line|
          Chef::Log.warn(line)
        end
      end

      def parse_current_rule_parameters(rule_list)
        name = ''
        all_rules = {}
        rule_list.each_with_index do |line, i|
          # Bypass empty lines
          next if line.length.zero?
          # First find the rule name
          if line =~ /^Rule Name:\s+(.*)$/
            name = Regexp.last_match(1).chomp
            all_rules[name] ||= {}
          end
          # We now have name then fill the hash for that named rule
          all_rules[name]['description'] = "\"#{Regexp.last_match(1).chomp}\"" if line =~ /^Description:\s+(.*)$/
          all_rules[name]['dir'] = Regexp.last_match(1).chomp.downcase if line =~ /^Direction:\s+(.*)$/
          all_rules[name]['localip'] = Regexp.last_match(1).chomp if line =~ /^LocalIP:\s+(.*)$/
          all_rules[name]['remoteip'] = Regexp.last_match(1).chomp if line =~ /^RemoteIP:\s+(.*)$/
          # Handle protocol carefully
          if line =~ /^Protocol:\s+(.*)$/
            all_rules[name]['protocol'] = Regexp.last_match(1).chomp.downcase
            # ICMP needs speclal handling
            if all_rules[name]['protocol'] =~ /icmp/
              all_rules[name]['protocol'] = "\"#{all_rules[name]['protocol']}:#{rule_list[i + 2].chomp.split(' ')[0]},#{rule_list[i + 2].chomp.split(' ')[1]}\""
            end
          end
          all_rules[name]['localport'] = Regexp.last_match(1).chomp if line =~ /^LocalPort:\s+(.*)$/
          all_rules[name]['remoteport'] = Regexp.last_match(1).chomp if line =~ /^RemotePort:\s+(.*)$/
          all_rules[name]['program'] = Regexp.last_match(1).chomp if line =~ /^Program:\s+(.*)$/
          all_rules[name]['service'] = Regexp.last_match(1).chomp if line =~ /^Service:\s+(.*)$/
          all_rules[name]['interfacetype'] = Regexp.last_match(1).chomp if line =~ /^InterfaceTypes:\s+(.*)$/
          all_rules[name]['action'] = Regexp.last_match(1).chomp if line =~ /^Action:\s+(.*)$/
        end
        all_rules
      end

      def retrieve_all_rules
        output = shell_out!('netsh advfirewall firewall show rule name=all verbose', returns: [0, 1])
        if output.exitstatus.nonzero? && output.stdout =~ /^No rules match/
          Chef::Log.warn('No firewall rules found')
          {}
        else
          parse_current_rule_parameters(output.stdout.sub(/^\r\n/, '').split(/\r\n/))
        end
      end

      def rule_up_to_date?(desired_rule_parameters, current_rule_parameters, rule_name)
        up_to_date = true
        desired_rule_parameters.each do |k, v|
          if current_rule_parameters[k].to_s.downcase !~ /^["]?#{v.to_s.downcase}["]?$/i
            up_to_date = false
            #require 'pry'
            #binding.pry if node['hostname'].downcase == 'argddb099'
            Chef::Log.debug("Firewall debug: Rule is changed: Rule name: #{rule_name}, Parameter: #{k}, Current value: #{current_rule_parameters[k].to_s.downcase}, Desired value: #{v.to_s.downcase}")
          end
        end
        up_to_date
      end
    end
  end
end
