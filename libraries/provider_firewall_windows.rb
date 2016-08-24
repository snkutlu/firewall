#
# Author:: Sander van Harmelen (<svanharmelen@schubergphilis.com>)
# Updated:: Suleyman Kutlu (<skutlu@schubergphilis.com>)
# Cookbook Name:: firewall
# Provider:: windows
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

class Chef
  class Provider::FirewallWindows < Chef::Provider::LWRPBase
    include FirewallCookbook::Helpers::Windows

    provides :firewall, os: 'windows'

    def whyrun_supported?
      false
    end

    action :install do
      next if disabled?(new_resource)

      converge_by('enable and start Windows Firewall service') do
        service 'MpsSvc' do
          action [:enable, :start]
        end
      end
    end

    action :restart do
      next if disabled?(new_resource)

      converge_by('Apply rule changes (if any) and restart Windows Firewall service') do
        # ensure it's initialized
        new_resource.rules({}) unless new_resource.rules
        new_resource.rules['windows'] = {} unless new_resource.rules['windows']
        new_resource.rules['windows']['log'] = {}
        new_resource.rules['windows']['block'] = {}
        new_resource.rules['windows']['allow'] = {}
        #
        # By default logging is disabled on Windows Firewall. If no logging rules provided, these will be in effect.
        #
        new_resource.rules['windows']['log']['droppedconnections'] = {}
        new_resource.rules['windows']['log']['droppedconnections']['action'] = 'disable'
        new_resource.rules['windows']['log']['allowedconnections'] = {}
        new_resource.rules['windows']['log']['allowedconnections']['action'] = 'disable'

        # Retrieve current running rules into a hash
        current_rules = retrieve_all_rules

        firewall_rules = run_context.resource_collection.select { |item| item.is_a?(Chef::Resource::FirewallRule) }
        firewall_rules.each do |firewall_rule|
          next unless firewall_rule.action.include?(:create) && !firewall_rule.should_skip?(:create)
          build_firewall_rule_hash(firewall_rule, new_resource.rules['windows'], current_rules)
        end

        # Apply rules in order:
        # First logging rules
        # -------------------
        # If logging rules are not provided, then execute them
        # execute_rules(new_resource.rules['windows']['log'])
        current_logging = retrieve_current_logging
        new_resource.rules['windows']['log'].each do |name, parameters|
          execute_rule("set currentprofile logging #{name} #{parameters['action']}") unless current_logging[name] == parameters['action']
        end

        # Then apply block and allow rules in order
        execute_rules(new_resource.rules['windows']['block']) unless new_resource.rules['windows']['block'].empty?
        execute_rules(new_resource.rules['windows']['allow']) unless new_resource.rules['windows']['allow'].empty?

        # If it is not desired to keep existing unwanted rules...
        # Find the rules to be removed from current list and delete them
        unless new_resource.keep_existing_rules
          to_delete = {}
          current_rules.each do |name, _parameters|
            next if new_resource.rules['windows']['allow'].key?(name) || new_resource.rules['windows']['block'].key?(name)
            to_delete[name] ||= {}
            to_delete[name]['firewall_command'] = 'delete'
          end
          execute_rules(to_delete) unless to_delete.empty?
        end

        # Apply desired default firewall policy at the end
        current_policy = retrieve_current_policy
        desired_input_policy = node['firewall']['windows']['defaults']['policy']['input']
        desired_output_policy = node['firewall']['windows']['defaults']['policy']['output']
        unless current_policy['input'] == desired_input_policy && current_policy['output'] == desired_output_policy
          execute_rule("set currentprofile firewallpolicy #{desired_input_policy},#{desired_output_policy}")
        end
        new_resource.updated_by_last_action(true)
      end
    end

    action :disable do
      next if disabled?(new_resource)

      converge_by('disable and stop Windows Firewall service') do
        if active?
          disable!
          Chef::Log.info("#{new_resource} disabled.")
          new_resource.updated_by_last_action(true)
        else
          Chef::Log.debug("#{new_resource} already disabled.")
        end

        service 'MpsSvc' do
          action [:disable, :stop]
        end
      end
    end

    action :flush do
      next if disabled?(new_resource)

      reset!
      Chef::Log.info("#{new_resource} reset.")
    end
  end
end
