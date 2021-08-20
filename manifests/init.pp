#
class profile_wireguard (
  Boolean $manage_sysctl,
  Boolean $manage_firewall_entry,
  Hash    $wireguard_interfaces,
  Hash    $wireguard_interface_defaults,
) {
  include ::wireguard

  if $manage_sysctl {
    if ! defined(Sysctl['net.ipv4.ip_forward']){
      sysctl{'net.ipv4.ip_forward':
        ensure => present,
        value  => '1',
      }
    }
    if ! defined(Sysctl['net.ipv4.xfrm4_gc_thresh']){
      sysctl{'net.ipv4.xfrm4_gc_thresh':
        ensure => present,
        value  => '32768',
      }
    }
    if ! defined(Sysctl['net.ipv4.conf.default.send_redirects']){
      sysctl{'net.ipv4.conf.default.send_redirects':
        ensure => present,
        value  => '0',
      }
    }
    if ! defined(Sysctl['net.ipv4.conf.all.send_redirects']){
      sysctl{'net.ipv4.conf.all.send_redirects':
        ensure => present,
        value  => '0',
      }
    }
    if ! defined(Sysctl['net.ipv4.conf.default.accept_redirects']){
      sysctl{'net.ipv4.conf.default.accept_redirects':
        ensure => present,
        value  => '0',
      }
    }
    if ! defined(Sysctl['net.ipv4.conf.all.accept_redirects']){
      sysctl{'net.ipv4.conf.all.accept_redirects':
        ensure => present,
        value  => '0',
      }
    }
  }

  if $manage_firewall_entry {
    firewall { '00000 accept everything in forward chain':
      chain  => 'FORWARD',
      action => 'accept',
      proto  => 'all',
    }

    firewallchain { 'WIREGUARD:filter:IPv4':
      ensure => 'present',
      purge  => true,
    }

    $_dports = $wireguard_interfaces.map | $if, $if_config | { $if_config['listen_port'] }

    firewall { '00001 wireguard to wireguard chain':
      proto => 'udp',
      dport => $_dports,
      chain => 'INPUT',
      jump  => 'WIREGUARD',
    }
  }

  create_resources('profile_wireguard::interface', $wireguard_interfaces, $wireguard_interface_defaults)
}
