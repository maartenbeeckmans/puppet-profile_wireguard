#
define profile_wireguard::interface (
  String                                      $private_key,
  Stdlib::Port                                $listen_port,
  Enum['ifupd', 'wg-quick', 'none']           $method,
  Optional[Stdlib::IP::Address::V4]           $address4,
  Enum['present', 'absent']                   $ensure                = 'present',
  Optional[Stdlib::IP::Address::V4::Nosubnet] $gateway4              = undef,
  Array[Stdlib::IP::Address]                  $dns                   = [],
  Optional[Integer[1,9202]]                   $mtu                   = undef,
  Hash                                        $peers                 = {},
  Boolean                                     $manage_firewall_entry = $::profile_wireguard::manage_firewall_entry,
) {
  wireguard::interface { $name:
    ensure      => $ensure,
    private_key => $private_key,
    listen_port => $listen_port,
    method      => $method,
    address4    => $address4,
    gateway4    => $gateway4,
    dns         => $dns,
    mtu         => $mtu,
    peers       => $peers,
  }

  if $manage_firewall_entry {
    $peers.each | $peer_name, $peer_options | {
      if $peer_options['endpoint'] {
        $_peer_address = regsubst($peer_options['endpoint'], ':.*', '')

        firewall { "${listen_port} wireguard accept ${peer_name}":
          source      => $_peer_address,
          destination => $facts['networking']['ip'],
          dport       => $listen_port,
          proto       => 'udp',
          action      => 'accept',
          chain       => 'WIREGUARD',
        }
      } else {
        firewall { "${listen_port} wireguard accept ${peer_name}":
          destination => $facts['networking']['ip'],
          dport       => $listen_port,
          proto       => 'udp',
          action      => 'accept',
          chain       => 'WIREGUARD',
        }
      }
    }
  }
}
