#
define profile_wireguard::interface (
  String                        $private_key,
  Stdlib::Port                  $listen_port,
  Stdlib::IP::Address::V4::CIDR $ip_address_cidr,
  Enum['present', 'absent']     $ensure                = 'present',
  Optional[Integer[1,9202]]     $mtu                   = undef,
  Optional[Enum['on', 'off']]   $table                 = 'off',
  Array[Hash]                   $peers                 = [],
  Optional[String]              $dns                   = undef,
  Boolean                       $saveconfig            = false,
  Boolean                       $manage_firewall_entry = $::profile_wireguard::manage_firewall_entry,
) {
  wireguard::interface { $name:
    ensure      => $ensure,
    private_key => $private_key,
    listen_port => $listen_port,
    address     => $ip_address_cidr,
    table       => $table,
    mtu         => $mtu,
    peers       => $peers,
    dns         => $dns,
    saveconfig  => $saveconfig,
  }

  if $manage_firewall_entry {
    $peers.each | $peer | {
      $_peer_address = regsubst($peer['endpoint'], ':.*', '')

      firewall { "${listen_port} wireguard accept ${name}":
        source      => $_peer_address,
        destination => $facts['networking']['ip'],
        dport       => $listen_port,
        proto       => 'udp',
        action      => 'accept',
        chain       => 'WIREGUARD',
      }
    }
  }
}
