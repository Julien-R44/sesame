import { BlockList, isIP } from 'node:net'

/**
 * Special-purpose address ranges (RFC 6890 and the IANA special-purpose
 * registries) that client metadata documents must never be fetched from.
 * IPv4-mapped IPv6 addresses are matched against the IPv4 ranges by
 * `BlockList` itself.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6890
 * @see https://www.iana.org/assignments/iana-ipv4-special-registry
 * @see https://www.iana.org/assignments/iana-ipv6-special-registry
 */
const IPV4_RANGES: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]

const IPV6_RANGES: Array<[string, number]> = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
]

const specialUseAddresses = new BlockList()
for (const [network, prefix] of IPV4_RANGES) specialUseAddresses.addSubnet(network, prefix, 'ipv4')
for (const [network, prefix] of IPV6_RANGES) specialUseAddresses.addSubnet(network, prefix, 'ipv6')

/**
 * Whether an IP address is loopback, private, link-local, reserved or
 * otherwise not publicly routable. Invalid input is treated as unsafe.
 */
export function isSpecialUseAddress(address: string) {
  const version = isIP(address)
  if (version === 0) return true

  return specialUseAddresses.check(address, version === 4 ? 'ipv4' : 'ipv6')
}
