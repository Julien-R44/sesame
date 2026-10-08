import { test } from '@japa/runner'
import { isSpecialUseAddress } from '../../src/client_id_metadata_documents/special_use_addresses.ts'

test.group('CIMD | special-use addresses', () => {
  test('blocks {0}')
    .with([
      '127.0.0.1',
      '127.1.2.3',
      '0.0.0.0',
      '10.0.0.1',
      '172.16.5.4',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '192.0.0.8',
      '198.18.0.1',
      '224.0.0.1',
      '255.255.255.255',
      '::',
      '::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '::ffff:169.254.169.254',
      'fc00::1',
      'fd12:3456::1',
      'fe80::1',
      'ff02::1',
      '2001:db8::1',
      '64:ff9b::a00:1',
      'not-an-ip',
    ])
    .run(({ assert }, address) => {
      assert.isTrue(isSpecialUseAddress(address))
    })

  test('allows public address {0}')
    .with(['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])
    .run(({ assert }, address) => {
      assert.isFalse(isSpecialUseAddress(address))
    })
})
