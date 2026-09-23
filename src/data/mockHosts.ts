import type { DirListing, HostNode } from '../types'

/** Seed catalogue for a first run — replaced by the user's own hosts.json the
 *  moment they save a host. Addresses use RFC 5737 / RFC 1918 documentation
 *  ranges on purpose: seed data ships in the repo, and example entries must
 *  never describe a real network. */
export const mockHosts: HostNode[] = [
  {
    kind: 'folder',
    id: 'f-net',
    name: 'Network',
    children: [
      {
        kind: 'folder',
        id: 'f-net-fw',
        name: 'Firewalls',
        children: [
          { kind: 'host', id: 'h1', name: 'edge-fw-01', hostname: '192.0.2.11', port: 22, username: 'admin', auth: 'key', tag: 'prod', color: 'red' },
          { kind: 'host', id: 'h2', name: 'edge-fw-02', hostname: '192.0.2.12', port: 22, username: 'admin', auth: 'key', tag: 'prod', color: 'red' },
          { kind: 'host', id: 'h3', name: 'lab-fw', hostname: '198.51.100.5', port: 22, username: 'admin', auth: 'password', color: 'green' },
        ],
      },
      {
        kind: 'folder',
        id: 'f-net-sw',
        name: 'Switches',
        children: [
          { kind: 'host', id: 'h4', name: 'core-sw-01', hostname: '192.0.2.2', port: 22, username: 'netadmin', auth: 'agent' },
          { kind: 'host', id: 'h5', name: 'idf-3-sw-04', hostname: '192.0.2.24', port: 22, username: 'netadmin', auth: 'agent' },
        ],
      },
    ],
  },
  {
    kind: 'folder',
    id: 'f-srv',
    name: 'Servers',
    children: [
      { kind: 'host', id: 'h8', name: 'backup-nas', hostname: '203.0.113.40', port: 22, username: 'svc-backup', auth: 'key' },
      { kind: 'host', id: 'h9', name: 'jump-01', hostname: '203.0.113.9', port: 2222, username: 'operator', auth: 'agent', tag: 'bastion', color: 'amber' },
    ],
  },
  { kind: 'host', id: 'h10', name: 'homelab', hostname: '10.0.0.50', port: 22, username: 'me', auth: 'password', color: 'green' },
]

/* Fixtures used only when running in a plain browser (npm run dev with no
   Tauri host). Times are unix epoch seconds, matching what the backend sends. */

export const mockLocalListing: DirListing = {
  path: 'C:\\Users\\me\\Documents',
  entries: [
    { name: '..', kind: 'directory', size: 0, modified: null, mode: '' },
    { name: 'exports', kind: 'directory', size: 0, modified: 1_788_000_000, mode: '' },
    { name: 'archive', kind: 'directory', size: 0, modified: 1_787_400_000, mode: '' },
    { name: 'running-config.xml', kind: 'file', size: 2_310_442, modified: 1_789_000_000, mode: '' },
    { name: 'interface-audit.csv', kind: 'file', size: 18_302, modified: 1_788_900_000, mode: '' },
    { name: 'deploy.ps1', kind: 'file', size: 3_180, modified: 1_788_100_000, mode: '' },
    { name: 'notes.md', kind: 'file', size: 4_120, modified: 1_787_900_000, mode: '' },
    { name: 'backup.tar.gz', kind: 'file', size: 88_120_400, modified: 1_786_500_000, mode: '' },
  ],
}

export const mockRemoteListing: DirListing = {
  path: '/var/log',
  entries: [
    { name: '..', kind: 'directory', size: 0, modified: null, mode: '' },
    { name: 'app', kind: 'directory', size: 0, modified: 1_788_300_000, mode: 'drwxr-xr-x' },
    { name: 'audit', kind: 'directory', size: 0, modified: 1_788_800_000, mode: 'drwx------' },
    { name: 'current', kind: 'symlink', size: 0, modified: 1_787_000_000, mode: 'lrwxrwxrwx' },
    { name: 'daemon.log', kind: 'file', size: 12_004_998, modified: 1_789_020_000, mode: '-rw-r--r--' },
    { name: 'kern.log', kind: 'file', size: 884_112, modified: 1_789_010_000, mode: '-rw-r--r--' },
    { name: 'app.conf', kind: 'file', size: 9_884, modified: 1_787_600_000, mode: '-rw-------' },
    { name: 'id_ed25519', kind: 'file', size: 464, modified: 1_780_000_000, mode: '-rw-------' },
  ],
}
