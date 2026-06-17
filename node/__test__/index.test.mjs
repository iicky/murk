import assert from 'node:assert'
import { execSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { exportAll, get, hasKey, load } from '../index.js'

// Find the murk binary.
const murkBin = join(process.cwd(), '..', 'target', 'release', 'murk')

function setupVault() {
  const dir = mkdtempSync(join(tmpdir(), 'murk-node-test-'))

  const run = (cmd, input) =>
    execSync(cmd, {
      cwd: dir,
      input,
      env: {
        ...process.env,
        PATH: `${join(process.cwd(), '..', 'target', 'release')}:${process.env.PATH}`,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })

  // Init vault.
  run(`${murkBin} init --vault .murk`, 'testuser\n')

  // Read key from .env.
  const dotenv = readFileSync(join(dir, '.env'), 'utf8')
  let murkKey
  for (const line of dotenv.split('\n')) {
    if (line.startsWith('export MURK_KEY_FILE=')) {
      const keyFile = line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
      murkKey = readFileSync(keyFile, 'utf8').trim()
      break
    }
    if (line.startsWith('export MURK_KEY=')) {
      murkKey = line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
      break
    }
  }

  // Add secrets.
  const env = { ...process.env, MURK_KEY: murkKey }
  execSync(`${murkBin} add DATABASE_URL --vault .murk`, {
    cwd: dir,
    input: 'postgres://localhost/mydb\n',
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  execSync(`${murkBin} add API_KEY --vault .murk`, {
    cwd: dir,
    input: 'sk-test-123\n',
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  execSync(`${murkBin} add STRIPE_SECRET --vault .murk`, {
    cwd: dir,
    input: 'sk_live_abc\n',
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  })

  return { dir, murkKey }
}

// Build a vault with an agent policy and a granted agent identity, so we can
// prove the bindings enforce the same policy the CLI applies at `agent exec`.
function setupAgentVault() {
  const dir = mkdtempSync(join(tmpdir(), 'murk-node-agent-'))
  const run = (cmd, input, extraEnv) =>
    execSync(cmd, {
      cwd: dir,
      input,
      env: {
        ...process.env,
        PATH: `${join(process.cwd(), '..', 'target', 'release')}:${process.env.PATH}`,
        ...extraEnv,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })

  run(`${murkBin} init --vault .murk`, 'agentowner\n')

  // Read operator key from .env.
  const dotenv = readFileSync(join(dir, '.env'), 'utf8')
  let opKey
  for (const line of dotenv.split('\n')) {
    if (line.startsWith('export MURK_KEY_FILE=')) {
      const keyFile = line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
      opKey = readFileSync(keyFile, 'utf8').trim()
      break
    }
    if (line.startsWith('export MURK_KEY=')) {
      opKey = line
        .split('=')[1]
        .trim()
        .replace(/^['"]|['"]$/g, '')
      break
    }
  }

  const opEnv = { MURK_KEY: opKey }
  run(`${murkBin} add AGENT_DB --vault .murk`, 'postgres://agent\n', opEnv)
  run(`${murkBin} add PROD_DB --vault .murk`, 'postgres://prod\n', opEnv)
  run(`${murkBin} describe AGENT_DB "agent db" --tag agents --vault .murk`, '', opEnv)
  run(`${murkBin} describe PROD_DB "prod db" --tag prod --vault .murk`, '', opEnv)
  run(`${murkBin} policy set --allow-tag agents --vault .murk`, '', opEnv)
  run(
    `${murkBin} agent grant --name codex --only AGENT_DB --out agent.key --vault .murk`,
    '',
    opEnv,
  )
  const agentKey = readFileSync(join(dir, 'agent.key'), 'utf8').trim()

  // Tightening the policy to drop the `agents` tag leaves the agent's scoped
  // ciphertext in place — the crypto still works, but policy should now refuse.
  const tightenPolicy = () => run(`${murkBin} policy set --allow-tag prod --vault .murk`, '', opEnv)

  return { dir, opKey, agentKey, tightenPolicy }
}

let testDir, testKey

// Setup
console.log('Setting up test vault...')
const setup = setupVault()
testDir = setup.dir
testKey = setup.murkKey
process.env.MURK_KEY = testKey
process.chdir(testDir)

// Tests
let passed = 0
let failed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`  ✓ ${name}`)
    passed++
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`)
    failed++
  }
}

console.log('\nRunning tests...\n')

test('load returns a vault', () => {
  const vault = load()
  assert.ok(vault)
})

test('load with explicit path', () => {
  const vault = load(join(testDir, '.murk'))
  assert.ok(vault)
})

test('vault.get returns correct value', () => {
  const vault = load()
  assert.strictEqual(vault.get('DATABASE_URL'), 'postgres://localhost/mydb')
  assert.strictEqual(vault.get('API_KEY'), 'sk-test-123')
})

test('vault.get returns null for missing key', () => {
  const vault = load()
  assert.strictEqual(vault.get('NONEXISTENT'), null)
})

test('vault.export returns all secrets', () => {
  const vault = load()
  const secrets = vault.export()
  assert.strictEqual(secrets.DATABASE_URL, 'postgres://localhost/mydb')
  assert.strictEqual(secrets.API_KEY, 'sk-test-123')
  assert.strictEqual(secrets.STRIPE_SECRET, 'sk_live_abc')
  assert.strictEqual(Object.keys(secrets).length, 3)
})

test('vault.keys returns all key names', () => {
  const vault = load()
  const keys = vault.keys().sort()
  assert.deepStrictEqual(keys, ['API_KEY', 'DATABASE_URL', 'STRIPE_SECRET'])
})

test('vault.length returns count', () => {
  const vault = load()
  assert.strictEqual(vault.length, 3)
})

test('vault.has returns true for existing key', () => {
  const vault = load()
  assert.strictEqual(vault.has('DATABASE_URL'), true)
  assert.strictEqual(vault.has('NONEXISTENT'), false)
})

test('get one-liner works', () => {
  assert.strictEqual(get('DATABASE_URL'), 'postgres://localhost/mydb')
})

test('get one-liner returns null for missing', () => {
  assert.strictEqual(get('NONEXISTENT'), null)
})

test('exportAll one-liner works', () => {
  const secrets = exportAll()
  assert.strictEqual(Object.keys(secrets).length, 3)
})

test('hasKey returns true when key set', () => {
  assert.strictEqual(hasKey(), true)
})

test('load with missing vault throws', () => {
  assert.throws(() => load('/nonexistent/.murk'))
})

// Agent policy enforcement: a granted agent identity is gated by the vault's
// policy from the binding, just like the CLI gates it at `agent exec`.
console.log('\nSetting up agent policy vault...')
const agent = setupAgentVault()
const agentVault = join(agent.dir, '.murk')

test('agent reads an in-scope, policy-allowed key', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.strictEqual(get('AGENT_DB', agentVault), 'postgres://agent')
})

test('agent cannot decrypt an out-of-scope key (crypto boundary)', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.strictEqual(get('PROD_DB', agentVault), null)
})

test('agent export returns only its scoped, allowed keys', () => {
  process.env.MURK_KEY = agent.agentKey
  const secrets = load(agentVault).export()
  assert.deepStrictEqual(Object.keys(secrets), ['AGENT_DB'])
  assert.strictEqual(secrets.AGENT_DB, 'postgres://agent')
})

test('tightening the policy retroactively blocks the agent get', () => {
  agent.tightenPolicy()
  process.env.MURK_KEY = agent.agentKey
  assert.throws(() => get('AGENT_DB', agentVault), /policy forbids/)
})

test('tightening the policy retroactively blocks the agent export', () => {
  process.env.MURK_KEY = agent.agentKey
  assert.throws(() => load(agentVault).export(), /policy forbids/)
})

// Cleanup
rmSync(testDir, { recursive: true, force: true })
rmSync(agent.dir, { recursive: true, force: true })

console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
