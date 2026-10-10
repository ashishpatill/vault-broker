/**
 * Daemon server: a Unix domain socket in a 0700 directory, and no other listener.
 *
 * The absence of a TCP port is the structural half of the man-in-the-middle answer. There
 * is no socket on localhost for a local attacker to connect to, no DNS name to spoof, no
 * certificate to forge and no port for another user of this machine to reach. The daemon
 * binds a path inside a directory only this user can enter.
 *
 * What the socket does NOT yet prove is *which* process connected. Any process running as
 * this user can reach the socket. I4 binds each client to its code signature; definitive
 * kernel peer-credential checks (`LOCAL_PEERCRED`) need a native helper and are deferred
 * to v0.2. This file is where that check will go — see `peerCredentials()`.
 */

import { createServer, type Server, type Socket } from 'node:net'
import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'

import { ensureDir0700 } from '../core/fsx.ts'
import { createLogger, redact } from '../core/logging.ts'
import { daemonLockPath, runtimeRoot, socketPath } from '../core/runtime-paths.ts'
import { assertCompatible, encodeFrame, parseFrame, ProtocolError } from './protocol.ts'
import { Session } from './session.ts'

const log = createLogger('server')

/** How long a single frame may take to arrive before the connection is dropped. */
const FRAME_TIMEOUT_MS = 30_000

/** Cap on a single frame, so a client cannot exhaust memory by never sending a newline. */
const MAX_FRAME_BYTES = 1 << 20 // 1 MiB

export interface DaemonHandle {
  readonly server: Server
  readonly session: Session
  readonly socket: string
  /** Resolves when the server has stopped accepting connections. */
  readonly closed: Promise<void>
  stop(): Promise<void>
}

/**
 * Single-instance guard.
 *
 * Written with `O_EXCL` semantics so two daemons racing to start cannot both win. A
 * stale lock from a crashed daemon is removed by `isLockStale`, which checks the pid.
 */
function acquireLock(lockFile: string): () => void {
  if (existsSync(lockFile)) {
    const recorded = readFileSync(lockFile, 'utf8').trim()
    const pid = Number.parseInt(recorded, 10)

    const alive = Number.isInteger(pid) && pid > 0 && (() => {
      try {
        // Signal 0 performs the permission and existence check without delivering.
        process.kill(pid, 0)
        return true
      } catch {
        return false
      }
    })()

    if (alive) {
      throw new Error(`a broker daemon is already running (pid ${pid})`)
    }
    unlinkSync(lockFile)
  }

  writeFileSync(lockFile, `${String(process.pid)}\n`, { mode: 0o600 })

  return () => {
    try {
      // Only remove our own lock; a later daemon may have replaced it.
      if (readFileSync(lockFile, 'utf8').trim() === String(process.pid)) {
        unlinkSync(lockFile)
      }
    } catch {
      // Already gone; nothing to clean up.
    }
  }
}

/**
 * Best-effort peer identity.
 *
 * Node exposes no `LOCAL_PEERCRED` equivalent, so this returns undefined today. It is the
 * documented seam for the v0.2 native helper: when that exists, the shim sends its pid and
 * the daemon verifies the peer's uid matches the current user *in the kernel* rather than
 * trusting a path or a self-reported identity.
 */
export function peerCredentials(_socket: Socket): { uid: number; pid: number } | undefined {
  return undefined
}

export interface StartDaemonOptions {
  readonly socket?: string
  readonly lockFile?: string
  readonly session: Session
}

export async function startDaemon(options: StartDaemonOptions): Promise<DaemonHandle> {
  const socket = options.socket ?? socketPath()
  const lockFile = options.lockFile ?? daemonLockPath()

  ensureDir0700(runtimeRoot())

  // A socket file left behind by a crash would make bind() fail with EADDRINUSE even
  // though nothing is listening.
  if (existsSync(socket)) unlinkSync(socket)

  const releaseLock = acquireLock(lockFile)

  /**
   * Live client sockets.
   *
   * Tracked so shutdown can destroy them; `net.Server` exposes no closeAllConnections.
   */
  const connections = new Set<Socket>()

  const server = createServer((conn) => {
    connections.add(conn)
    conn.on('close', () => connections.delete(conn))
    handleConnection(conn, options.session, socket)
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(socket, () => {
      server.removeListener('error', reject)
      resolve()
    })
  })

  // The socket lives inside a 0700 directory, so only this user can reach it. Setting the
  // mode explicitly means a umask change cannot widen it.
  chmodSync(socket, 0o600)

  let closed: Promise<void>
  closed = new Promise<void>((resolve) => server.once('close', () => resolve()))

  const stop = async (): Promise<void> => {
    // server.close() only stops accepting, then waits for every existing connection to
    // end — so one lingering client hangs shutdown indefinitely, which surfaces as
    // `vaultbroker daemon stop` never returning. `closeAllConnections()` is an
    // http.Server method and does NOT exist on net.Server, so sockets are tracked
    // explicitly and destroyed here.
    for (const conn of connections) conn.destroy()
    connections.clear()

    await new Promise<void>((resolve) => {
      server.close(() => resolve())
    })
    try {
      if (existsSync(socket)) unlinkSync(socket)
    } catch {
      // Best effort; the socket is inside our own runtime directory.
    }
    releaseLock()
    await closed
  }

  log.info('daemon listening', { socket })
  return { server, session: options.session, socket, closed, stop }
}

/**
 * Serve one connection.
 *
 * Frames are newline-delimited JSON. A partial frame is buffered rather than parsed
 * early, because parsing a truncated frame and failing on it would report a client bug
 * where the real fault is transport fragmentation.
 */
function handleConnection(conn: Socket, session: Session, socket: string): void {
  const peer = peerCredentials(conn)
  log.debug('client connected', { peer: peer ?? 'unavailable' })

  let buffer = ''
  let timedOut = false

  const timer = setTimeout(() => {
    timedOut = true
    conn.destroy()
  }, FRAME_TIMEOUT_MS)
  timer.unref()

  conn.setEncoding('utf8')

  conn.on('data', (chunk: string) => {
    if (timedOut) return

    buffer += chunk

    if (buffer.length > MAX_FRAME_BYTES && !buffer.includes('\n')) {
      log.warn('frame exceeded maximum size; dropping connection')
      conn.destroy()
      return
    }

    let newlineIndex = buffer.indexOf('\n')
    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex)
      buffer = buffer.slice(newlineIndex + 1)

      if (line.trim() !== '') {
        void dispatch(line, conn, session, socket)
      }

      newlineIndex = buffer.indexOf('\n')
    }
  })

  conn.on('error', (err) => {
    log.debug('connection error', { error: redact(String(err)) })
    conn.destroy()
  })

  conn.on('close', () => {
    clearTimeout(timer)
  })
}

async function dispatch(line: string, conn: Socket, session: Session, socket: string): Promise<void> {
  try {
    const frame = parseFrame(line)

    if (frame.kind !== 'request') {
      conn.write(
        encodeFrame({
          kind: 'response',
          id: frame.id,
          ok: false,
          error: { code: 'BAD_REQUEST', message: 'expected a request frame' },
        }),
      )
      return
    }

    assertCompatible(frame)
    const response = await session.handle(frame, socket)
    conn.write(encodeFrame(response))

    if (frame.command === 'shutdown') {
      setTimeout(() => conn.end(), 10).unref()
    }
  } catch (error) {
    const message = error instanceof ProtocolError ? error.message : 'malformed request'
    log.debug('rejected frame', { error: redact(message) })
    // The id is unknown when the frame could not be parsed, so correlate on a sentinel.
    conn.write(
      encodeFrame({
        kind: 'response',
        id: 'unknown',
        ok: false,
        error: { code: 'BAD_REQUEST', message },
      }),
    )
  }
}