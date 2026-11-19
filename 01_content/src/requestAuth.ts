/** Use the host's current authentication service for every request, never a cached grant. */
export async function requestRejection(ctx: any, req: any): Promise<number | undefined> {
  try {
    const connection = typeof ctx.get === 'function' ? ctx.get('connection') : undefined
    if (!connection) return 503
    if (typeof connection.admit === 'function') {
      const admission = await connection.admit(req)
      if (!admission || typeof admission !== 'object') return 503
      if ('rejection' in admission) return admission.rejection === 401 ? 401 : 403
      const peer = admission.peer
      // 0.2.1 has owner/non-owner principals. 0.2.0 has a single operator Peer.
      if (peer?.principal?.kind === 'owner') return undefined
      if (peer && peer === connection.operator && peer.principal === undefined) return undefined
      return 403
    }
    // DSH 0.1.x has no per-request peer: the same Host/Origin + browser-token fence the
    // host applies to its own /api routes is exposed synchronously instead. Only an
    // explicit 401/403 rejects; an unusable answer still falls through to 503.
    if (typeof connection.requestRejection === 'function') {
      const rejection = connection.requestRejection({ headers: req?.headers ?? {} })
      if (rejection === 401 || rejection === 403) return rejection
      if (rejection === undefined || rejection === null) return undefined
      return 403
    }
  } catch {}
  // An unavailable or failed security service must not turn into public filesystem access.
  return 503
}

export function rejectionText(status: number): string {
  return status === 401 ? 'unauthorized' : status === 403 ? 'forbidden' : 'Host authentication unavailable'
}
