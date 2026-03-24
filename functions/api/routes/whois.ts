import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const whoisRoute = new Hono<{ Bindings: Env }>()

interface WhoisResult {
  domain: string
  registrar?: string
  createdDate?: string
  updatedDate?: string
  expiryDate?: string
  status?: string[]
  nameservers?: string[]
  registrant?: {
    name?: string
    organization?: string
    country?: string
    email?: string
  }
  raw?: string
  error?: string
}

whoisRoute.get('/', async (c) => {
  const domain = c.req.query('domain')

  if (!domain) {
    return c.json({ error: 'domain is required' }, 400)
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

  const cacheKey = `cache:whois:${cleanDomain}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    const rdapRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`)
    if (rdapRes.ok) {
      const rdapData = await rdapRes.json() as Record<string, unknown>
      
      const result: WhoisResult = {
        domain: cleanDomain,
        raw: JSON.stringify(rdapData, null, 2),
      }

      if (rdapData.registrar) {
        result.registrar = String(rdapData.registrar)
      } else if (rdapData.port43) {
        result.registrar = String(rdapData.port43)
      }

      const events = rdapData.events as Array<{ eventAction: string; eventDate: string }> | undefined
      if (events) {
        for (const event of events) {
          if (event.eventAction === 'registration') {
            result.createdDate = event.eventDate
          } else if (event.eventAction === 'last changed') {
            result.updatedDate = event.eventDate
          } else if (event.eventAction === 'expiration') {
            result.expiryDate = event.eventDate
          }
        }
      }

      const nameservers = rdapData.nameservers as Array<{ ldhName: string }> | undefined
      if (nameservers) {
        result.nameservers = nameservers.map(ns => ns.ldhName.toLowerCase())
      }

      const status = rdapData.status as string[] | undefined
      if (status) {
        result.status = status
      }

      const entities = rdapData.entities as Array<Record<string, unknown>> | undefined
      if (entities) {
        for (const entity of entities) {
          const roles = entity.roles as string[] | undefined
          if (roles && roles.includes('registrant')) {
            const vcardArray = entity.vcardArray as Array<unknown> | undefined
            if (vcardArray && Array.isArray(vcardArray[1])) {
              const vcardItems = vcardArray[1] as Array<Array<unknown>>
              const registrant: Record<string, string> = {}
              
              for (const item of vcardItems) {
                if (Array.isArray(item) && item.length >= 2) {
                  const key = item[0] as string
                  const value = item[1]
                  if (typeof value === 'string') {
                    if (key === 'fn') {
                      registrant.name = value
                    } else if (key === 'org') {
                      registrant.organization = value
                    } else if (key === 'email') {
                      registrant.email = value
                    } else if (key === 'adr') {
                      const adr = value as Array<unknown>
                      if (Array.isArray(adr) && adr[5]) {
                        registrant.country = String(adr[5])
                      }
                    }
                  }
                }
              }
              
              if (Object.keys(registrant).length > 0) {
                result.registrant = registrant
              }
            }
          }
        }
      }

      try {
        await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
      } catch {}

      return c.json(result)
    }
    
    return c.json({ error: 'WHOIS query failed', details: `HTTP ${rdapRes.status}` }, 502)
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500)
  }
})
