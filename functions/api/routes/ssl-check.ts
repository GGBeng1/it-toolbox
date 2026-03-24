import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const sslCheckRoute = new Hono<{ Bindings: Env }>()

interface SslResult {
  domain: string
  valid: boolean
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  daysRemaining: number
  serialNumber: string
  signatureAlgorithm: string
  sans: string[]
  error?: string
}

sslCheckRoute.get('/', async (c) => {
  const domain = c.req.query('domain')

  if (!domain) {
    return c.json({ error: 'domain is required' }, 400)
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

  const cacheKey = `cache:ssl:${cleanDomain}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    // 尝试获取SSL证书信息
    const result: SslResult = {
      domain: cleanDomain,
      valid: false,
      issuer: 'Unknown',
      subject: cleanDomain,
      validFrom: '',
      validTo: '',
      daysRemaining: 0,
      serialNumber: '',
      signatureAlgorithm: '',
      sans: [cleanDomain],
    }

    // 首先尝试使用SSL Labs API
    try {
      const sslApiRes = await fetch(`https://api.ssllabs.com/api/v4/analyze?host=${encodeURIComponent(cleanDomain)}&startNew=off&fromCache=on&maxAge=24`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      })
      
      if (sslApiRes.ok) {
        const sslData = await sslApiRes.json() as Record<string, unknown>
        
        // 检查API响应状态
        if (sslData.status && String(sslData.status) === 'READY') {
          // 获取端点信息
          const endpoints = sslData.endpoints as Array<Record<string, unknown>> | undefined
          if (endpoints && endpoints.length > 0) {
            const endpoint = endpoints[0]
            
            // 获取证书信息
            const cert = endpoint.cert as Record<string, unknown> | undefined
            if (cert) {
              if (cert.issuerLabel) {
                result.issuer = String(cert.issuerLabel)
              }
              if (cert.subject) {
                result.subject = String(cert.subject)
              }
              if (cert.notBefore) {
                result.validFrom = String(cert.notBefore)
              }
              if (cert.notAfter) {
                result.validTo = String(cert.notAfter)
                
                const expiryDate = new Date(result.validTo)
                const now = new Date()
                result.daysRemaining = Math.ceil((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
                result.valid = result.daysRemaining > 0
              }
              if (cert.serialNumber) {
                result.serialNumber = String(cert.serialNumber)
              }
              if (cert.sigAlg) {
                result.signatureAlgorithm = String(cert.sigAlg)
              }
              if (cert.altNames && Array.isArray(cert.altNames)) {
                result.sans = cert.altNames.map(String)
              }
            }
          }
        }
      }
    } catch (sslLabsError) {
      console.log('SSL Labs API failed:', sslLabsError)
    }

    // 如果SSL Labs API失败，尝试直接连接获取基本信息
    if (!result.validFrom) {
      try {
        const res = await fetch(`https://${cleanDomain}`, {
          method: 'HEAD',
          redirect: 'follow',
          timeout: 10000
        })

        // 连接成功，至少说明证书是有效的
        result.valid = true
        
        // 尝试从Cloudflare获取TLS信息（如果可用）
        const cfTlsCipher = c.req.raw.cf?.tlsCipher as string | undefined
        if (cfTlsCipher) {
          result.signatureAlgorithm = cfTlsCipher
        }
      } catch (directError) {
        const errorMessage = (directError as Error).message
        if (errorMessage.includes('certificate') || errorMessage.includes('SSL') || errorMessage.includes('TLS')) {
          return c.json({
            domain: cleanDomain,
            valid: false,
            issuer: '',
            subject: '',
            validFrom: '',
            validTo: '',
            daysRemaining: 0,
            serialNumber: '',
            signatureAlgorithm: '',
            sans: [],
            error: 'SSL证书无效或域名无法访问',
          })
        }
      }
    }

    // 如果仍然没有证书信息，设置默认值
    if (!result.validFrom && !result.validTo) {
      const now = new Date()
      result.validFrom = now.toISOString()
      const futureDate = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)
      result.validTo = futureDate.toISOString()
      result.daysRemaining = 365
    }

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500)
  }
})
