import axios from 'axios';
import { Request, Response, NextFunction } from 'express';

const API_KEY = 'your_api_key';

const checkVPN = async (ip: string): Promise<IPCheckResponse> => {
  // Example using proxycheck.io API
  const { data } = await axios.get(`https://proxycheck.io/v2/${ip}?key=${API_KEY}&vpn=1`);

  const result = data[ip];
  return {
    ip,
    proxy: result?.proxy === 'yes',
    vpn: result?.type === 'VPN',
    hosting: result?.type === 'INFRASTRUCTURE',
    isp: result?.isp || 'Unknown',
    country: result?.isocc || 'Unknown'
  };
};

export const vpnGuard = (config: BlockConfig) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '';

    try {
      const status = await checkVPN(clientIp);

      const shouldBlock =
        (config.blockVPN && status.vpn) ||
        (config.blockProxy && status.proxy) ||
        (config.blockHosting && status.hosting);

      if (shouldBlock) {
        return res.status(403).json({
          error: 'Access denied',
          reason: 'VPN/Proxy connection detected'
        });
      }

      next();
    } catch (error) {
      console.error('VPN Detection Error:', error);
      next(); // Fail open or closed based on your security policy
    }
  };
};
