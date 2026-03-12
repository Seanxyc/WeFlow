import { app } from 'electron'
import { wcdbService } from './wcdbService'

interface UsageStats {
  appVersion: string
  platform: string
  deviceId: string
  timestamp: number
  online: boolean
  pages: string[]
}

class CloudControlService {
  private deviceId: string = ''
  private timer: NodeJS.Timeout | null = null
  private pages: Set<string> = new Set()

  async init() {
    this.deviceId = this.getDeviceId()
    await wcdbService.cloudInit(300)
    await this.reportOnline()

    this.timer = setInterval(() => {
      this.reportOnline()
    }, 300000)
  }

  private getDeviceId(): string {
    const crypto = require('crypto')
    const os = require('os')
    const machineId = os.hostname() + os.platform() + os.arch()
    return crypto.createHash('md5').update(machineId).digest('hex')
  }

  private async reportOnline() {
    const data: UsageStats = {
      appVersion: app.getVersion(),
      platform: this.getPlatformVersion(),
      deviceId: this.deviceId,
      timestamp: Date.now(),
      online: true,
      pages: Array.from(this.pages)
    }

    await wcdbService.cloudReport(JSON.stringify(data))
    this.pages.clear()
  }

  private getPlatformVersion(): string {
    const os = require('os')
    const platform = process.platform

    if (platform === 'win32') {
      const release = os.release()
      const parts = release.split('.')
      const major = parseInt(parts[0])
      const minor = parseInt(parts[1] || '0')
      const build = parseInt(parts[2] || '0')

      // Windows 11 是 10.0.22000+，且主版本必须是 10.0
      if (major === 10 && minor === 0 && build >= 22000) {
        return 'Windows 11'
      } else if (major === 10) {
        return 'Windows 10'
      }
      return `Windows ${release}`
    }

    if (platform === 'darwin') {
      // `os.release()` returns Darwin kernel version (e.g. 25.3.0),
      // while cloud reporting expects the macOS product version (e.g. 26.3).
      const macVersion = typeof process.getSystemVersion === 'function' ? process.getSystemVersion() : os.release()
      return `macOS ${macVersion}`
    }

    return platform
  }

  recordPage(pageName: string) {
    this.pages.add(pageName)
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
    wcdbService.cloudStop()
  }

  async getLogs() {
    return wcdbService.getLogs()
  }
}

export const cloudControlService = new CloudControlService()

