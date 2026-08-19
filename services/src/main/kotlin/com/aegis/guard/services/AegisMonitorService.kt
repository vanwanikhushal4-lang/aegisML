package com.aegis.guard.services

import android.app.Service
import android.content.Intent
import android.os.IBinder

class AegisMonitorService : Service() {
    override fun onBind(intent: Intent?): IBinder? {
        return null
        // TODO: Implement monitor logic
    }
}
