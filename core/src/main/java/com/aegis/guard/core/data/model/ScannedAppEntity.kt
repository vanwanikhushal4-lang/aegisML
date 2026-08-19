package com.aegis.guard.core.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scanned_apps")
data class ScannedAppEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val version: String,
    val riskScore: Int,
    val isSystemApp: Boolean,
    val dangerousPermissions: List<String>,
    val threatLevel: String
)
