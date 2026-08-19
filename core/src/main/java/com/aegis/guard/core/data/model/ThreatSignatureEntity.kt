package com.aegis.guard.core.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "threat_signatures")
data class ThreatSignatureEntity(
    @PrimaryKey val signatureHash: String,
    val threatName: String,
    val severity: String
)
