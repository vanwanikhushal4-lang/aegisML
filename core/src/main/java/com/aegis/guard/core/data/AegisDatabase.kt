package com.aegis.guard.core.data

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.aegis.guard.core.data.model.ScannedAppEntity
import com.aegis.guard.core.data.model.ThreatSignatureEntity
import com.aegis.guard.core.data.dao.ScannedAppDao
import com.aegis.guard.core.data.dao.ThreatSignatureDao

@Database(
    entities = [
        ScannedAppEntity::class,
        ThreatSignatureEntity::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AegisDatabase : RoomDatabase() {
    abstract fun scannedAppDao(): ScannedAppDao
    abstract fun threatSignatureDao(): ThreatSignatureDao
}
