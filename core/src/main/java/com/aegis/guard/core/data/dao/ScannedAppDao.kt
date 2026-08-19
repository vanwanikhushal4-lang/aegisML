package com.aegis.guard.core.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.aegis.guard.core.data.model.ScannedAppEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScannedAppDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScannedApp(app: ScannedAppEntity)

    @Query("SELECT * FROM scanned_apps")
    fun getAllScannedApps(): Flow<List<ScannedAppEntity>>

    @Query("SELECT * FROM scanned_apps WHERE packageName = :packageName")
    suspend fun getScannedApp(packageName: String): ScannedAppEntity?
    
    @Query("DELETE FROM scanned_apps")
    suspend fun clearScannedApps()
}
