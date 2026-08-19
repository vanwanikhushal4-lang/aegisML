package com.aegis.guard.core.data.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.aegis.guard.core.data.model.ThreatSignatureEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatSignatureDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSignatures(signatures: List<ThreatSignatureEntity>)

    @Query("SELECT * FROM threat_signatures")
    fun getAllSignatures(): Flow<List<ThreatSignatureEntity>>

    @Query("SELECT * FROM threat_signatures WHERE signatureHash = :hash")
    suspend fun getSignature(hash: String): ThreatSignatureEntity?

    @Query("DELETE FROM threat_signatures")
    suspend fun clearSignatures()
}
