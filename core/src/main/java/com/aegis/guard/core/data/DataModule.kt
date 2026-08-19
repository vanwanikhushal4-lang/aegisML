package com.aegis.guard.core.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import androidx.room.Room
import com.aegis.guard.core.data.dao.ScannedAppDao
import com.aegis.guard.core.data.dao.ThreatSignatureDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    @Provides
    @Singleton
    fun provideAegisDatabase(
        @ApplicationContext context: Context
    ): AegisDatabase {
        return Room.databaseBuilder(
            context,
            AegisDatabase::class.java,
            "aegis_database"
        ).build()
    }

    @Provides
    @Singleton
    fun provideScannedAppDao(database: AegisDatabase): ScannedAppDao {
        return database.scannedAppDao()
    }

    @Provides
    @Singleton
    fun provideThreatSignatureDao(database: AegisDatabase): ThreatSignatureDao {
        return database.threatSignatureDao()
    }

    @Provides
    @Singleton
    fun provideDataStore(
        @ApplicationContext context: Context
    ): DataStore<Preferences> {
        return PreferenceDataStoreFactory.create(
            produceFile = { context.preferencesDataStoreFile("aegis_preferences") }
        )
    }
}
