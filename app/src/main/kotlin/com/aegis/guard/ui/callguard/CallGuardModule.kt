package com.aegis.guard.ui.callguard

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CallGuardModule {
    @Provides
    @Singleton
    fun provideCallGuardService(
        @ApplicationContext context: Context
    ): CallGuardService = CallGuardService(context)
}
