package com.aegis.guard.core.data

import androidx.room.TypeConverter

class Converters {
    @TypeConverter
    fun fromPermissionsList(permissions: List<String>?): String {
        return permissions?.joinToString(separator = ",") ?: ""
    }

    @TypeConverter
    fun toPermissionsList(permissionsString: String?): List<String> {
        return permissionsString?.split(",")?.filter { it.isNotEmpty() } ?: emptyList()
    }
}
