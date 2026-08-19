package com.aegis.guard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = ElectricCyan,
    secondary = NeonGreen,
    tertiary = AmberGlow,
    background = DeepSpaceBlack,
    surface = DarkNavy,
    surfaceVariant = SurfaceVariant,
    onPrimary = DeepSpaceBlack,
    onSecondary = DeepSpaceBlack,
    onTertiary = DeepSpaceBlack,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    onSurfaceVariant = TextSecondary,
    error = CrimsonPulse
)

@Composable
fun AegisTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content
    )
}
