package com.aegis.guard.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.guard.ui.theme.AmberGlow
import com.aegis.guard.ui.theme.CrimsonPulse
import com.aegis.guard.ui.theme.NeonGreen
import com.aegis.guard.ui.theme.TextPrimary

enum class ThreatLevel {
    SAFE, SUSPICIOUS, DANGEROUS
}

@Composable
fun ThreatBadge(threatLevel: ThreatLevel, modifier: Modifier = Modifier) {
    val color = when (threatLevel) {
        ThreatLevel.SAFE -> NeonGreen
        ThreatLevel.SUSPICIOUS -> AmberGlow
        ThreatLevel.DANGEROUS -> CrimsonPulse
    }
    
    val text = when (threatLevel) {
        ThreatLevel.SAFE -> "Safe"
        ThreatLevel.SUSPICIOUS -> "Suspicious"
        ThreatLevel.DANGEROUS -> "Dangerous"
    }

    Row(
        modifier = modifier.padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(color)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text, color = TextPrimary, fontSize = 14.sp)
    }
}
