package com.aegis.guard.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Message
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.guard.ui.components.GlassCard
import com.aegis.guard.ui.components.ProtectionScoreRing
import com.aegis.guard.ui.components.ShieldIcon
import com.aegis.guard.ui.theme.DeepSpaceBlack
import com.aegis.guard.ui.theme.ElectricCyan
import com.aegis.guard.ui.theme.NeonGreen
import com.aegis.guard.ui.theme.TextPrimary
import com.aegis.guard.ui.theme.TextSecondary

@Composable
fun DashboardScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpaceBlack)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(24.dp))
        
        ShieldIcon()
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "AEGIS",
            color = TextPrimary,
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 2.sp
        )
        
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(NeonGreen)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Protection Active",
                color = NeonGreen,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium
            )
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        ProtectionScoreRing(score = 87)
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "Looking good. Everything's under control.",
            color = TextSecondary,
            fontSize = 14.sp
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        // 2x2 Grid of Stats
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Filled.Language,
                number = "23",
                label = "URLs Blocked"
            )
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Filled.Shield,
                number = "147",
                label = "Apps Scanned"
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Filled.Phone,
                number = "8",
                label = "Calls Screened"
            )
            StatCard(
                modifier = Modifier.weight(1f),
                icon = Icons.Filled.Message,
                number = "34",
                label = "SMS Checked"
            )
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterStart) {
            Text(
                text = "Today's Activity",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        ActivityItem(time = "10:42 AM", desc = "Scanned 3 new installed apps")
        Spacer(modifier = Modifier.height(8.dp))
        ActivityItem(time = "09:15 AM", desc = "Blocked suspicious URL in browser")
        Spacer(modifier = Modifier.height(8.dp))
        ActivityItem(time = "08:30 AM", desc = "Screened call from unknown number")
    }
}

@Composable
fun StatCard(modifier: Modifier = Modifier, icon: ImageVector, number: String, label: String) {
    GlassCard(modifier = modifier.fillMaxWidth()) {
        Column(horizontalAlignment = Alignment.Start) {
            Icon(imageVector = icon, contentDescription = null, tint = ElectricCyan, modifier = Modifier.size(24.dp))
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = number, color = TextPrimary, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Text(text = label, color = TextSecondary, fontSize = 12.sp)
        }
    }
}

@Composable
fun ActivityItem(time: String, desc: String) {
    GlassCard(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(ElectricCyan)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(text = desc, color = TextPrimary, fontSize = 14.sp)
                Text(text = time, color = TextSecondary, fontSize = 12.sp)
            }
        }
    }
}
