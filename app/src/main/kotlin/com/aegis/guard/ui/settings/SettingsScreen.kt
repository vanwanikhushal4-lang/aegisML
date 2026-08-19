package com.aegis.guard.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.guard.ui.theme.DeepSpaceBlack
import com.aegis.guard.ui.theme.ElectricCyan
import com.aegis.guard.ui.theme.TextPrimary

@Composable
fun SettingsScreen() {
    Box(modifier = Modifier.fillMaxSize().background(DeepSpaceBlack), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(imageVector = Icons.Filled.Settings, contentDescription = null, tint = ElectricCyan, modifier = Modifier.size(64.dp))
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = "Settings", color = TextPrimary, fontSize = 24.sp)
        }
    }
}
