package com.aegis.guard.ui.callguard

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.guard.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*
import kotlin.math.*

@Composable
fun CallGuardScreen(viewModel: CallGuardViewModel = hiltViewModel()) {
    val numberInput by viewModel.numberInput.collectAsState()
    val checkState by viewModel.checkState.collectAsState()
    val isProtectionEnabled by viewModel.isProtectionEnabled.collectAsState()
    val blockedHistory by viewModel.blockedHistory.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val simulatedCall by viewModel.simulatedCall.collectAsState()
    val focusManager = LocalFocusManager.current

    Box(modifier = Modifier.fillMaxSize()) {

        // Background
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF050810), Color(0xFF080510), Color(0xFF050810))
                    )
                )
        )
        PhoneSignalBackground()

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header + Protection Toggle
            item { CallGuardHeader(isEnabled = isProtectionEnabled, onToggle = viewModel::toggleProtection) }

            // Stats
            item { CallStatsRow(stats = stats) }

            // Live demo button
            item {
                DemoCallButton(onSimulate = { viewModel.simulateIncomingCall("+919876543210") })
            }

            // Number Lookup Card
            item {
                NumberLookupCard(
                    input = numberInput,
                    checkState = checkState,
                    onInputChange = viewModel::onNumberInputChange,
                    onCheck = { focusManager.clearFocus(); viewModel.checkNumber() },
                    onClear = viewModel::clearResult
                )
            }

            // Check result
            item {
                AnimatedVisibility(
                    visible = checkState is NumberCheckState.Result,
                    enter = fadeIn(tween(400)) + expandVertically(tween(400, easing = EaseOut)),
                    exit = fadeOut(tween(200)) + shrinkVertically(tween(200))
                ) {
                    (checkState as? NumberCheckState.Result)?.let {
                        NumberRiskCard(info = it.info)
                    }
                }
            }

            // Blocked history header
            if (blockedHistory.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("BLOCKED CALLS", color = TextSecondary, fontSize = 10.sp, letterSpacing = 3.sp, fontWeight = FontWeight.Medium)
                        Spacer(Modifier.weight(1f))
                        Text("${blockedHistory.size} calls", color = TextSecondary.copy(alpha = 0.5f), fontSize = 10.sp)
                    }
                }
                items(blockedHistory) { entry ->
                    BlockedCallItem(entry = entry)
                }
            }

            item { Spacer(Modifier.height(16.dp)) }
        }

        // Simulated incoming call overlay
        AnimatedVisibility(
            visible = simulatedCall !is SimulatedCallState.None,
            enter = fadeIn() + slideInVertically { -it },
            exit = fadeOut() + slideOutVertically { -it },
            modifier = Modifier.align(Alignment.TopCenter)
        ) {
            IncomingCallOverlay(
                state = simulatedCall,
                onDismiss = viewModel::dismissSimulation
            )
        }
    }
}

// ─── Phone Signal Background ──────────────────────────────────────────────────

@Composable
fun PhoneSignalBackground() {
    val infiniteTransition = rememberInfiniteTransition(label = "signal")
    val wave by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(3000, easing = LinearEasing)),
        label = "wave"
    )
    Canvas(modifier = Modifier.fillMaxSize()) {
        val cx = size.width * 0.85f
        val cy = size.height * 0.15f
        for (i in 1..5) {
            val radius = (i * 60f) + (wave * 60f)
            val alpha = ((1f - wave) * 0.06f * (1f - i / 6f)).coerceAtLeast(0f)
            drawCircle(
                color = Color(0xFF7B61FF).copy(alpha = alpha),
                center = Offset(cx, cy),
                radius = radius,
                style = Stroke(width = 1.5f)
            )
        }
    }
}

// ─── Header ───────────────────────────────────────────────────────────────────

@Composable
fun CallGuardHeader(isEnabled: Boolean, onToggle: () -> Unit) {
    val color = if (isEnabled) NeonGreen else TextSecondary
    val infiniteTransition = rememberInfiniteTransition(label = "callHdr")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.5f, targetValue = 1f,
        animationSpec = if (isEnabled)
            infiniteRepeatable(tween(1500, easing = EaseInOut), RepeatMode.Reverse)
        else
            infiniteRepeatable(tween(3000, easing = EaseInOut), RepeatMode.Reverse),
        label = "hdrPulse"
    )

    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Box(contentAlignment = Alignment.Center) {
            Box(
                modifier = Modifier
                    .size(50.dp)
                    .scale(pulse)
                    .background(color.copy(alpha = 0.15f), CircleShape)
            )
            Icon(Icons.Filled.Phone, contentDescription = null, tint = color, modifier = Modifier.size(28.dp))
        }
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text("CALL GUARD", color = color, fontSize = 18.sp, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
            Text(
                if (isEnabled) "Actively screening all calls" else "Protection is paused",
                color = TextSecondary, fontSize = 12.sp
            )
        }

        // Big toggle
        Switch(
            checked = isEnabled,
            onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = NeonGreen,
                uncheckedThumbColor = TextSecondary,
                uncheckedTrackColor = SurfaceVariant
            )
        )
    }
}

// ─── Stats Row ────────────────────────────────────────────────────────────────

@Composable
fun CallStatsRow(stats: CallGuardStats) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        CallStatChip(Modifier.weight(1f), stats.totalCallsScreened, "SCREENED", ElectricCyan, Icons.Filled.FilterList)
        CallStatChip(Modifier.weight(1f), stats.spamBlocked + stats.robocallsBlocked, "SPAM", AmberGlow, Icons.Filled.Block)
        CallStatChip(Modifier.weight(1f), stats.scamBlocked, "SCAMS", CrimsonPulse, Icons.Filled.ReportGmailerrorred)
    }
}

@Composable
fun CallStatChip(
    modifier: Modifier,
    value: Int,
    label: String,
    color: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    val animVal by animateIntAsState(targetValue = value, animationSpec = tween(800), label = "cv")
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.07f), RoundedCornerShape(14.dp))
            .border(1.dp, color.copy(alpha = 0.18f), RoundedCornerShape(14.dp))
            .padding(vertical = 12.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null, tint = color.copy(alpha = 0.6f), modifier = Modifier.size(15.dp))
            Spacer(Modifier.height(4.dp))
            Text("$animVal", color = color, fontSize = 20.sp, fontWeight = FontWeight.Black)
            Text(label, color = color.copy(alpha = 0.55f), fontSize = 8.sp, letterSpacing = 0.5.sp)
        }
    }
}

// ─── Demo Call Button ─────────────────────────────────────────────────────────

@Composable
fun DemoCallButton(onSimulate: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "demo")
    val ring1 by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1800, easing = EaseOut), RepeatMode.Restart),
        label = "r1"
    )
    val ring2 by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1800, 600, easing = EaseOut), RepeatMode.Restart),
        label = "r2"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF7B61FF).copy(alpha = 0.07f), RoundedCornerShape(20.dp))
            .border(1.dp, Color(0xFF7B61FF).copy(alpha = 0.2f), RoundedCornerShape(20.dp))
            .padding(18.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Animated phone ringing icon
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(52.dp)) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .scale(0.5f + ring1 * 0.5f)
                        .alpha(1f - ring1)
                        .background(Color(0xFF7B61FF).copy(alpha = 0.4f), CircleShape)
                )
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .scale(0.5f + ring2 * 0.5f)
                        .alpha(1f - ring2)
                        .background(Color(0xFF7B61FF).copy(alpha = 0.4f), CircleShape)
                )
                Icon(
                    Icons.Filled.Phone,
                    contentDescription = null,
                    tint = Color(0xFF7B61FF),
                    modifier = Modifier.size(26.dp)
                )
            }
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Simulate Scam Call", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                Text(
                    "See AEGIS intercept a real scam number in real-time",
                    color = TextSecondary, fontSize = 11.sp, lineHeight = 16.sp
                )
            }
            Spacer(Modifier.width(12.dp))
            FilledIconButton(
                onClick = onSimulate,
                modifier = Modifier.size(40.dp),
                colors = IconButtonDefaults.filledIconButtonColors(
                    containerColor = Color(0xFF7B61FF).copy(alpha = 0.2f),
                    contentColor = Color(0xFF7B61FF)
                )
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = "Simulate", modifier = Modifier.size(20.dp))
            }
        }
    }
}

// ─── Incoming Call Overlay ────────────────────────────────────────────────────

@Composable
fun IncomingCallOverlay(state: SimulatedCallState, onDismiss: () -> Unit) {
    val isIncoming = state is SimulatedCallState.Incoming
    val isScreened = state is SimulatedCallState.Screened
    val info = when (state) {
        is SimulatedCallState.Incoming -> state.info
        is SimulatedCallState.Screened -> state.info
        else -> return
    }
    val blocked = (state as? SimulatedCallState.Screened)?.blocked ?: false
    val accentColor = if (isIncoming) Color(0xFF7B61FF) else if (blocked) CrimsonPulse else NeonGreen

    val infiniteTransition = rememberInfiniteTransition(label = "overlay")
    val ringScale by infiniteTransition.animateFloat(
        initialValue = if (isIncoming) 1f else 1.3f,
        targetValue = if (isIncoming) 1.3f else 1.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(if (isIncoming) 700 else 999_999, easing = EaseInOut),
            repeatMode = RepeatMode.Reverse
        ),
        label = "rs"
    )
    val ringAlpha by infiniteTransition.animateFloat(
        initialValue = if (isIncoming) 0.7f else 0.1f,
        targetValue = if (isIncoming) 0.1f else 0.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(if (isIncoming) 700 else 999_999, easing = EaseInOut),
            repeatMode = RepeatMode.Reverse
        ),
        label = "ra"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .background(
                brush = Brush.verticalGradient(listOf(Color(0xFF0D0B1E), Color(0xFF120E25))),
                shape = RoundedCornerShape(28.dp)
            )
            .border(1.5.dp, accentColor.copy(alpha = 0.5f), RoundedCornerShape(28.dp))
            .padding(24.dp)
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {

            // Status pill
            Box(
                modifier = Modifier
                    .background(accentColor.copy(alpha = 0.15f), RoundedCornerShape(50))
                    .border(1.dp, accentColor.copy(alpha = 0.4f), RoundedCornerShape(50))
                    .padding(horizontal = 14.dp, vertical = 5.dp)
            ) {
                Text(
                    text = when {
                        isIncoming -> "● INCOMING CALL"
                        blocked -> "🛡 BLOCKED BY AEGIS"
                        else -> "✓ CALL CLEARED"
                    },
                    color = accentColor,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp
                )
            }

            Spacer(Modifier.height(20.dp))

            // Phone icon with rings
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(100.dp)) {
                if (isIncoming) {
                    Box(
                        modifier = Modifier
                            .size(100.dp)
                            .scale(ringScale)
                            .alpha(ringAlpha)
                            .background(accentColor.copy(alpha = 0.3f), CircleShape)
                    )
                }
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .background(accentColor.copy(alpha = 0.15f), CircleShape)
                        .border(1.5.dp, accentColor.copy(alpha = 0.4f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = when {
                            isScreened && blocked -> Icons.Filled.CallEnd
                            isScreened -> Icons.Filled.CallReceived
                            else -> Icons.Filled.PhoneInTalk
                        },
                        contentDescription = null,
                        tint = accentColor,
                        modifier = Modifier.size(36.dp)
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            Text(info.number, color = TextPrimary, fontSize = 22.sp, fontWeight = FontWeight.Black, letterSpacing = 1.sp)
            Spacer(Modifier.height(4.dp))
            Text(info.label, color = accentColor, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)

            Spacer(Modifier.height(16.dp))

            // Risk badge
            val riskColor = when (info.risk) {
                CallRisk.SAFE -> NeonGreen
                CallRisk.SUSPECTED_SPAM -> AmberGlow
                else -> CrimsonPulse
            }
            Row(
                modifier = Modifier
                    .background(riskColor.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
                    .border(1.dp, riskColor.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("RISK", color = riskColor.copy(alpha = 0.6f), fontSize = 9.sp, letterSpacing = 1.sp)
                    Text(info.risk.name.replace("_", " "), color = riskColor, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
                Box(modifier = Modifier.width(1.dp).height(28.dp).background(riskColor.copy(alpha = 0.2f)))
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("REPORTS", color = riskColor.copy(alpha = 0.6f), fontSize = 9.sp, letterSpacing = 1.sp)
                    Text("${info.reportCount}", color = riskColor, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
                Box(modifier = Modifier.width(1.dp).height(28.dp).background(riskColor.copy(alpha = 0.2f)))
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("CONFIDENCE", color = riskColor.copy(alpha = 0.6f), fontSize = 9.sp, letterSpacing = 1.sp)
                    Text("${info.confidence}%", color = riskColor, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            if (isScreened) {
                Spacer(Modifier.height(12.dp))
                Text(
                    if (blocked) "Call silently terminated. Number flagged in your history."
                    else "Number verified safe. Call allowed.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    textAlign = TextAlign.Center,
                    lineHeight = 17.sp
                )
                Spacer(Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onDismiss,
                    border = BorderStroke(1.dp, TextSecondary.copy(alpha = 0.3f)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("DISMISS", fontSize = 11.sp, letterSpacing = 2.sp)
                }
            }
        }
    }
}

// ─── Number Lookup Card ───────────────────────────────────────────────────────

@Composable
fun NumberLookupCard(
    input: String,
    checkState: NumberCheckState,
    onInputChange: (String) -> Unit,
    onCheck: () -> Unit,
    onClear: () -> Unit
) {
    val isChecking = checkState is NumberCheckState.Checking
    val borderColor by animateColorAsState(
        when (checkState) {
            is NumberCheckState.Checking -> AmberGlow
            is NumberCheckState.Result -> if (checkState.info.risk == CallRisk.SAFE) NeonGreen else CrimsonPulse
            else -> ElectricCyan.copy(alpha = 0.2f)
        },
        animationSpec = tween(400), label = "nb"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(FrostedGlass.copy(alpha = 0.5f), RoundedCornerShape(20.dp))
            .border(1.5.dp, borderColor, RoundedCornerShape(20.dp))
            .padding(18.dp)
    ) {
        Column {
            Text("NUMBER LOOKUP", color = ElectricCyan, fontSize = 10.sp, letterSpacing = 3.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = input,
                onValueChange = onInputChange,
                modifier = Modifier.fillMaxWidth(),
                placeholder = {
                    Text("+91 XXXXX XXXXX or any number...", color = TextSecondary.copy(alpha = 0.4f), fontSize = 13.sp)
                },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = ElectricCyan.copy(alpha = 0.5f),
                    unfocusedBorderColor = ElectricCyan.copy(alpha = 0.1f),
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    cursorColor = ElectricCyan,
                    focusedContainerColor = Color.Black.copy(alpha = 0.3f),
                    unfocusedContainerColor = Color.Black.copy(alpha = 0.2f),
                ),
                shape = RoundedCornerShape(12.dp),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone, imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = { onCheck() }),
                leadingIcon = {
                    Icon(Icons.Filled.Phone, null, tint = ElectricCyan.copy(alpha = 0.5f), modifier = Modifier.size(18.dp))
                },
                trailingIcon = {
                    if (input.isNotEmpty()) IconButton(onClick = onClear) {
                        Icon(Icons.Filled.Close, null, tint = TextSecondary, modifier = Modifier.size(18.dp))
                    }
                }
            )

            Spacer(Modifier.height(12.dp))

            Button(
                onClick = onCheck,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                enabled = input.isNotBlank() && !isChecking,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent, disabledContainerColor = Color.Transparent),
                border = BorderStroke(1.5.dp, if (input.isNotBlank() && !isChecking) ElectricCyan else ElectricCyan.copy(0.2f)),
                contentPadding = PaddingValues(0.dp)
            ) {
                Box(
                    modifier = Modifier.fillMaxSize().background(
                        if (input.isNotBlank() && !isChecking)
                            Brush.horizontalGradient(listOf(ElectricCyan.copy(0.12f), ElectricCyan.copy(0.25f), ElectricCyan.copy(0.12f)))
                        else Brush.horizontalGradient(listOf(Color.Transparent, Color.Transparent))
                    ),
                    contentAlignment = Alignment.Center
                ) {
                    if (isChecking) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(color = AmberGlow, strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(10.dp))
                            Text("CHECKING...", color = AmberGlow, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Search, null, tint = ElectricCyan, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("CHECK NUMBER", color = ElectricCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
                        }
                    }
                }
            }
        }
    }
}

// ─── Number Risk Result Card ──────────────────────────────────────────────────

@Composable
fun NumberRiskCard(info: CallRiskInfo) {
    val color = when (info.risk) {
        CallRisk.SAFE -> NeonGreen
        CallRisk.SUSPECTED_SPAM -> AmberGlow
        else -> CrimsonPulse
    }
    val icon = when (info.risk) {
        CallRisk.SAFE -> Icons.Filled.CheckCircle
        CallRisk.SUSPECTED_SPAM -> Icons.Filled.HelpOutline
        else -> Icons.Filled.Cancel
    }

    val infiniteTransition = rememberInfiniteTransition(label = "riskCard")
    val glow by infiniteTransition.animateFloat(
        initialValue = 0.6f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1200, easing = EaseInOut), RepeatMode.Reverse),
        label = "rg"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Brush.verticalGradient(listOf(color.copy(alpha = 0.1f), color.copy(alpha = 0.05f))), RoundedCornerShape(20.dp))
            .border(1.5.dp, color.copy(alpha = 0.45f), RoundedCornerShape(20.dp))
            .padding(20.dp)
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
            Box(contentAlignment = Alignment.Center) {
                Box(
                    modifier = Modifier.size(76.dp).scale(glow)
                        .background(color.copy(alpha = 0.15f), CircleShape)
                )
                Icon(icon, null, tint = color, modifier = Modifier.size(46.dp))
            }
            Spacer(Modifier.height(10.dp))
            Text(info.risk.name.replace("_", " "), color = color, fontSize = 18.sp, fontWeight = FontWeight.Black, letterSpacing = 1.sp)
            Spacer(Modifier.height(2.dp))
            Text(info.number, color = TextSecondary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.height(12.dp))

            // Confidence bar
            Text("Confidence: ${info.confidence}%", color = TextSecondary, fontSize = 10.sp, letterSpacing = 1.sp)
            Spacer(Modifier.height(6.dp))
            val animConf by animateFloatAsState(info.confidence / 100f, tween(800), label = "conf")
            Box(
                modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp))
                    .background(SurfaceVariant)
            ) {
                Box(
                    modifier = Modifier.fillMaxWidth(animConf).fillMaxHeight()
                        .background(Brush.horizontalGradient(listOf(color.copy(0.7f), color)), RoundedCornerShape(3.dp))
                )
            }

            if (info.reportCount > 0) {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier
                        .background(color.copy(alpha = 0.08f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 14.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Filled.Group, null, tint = color, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "${info.reportCount} users reported this as \"${info.label}\"",
                        color = color.copy(alpha = 0.85f),
                        fontSize = 11.sp,
                        lineHeight = 16.sp
                    )
                }
            }
        }
    }
}

// ─── Blocked Call Item ────────────────────────────────────────────────────────

@Composable
fun BlockedCallItem(entry: BlockedCallEntry) {
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { kotlinx.coroutines.delay(80); visible = true }

    val color = when (entry.callRisk) {
        CallRisk.SAFE -> NeonGreen
        CallRisk.SUSPECTED_SPAM -> AmberGlow
        else -> CrimsonPulse
    }
    val timeFormat = remember { SimpleDateFormat("HH:mm · dd MMM", Locale.getDefault()) }

    AnimatedVisibility(visible = visible, enter = fadeIn(tween(300)) + slideInHorizontally(tween(300)) { it / 3 }) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.horizontalGradient(listOf(color.copy(alpha = 0.05f), FrostedGlass.copy(alpha = 0.3f))),
                    RoundedCornerShape(14.dp)
                )
                .border(1.dp, color.copy(alpha = 0.2f), RoundedCornerShape(14.dp))
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(color.copy(alpha = 0.1f), CircleShape)
                    .border(1.dp, color.copy(alpha = 0.25f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Filled.CallEnd, null, tint = color, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.displayName, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(entry.riskLabel, color = color.copy(alpha = 0.8f), fontSize = 10.sp, fontWeight = FontWeight.Medium)
                    Text("  ·  ", color = TextSecondary, fontSize = 10.sp)
                    Text(timeFormat.format(Date(entry.blockedAt)), color = TextSecondary, fontSize = 10.sp)
                }
            }
            Box(
                modifier = Modifier
                    .background(color.copy(alpha = 0.1f), RoundedCornerShape(8.dp))
                    .border(0.5.dp, color.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 5.dp)
            ) {
                Text("BLOCKED", color = color, fontSize = 8.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            }
        }
    }
}
