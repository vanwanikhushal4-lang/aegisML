package com.aegis.guard.ui.scanner

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.guard.scanner.ScanResult
import com.aegis.guard.scanner.ThreatLevel
import com.aegis.guard.ui.theme.*
import kotlinx.coroutines.delay
import kotlin.math.*

@Composable
fun ScannerScreen(
    viewModel: ScannerViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        DeepSpaceBlack,
                        Color(0xFF050810),
                        DeepSpaceBlack
                    )
                )
            )
    ) {
        // Animated background grid
        BackgroundGrid()

        when (val state = uiState) {
            is ScannerUiState.Idle -> IdleScreen(onScanClick = { viewModel.startScan() })
            is ScannerUiState.Scanning -> ScanningScreen(progress = state.progress, appCount = state.appsScanned)
            is ScannerUiState.Results -> ResultsScreen(
                apps = state.apps,
                onRescan = { viewModel.startScan() }
            )
        }
    }
}

// ─── Background Grid ─────────────────────────────────────────────────────────

@Composable
fun BackgroundGrid() {
    val infiniteTransition = rememberInfiniteTransition(label = "grid")
    val gridOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 40f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "gridScroll"
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        val gridSize = 40f
        val gridColor = ElectricCyan.copy(alpha = 0.04f)

        // Draw vertical lines
        var x = (gridOffset % gridSize) - gridSize
        while (x < size.width) {
            drawLine(gridColor, Offset(x, 0f), Offset(x, size.height), strokeWidth = 0.5f)
            x += gridSize
        }
        // Draw horizontal lines
        var y = (gridOffset % gridSize) - gridSize
        while (y < size.height) {
            drawLine(gridColor, Offset(0f, y), Offset(size.width, y), strokeWidth = 0.5f)
            y += gridSize
        }
    }
}

// ─── Idle Screen ──────────────────────────────────────────────────────────────

@Composable
fun IdleScreen(onScanClick: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "idle")

    // Pulsing rings
    val ring1Scale by infiniteTransition.animateFloat(
        initialValue = 0.8f, targetValue = 1.4f,
        animationSpec = infiniteRepeatable(tween(2000, easing = EaseOut), RepeatMode.Restart),
        label = "ring1"
    )
    val ring1Alpha by infiniteTransition.animateFloat(
        initialValue = 0.6f, targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(2000, easing = EaseOut), RepeatMode.Restart),
        label = "ring1a"
    )
    val ring2Scale by infiniteTransition.animateFloat(
        initialValue = 0.8f, targetValue = 1.4f,
        animationSpec = infiniteRepeatable(tween(2000, 700, easing = EaseOut), RepeatMode.Restart),
        label = "ring2"
    )
    val ring2Alpha by infiniteTransition.animateFloat(
        initialValue = 0.6f, targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(2000, 700, easing = EaseOut), RepeatMode.Restart),
        label = "ring2a"
    )
    val ring3Scale by infiniteTransition.animateFloat(
        initialValue = 0.8f, targetValue = 1.4f,
        animationSpec = infiniteRepeatable(tween(2000, 1400, easing = EaseOut), RepeatMode.Restart),
        label = "ring3"
    )
    val ring3Alpha by infiniteTransition.animateFloat(
        initialValue = 0.6f, targetValue = 0f,
        animationSpec = infiniteRepeatable(tween(2000, 1400, easing = EaseOut), RepeatMode.Restart),
        label = "ring3a"
    )

    // Shield breathing
    val shieldScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.06f,
        animationSpec = infiniteRepeatable(tween(1800, easing = EaseInOut), RepeatMode.Reverse),
        label = "shield"
    )
    val shieldGlow by infiniteTransition.animateFloat(
        initialValue = 0.3f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1800, easing = EaseInOut), RepeatMode.Reverse),
        label = "glow"
    )

    // Floating particles
    val particleAnim by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(4000, easing = LinearEasing)),
        label = "particles"
    )

    // Button pulse
    val btnScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.05f,
        animationSpec = infiniteRepeatable(tween(1000, easing = EaseInOut), RepeatMode.Reverse),
        label = "btn"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Title
        Text(
            "THREAT SCANNER",
            color = ElectricCyan,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 6.sp
        )
        Spacer(Modifier.height(48.dp))

        // Shield with pulsing rings
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(220.dp)
        ) {
            // Pulsing rings
            Box(
                modifier = Modifier
                    .size(200.dp)
                    .scale(ring1Scale)
                    .alpha(ring1Alpha)
                    .border(1.5.dp, ElectricCyan.copy(alpha = 0.5f), CircleShape)
            )
            Box(
                modifier = Modifier
                    .size(200.dp)
                    .scale(ring2Scale)
                    .alpha(ring2Alpha)
                    .border(1.5.dp, ElectricCyan.copy(alpha = 0.5f), CircleShape)
            )
            Box(
                modifier = Modifier
                    .size(200.dp)
                    .scale(ring3Scale)
                    .alpha(ring3Alpha)
                    .border(1.5.dp, ElectricCyan.copy(alpha = 0.5f), CircleShape)
            )

            // Glow orb behind shield
            Box(
                modifier = Modifier
                    .size(130.dp)
                    .scale(shieldScale)
                    .background(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                ElectricCyan.copy(alpha = shieldGlow * 0.4f),
                                Color.Transparent
                            )
                        ),
                        shape = CircleShape
                    )
            )

            // Shield icon
            Icon(
                imageVector = Icons.Filled.Security,
                contentDescription = "Shield",
                tint = ElectricCyan,
                modifier = Modifier
                    .size(100.dp)
                    .scale(shieldScale)
                    .drawBehind {
                        drawCircle(
                            color = ElectricCyan.copy(alpha = shieldGlow * 0.2f),
                            radius = size.minDimension * 0.8f
                        )
                    }
            )

            // Floating particles
            FloatingParticles(animProgress = particleAnim, color = ElectricCyan)
        }

        Spacer(Modifier.height(48.dp))

        Text(
            "AEGIS is standing by.",
            color = TextPrimary,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Deep scan all installed applications\nfor malware, spyware & hidden threats.",
            color = TextSecondary,
            fontSize = 13.sp,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp
        )

        Spacer(Modifier.height(52.dp))

        // Scan button
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.scale(btnScale)
        ) {
            // Outer glow
            Box(
                modifier = Modifier
                    .width(200.dp)
                    .height(52.dp)
                    .background(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                ElectricCyan.copy(alpha = 0.3f),
                                Color.Transparent
                            ),
                            radius = 200f
                        ),
                        shape = RoundedCornerShape(50)
                    )
            )
            Button(
                onClick = onScanClick,
                modifier = Modifier
                    .width(200.dp)
                    .height(52.dp),
                shape = RoundedCornerShape(50),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                border = BorderStroke(1.5.dp, ElectricCyan),
                contentPadding = PaddingValues(0.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            brush = Brush.horizontalGradient(
                                listOf(
                                    ElectricCyan.copy(alpha = 0.15f),
                                    ElectricCyan.copy(alpha = 0.3f),
                                    ElectricCyan.copy(alpha = 0.15f)
                                )
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "INITIATE SCAN",
                        color = ElectricCyan,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 3.sp
                    )
                }
            }
        }
    }
}

// ─── Floating Particles ───────────────────────────────────────────────────────

@Composable
fun FloatingParticles(animProgress: Float, color: Color) {
    val particles = remember {
        List(12) { i ->
            val angle = (i * 30f) * (PI / 180f).toFloat()
            val radius = 90f + (i % 3) * 20f
            Triple(angle, radius, i * 0.083f) // angle, radius, phase offset
        }
    }

    Canvas(modifier = Modifier.size(220.dp)) {
        val center = Offset(size.width / 2, size.height / 2)
        particles.forEach { (baseAngle, baseRadius, phaseOffset) ->
            val progress = (animProgress + phaseOffset) % 1f
            val angle = baseAngle + progress * 2 * PI.toFloat()
            val radiusVariation = baseRadius + sin(progress * 2 * PI.toFloat()) * 10f
            val x = center.x + cos(angle) * radiusVariation
            val y = center.y + sin(angle) * radiusVariation
            val particleAlpha = 0.3f + sin(progress * 2 * PI.toFloat()) * 0.3f + 0.3f

            drawCircle(
                color = color.copy(alpha = particleAlpha.coerceIn(0f, 1f)),
                radius = 3f + sin(progress * PI.toFloat()) * 2f,
                center = Offset(x, y)
            )
        }
    }
}

// ─── Scanning Screen ──────────────────────────────────────────────────────────

@Composable
fun ScanningScreen(progress: Float, appCount: Int) {
    val infiniteTransition = rememberInfiniteTransition(label = "scan")

    // Radar sweep rotation
    val radarAngle by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1500, easing = LinearEasing)),
        label = "radar"
    )

    // Concentric ring pulses
    val ringPulse by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1000, easing = LinearEasing)),
        label = "ringPulse"
    )

    // Data stream characters
    val streamAnim by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(3000, easing = LinearEasing)),
        label = "stream"
    )

    val animatedProgress by animateFloatAsState(
        targetValue = progress,
        animationSpec = tween(300),
        label = "progress"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "SCANNING",
            color = AmberGlow,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 8.sp
        )
        Spacer(Modifier.height(40.dp))

        // RADAR
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(260.dp)
        ) {
            Canvas(modifier = Modifier.size(260.dp)) {
                val center = Offset(size.width / 2, size.height / 2)
                val maxRadius = size.minDimension / 2

                // Background circle fill
                drawCircle(
                    color = Color(0xFF0A1A0A).copy(alpha = 0.8f),
                    center = center,
                    radius = maxRadius
                )

                // Concentric rings with pulse
                for (i in 1..4) {
                    val ringRadius = maxRadius * (i / 4f)
                    val pulseAlpha = if (i == (ringPulse * 4).toInt() % 4 + 1) 0.5f else 0.12f
                    drawCircle(
                        color = ElectricCyan.copy(alpha = pulseAlpha),
                        center = center,
                        radius = ringRadius,
                        style = Stroke(width = if (pulseAlpha > 0.2f) 2f else 1f)
                    )
                }

                // Cross lines
                drawLine(
                    color = ElectricCyan.copy(alpha = 0.1f),
                    start = Offset(center.x, center.y - maxRadius),
                    end = Offset(center.x, center.y + maxRadius),
                    strokeWidth = 1f
                )
                drawLine(
                    color = ElectricCyan.copy(alpha = 0.1f),
                    start = Offset(center.x - maxRadius, center.y),
                    end = Offset(center.x + maxRadius, center.y),
                    strokeWidth = 1f
                )

                // Radar sweep with gradient trail
                rotate(degrees = radarAngle, pivot = center) {
                    // Sweep gradient
                    drawArc(
                        brush = Brush.sweepGradient(
                            colors = listOf(
                                Color.Transparent,
                                Color.Transparent,
                                Color.Transparent,
                                AmberGlow.copy(alpha = 0.5f),
                                AmberGlow.copy(alpha = 0.8f),
                            ),
                            center = center
                        ),
                        startAngle = -90f,
                        sweepAngle = 80f,
                        useCenter = true,
                        topLeft = Offset(center.x - maxRadius, center.y - maxRadius),
                        size = Size(maxRadius * 2, maxRadius * 2)
                    )
                    // Leading edge line
                    drawLine(
                        color = AmberGlow,
                        start = center,
                        end = Offset(center.x, center.y - maxRadius),
                        strokeWidth = 2f
                    )
                }

                // Radar blips (fake threats found)
                val blipPositions = listOf(
                    Pair(0.4f, 220f), Pair(0.6f, 45f), Pair(0.75f, 130f), Pair(0.3f, 310f)
                )
                blipPositions.forEach { (radFrac, angleDeg) ->
                    val bAngle = angleDeg * PI.toFloat() / 180f
                    val bRadius = maxRadius * radFrac
                    val bx = center.x + cos(bAngle) * bRadius
                    val by = center.y + sin(bAngle) * bRadius
                    val blipAlpha = ((sin(ringPulse * 2 * PI.toFloat()) + 1) / 2f)
                    drawCircle(
                        color = CrimsonPulse.copy(alpha = blipAlpha),
                        radius = 6f,
                        center = Offset(bx, by)
                    )
                    drawCircle(
                        color = CrimsonPulse.copy(alpha = blipAlpha * 0.3f),
                        radius = 12f,
                        center = Offset(bx, by)
                    )
                }

                // Center dot
                drawCircle(
                    color = AmberGlow,
                    radius = 5f,
                    center = center
                )
                drawCircle(
                    color = AmberGlow.copy(alpha = 0.3f),
                    radius = 12f,
                    center = center
                )

                // Outer ring border
                drawCircle(
                    color = ElectricCyan.copy(alpha = 0.3f),
                    center = center,
                    radius = maxRadius,
                    style = Stroke(width = 2f)
                )
            }
        }

        Spacer(Modifier.height(36.dp))

        // Apps scanned counter
        AnimatedContent(
            targetState = appCount,
            transitionSpec = {
                (slideInVertically { -it } + fadeIn()) togetherWith
                        (fadeOut())
            },
            label = "counter"
        ) { count ->
            Text(
                text = "$count",
                color = AmberGlow,
                fontSize = 48.sp,
                fontWeight = FontWeight.Black
            )
        }
        Text(
            "APPS ANALYZED",
            color = TextSecondary,
            fontSize = 10.sp,
            letterSpacing = 4.sp
        )

        Spacer(Modifier.height(32.dp))

        // Progress bar
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(4.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(SurfaceVariant)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction = animatedProgress)
                    .fillMaxHeight()
                    .background(
                        brush = Brush.horizontalGradient(
                            listOf(ElectricCyan, AmberGlow)
                        ),
                        shape = RoundedCornerShape(2.dp)
                    )
            )
        }

        Spacer(Modifier.height(12.dp))

        // Scrolling data stream text
        DataStreamText(animProgress = streamAnim)
    }
}

@Composable
fun DataStreamText(animProgress: Float) {
    val lines = listOf(
        "Analyzing permission manifests...",
        "Checking signature hashes...",
        "Scanning for overlay attacks...",
        "Verifying network permissions...",
        "Detecting accessibility abuse...",
        "Analyzing DEX bytecode flags..."
    )
    val lineIndex = (animProgress * lines.size).toInt().coerceIn(0, lines.size - 1)
    val displayLine = lines[lineIndex]

    Text(
        text = "> $displayLine",
        color = ElectricCyan.copy(alpha = 0.7f),
        fontSize = 11.sp,
        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
        letterSpacing = 0.5.sp
    )
}

// ─── Results Screen ───────────────────────────────────────────────────────────

@Composable
fun ResultsScreen(apps: List<ScanResult>, onRescan: () -> Unit) {
    val dangerousCount = apps.count { it.threatLevel == ThreatLevel.DANGEROUS }
    val suspiciousCount = apps.count { it.threatLevel == ThreatLevel.SUSPICIOUS }
    val safeCount = apps.count { it.threatLevel == ThreatLevel.SAFE }

    val infiniteTransition = rememberInfiniteTransition(label = "results")
    val threatPulse by infiniteTransition.animateFloat(
        initialValue = 0.7f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(600, easing = EaseInOut), RepeatMode.Reverse),
        label = "threatPulse"
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(top = 24.dp, bottom = 32.dp)
    ) {
        // Header
        item {
            Text(
                "SCAN COMPLETE",
                color = ElectricCyan,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 6.sp,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(20.dp))

            // Threat Summary Banner
            if (dangerousCount > 0) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.horizontalGradient(
                                listOf(
                                    CrimsonPulse.copy(alpha = 0.15f),
                                    CrimsonPulse.copy(alpha = 0.25f),
                                    CrimsonPulse.copy(alpha = 0.15f)
                                )
                            ),
                            shape = RoundedCornerShape(16.dp)
                        )
                        .border(
                            width = 1.dp,
                            brush = Brush.horizontalGradient(
                                listOf(CrimsonPulse.copy(alpha = 0.4f), CrimsonPulse.copy(alpha = 0.8f), CrimsonPulse.copy(alpha = 0.4f))
                            ),
                            shape = RoundedCornerShape(16.dp)
                        )
                        .padding(20.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = CrimsonPulse,
                            modifier = Modifier.size(40.dp).scale(threatPulse)
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "$dangerousCount THREATS DETECTED",
                            color = CrimsonPulse,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 2.sp
                        )
                    }
                }
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.horizontalGradient(
                                listOf(
                                    NeonGreen.copy(alpha = 0.1f),
                                    NeonGreen.copy(alpha = 0.2f),
                                    NeonGreen.copy(alpha = 0.1f)
                                )
                            ),
                            shape = RoundedCornerShape(16.dp)
                        )
                        .border(1.dp, NeonGreen.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
                        .padding(20.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = NeonGreen,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "DEVICE SECURE",
                            color = NeonGreen,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 2.sp
                        )
                    }
                }
            }

            Spacer(Modifier.height(20.dp))

            // Stats row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                StatChip(Modifier.weight(1f), count = dangerousCount, label = "DANGER", color = CrimsonPulse)
                StatChip(Modifier.weight(1f), count = suspiciousCount, label = "SUSPECT", color = AmberGlow)
                StatChip(Modifier.weight(1f), count = safeCount, label = "CLEAN", color = NeonGreen)
            }

            Spacer(Modifier.height(20.dp))

            // Rescan button
            OutlinedButton(
                onClick = onRescan,
                modifier = Modifier.fillMaxWidth().height(44.dp),
                shape = RoundedCornerShape(50),
                border = BorderStroke(1.dp, ElectricCyan.copy(alpha = 0.4f)),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = ElectricCyan)
            ) {
                Text("RESCAN", fontSize = 12.sp, letterSpacing = 4.sp, fontWeight = FontWeight.Bold)
            }

            Spacer(Modifier.height(8.dp))

            Text(
                "ALL APPS  (${apps.size})",
                color = TextSecondary,
                fontSize = 10.sp,
                letterSpacing = 3.sp,
                modifier = Modifier.padding(vertical = 8.dp)
            )
        }

        // App items with stagger
        itemsIndexed(apps) { index, app ->
            AnimatedAppItem(app = app, index = index)
        }
    }
}

@Composable
fun StatChip(modifier: Modifier, count: Int, label: String, color: Color) {
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
            .border(1.dp, color.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
            .padding(vertical = 12.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "$count",
                color = color,
                fontSize = 22.sp,
                fontWeight = FontWeight.Black
            )
            Text(
                text = label,
                color = color.copy(alpha = 0.7f),
                fontSize = 9.sp,
                letterSpacing = 1.sp,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

@Composable
fun AnimatedAppItem(app: ScanResult, index: Int) {
    var visible by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        delay(index * 40L)
        visible = true
    }

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(300)) + slideInVertically(tween(300)) { it / 2 }
    ) {
        val color = when (app.threatLevel) {
            ThreatLevel.SAFE -> NeonGreen
            ThreatLevel.SUSPICIOUS -> AmberGlow
            ThreatLevel.DANGEROUS -> CrimsonPulse
        }
        val label = when (app.threatLevel) {
            ThreatLevel.SAFE -> "SAFE"
            ThreatLevel.SUSPICIOUS -> "SUSPECT"
            ThreatLevel.DANGEROUS -> "THREAT"
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = Brush.horizontalGradient(
                        listOf(
                            color.copy(alpha = 0.05f),
                            FrostedGlass.copy(alpha = 0.5f)
                        )
                    ),
                    shape = RoundedCornerShape(12.dp)
                )
                .border(
                    width = 1.dp,
                    brush = Brush.horizontalGradient(
                        listOf(color.copy(alpha = 0.3f), Color.Transparent)
                    ),
                    shape = RoundedCornerShape(12.dp)
                )
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Left accent bar
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height(36.dp)
                    .background(color, RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.appName,
                    color = TextPrimary,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = app.packageName,
                    color = TextSecondary,
                    fontSize = 10.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }

            Spacer(Modifier.width(10.dp))

            Column(horizontalAlignment = Alignment.End) {
                // Score badge
                Box(
                    modifier = Modifier
                        .background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp))
                        .border(0.5.dp, color.copy(alpha = 0.4f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = label,
                        color = color,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "RISK ${app.score}",
                    color = color.copy(alpha = 0.7f),
                    fontSize = 9.sp,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }
        }
    }
}
