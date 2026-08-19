package com.aegis.guard.ui.webshield

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
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.guard.ui.theme.*
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*
import kotlin.math.*

@Composable
fun WebShieldScreen(viewModel: WebShieldViewModel = hiltViewModel()) {
    val urlInput by viewModel.urlInput.collectAsState()
    val urlCheckState by viewModel.urlCheckState.collectAsState()
    val smsCheckState by viewModel.smsCheckState.collectAsState()
    val history by viewModel.history.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val focusManager = LocalFocusManager.current

    val infiniteTransition = rememberInfiniteTransition(label = "ws_bg")
    val bgShift by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(8000, easing = LinearEasing)),
        label = "bgShift"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF050810),
                        Color(0xFF060C16),
                        Color(0xFF050810)
                    )
                )
            )
    ) {
        // Animated network nodes background
        NetworkBackground(animProgress = bgShift)

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            item { WebShieldHeader() }

            // Stats row
            item { StatsRow(stats = stats) }

            // URL Input Card
            item {
                UrlInputCard(
                    urlInput = urlInput,
                    checkState = urlCheckState,
                    onInputChange = viewModel::onUrlInputChange,
                    onCheck = {
                        focusManager.clearFocus()
                        viewModel.checkUrl()
                    },
                    onClear = viewModel::clearResult
                )
            }

            // Result card (animated in/out)
            item {
                AnimatedVisibility(
                    visible = urlCheckState is UrlCheckState.Result,
                    enter = fadeIn(tween(400)) + expandVertically(tween(400, easing = EaseOut)),
                    exit = fadeOut(tween(200)) + shrinkVertically(tween(200))
                ) {
                    (urlCheckState as? UrlCheckState.Result)?.let {
                        UrlResultCard(result = it.result)
                    }
                }
            }

            // SMS Scanner Card
            item {
                SmsLinkScannerCard(
                    smsState = smsCheckState,
                    onScan = viewModel::scanSmsLinks
                )
            }

            // SMS Results
            if (smsCheckState is SmsCheckState.Results) {
                val results = (smsCheckState as SmsCheckState.Results).results
                items(results) { smsResult ->
                    SmsLinkItem(smsResult = smsResult)
                }
            }

            // History
            if (history.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "RECENT SCANS",
                            color = TextSecondary,
                            fontSize = 10.sp,
                            letterSpacing = 3.sp,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(Modifier.weight(1f))
                        Text(
                            "${history.size} scans",
                            color = TextSecondary.copy(alpha = 0.5f),
                            fontSize = 10.sp
                        )
                    }
                }
                items(history) { scanResult ->
                    HistoryItem(result = scanResult)
                }
            }

            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

// ─── Network Background Canvas ─────────────────────────────────────────────

@Composable
fun NetworkBackground(animProgress: Float) {
    val nodes = remember {
        List(12) { Pair((10..90).random() / 100f, (10..90).random() / 100f) }
    }
    Canvas(modifier = Modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height

        // Draw connections between nearby nodes
        nodes.forEachIndexed { i, (nx1, ny1) ->
            nodes.forEachIndexed { j, (nx2, ny2) ->
                if (i < j) {
                    val dist = sqrt((nx2 - nx1).pow(2) + (ny2 - ny1).pow(2))
                    if (dist < 0.3f) {
                        val pulseAlpha = (sin((animProgress + (i + j) * 0.1f) * 2 * PI.toFloat()) + 1) / 2f * 0.08f + 0.02f
                        drawLine(
                            color = ElectricCyan.copy(alpha = pulseAlpha),
                            start = Offset(nx1 * w, ny1 * h),
                            end = Offset(nx2 * w, ny2 * h),
                            strokeWidth = 0.8f
                        )
                    }
                }
            }
        }

        // Draw node dots
        nodes.forEachIndexed { i, (nx, ny) ->
            val pulseAlpha = (sin((animProgress + i * 0.2f) * 2 * PI.toFloat()) + 1) / 2f * 0.2f + 0.05f
            drawCircle(
                color = ElectricCyan.copy(alpha = pulseAlpha.toFloat()),
                radius = 3f,
                center = Offset(nx * w, ny * h)
            )
        }
    }
}

// ─── Header ───────────────────────────────────────────────────────────────────

@Composable
fun WebShieldHeader() {
    val infiniteTransition = rememberInfiniteTransition(label = "header")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(2000, easing = EaseInOut), RepeatMode.Reverse),
        label = "glow"
    )

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth()
    ) {
        Box(contentAlignment = Alignment.Center) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(
                        brush = Brush.radialGradient(
                            listOf(ElectricCyan.copy(alpha = glowAlpha * 0.3f), Color.Transparent)
                        ),
                        shape = CircleShape
                    )
            )
            Icon(
                Icons.Filled.Language,
                contentDescription = null,
                tint = ElectricCyan,
                modifier = Modifier.size(28.dp)
            )
        }
        Spacer(Modifier.width(14.dp))
        Column {
            Text("WEB SHIELD", color = ElectricCyan, fontSize = 18.sp, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
            Text("Real-time URL & Link Protection", color = TextSecondary, fontSize = 12.sp)
        }

        Spacer(Modifier.weight(1f))

        // Active indicator
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .background(NeonGreen.copy(alpha = 0.1f), RoundedCornerShape(50))
                .border(1.dp, NeonGreen.copy(alpha = 0.3f), RoundedCornerShape(50))
                .padding(horizontal = 10.dp, vertical = 5.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .background(NeonGreen, CircleShape)
            )
            Spacer(Modifier.width(5.dp))
            Text("ACTIVE", color = NeonGreen, fontSize = 9.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
        }
    }
}

// ─── Stats Row ────────────────────────────────────────────────────────────────

@Composable
fun StatsRow(stats: WebShieldStats) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        WebStatChip(modifier = Modifier.weight(1f), value = stats.urlsChecked, label = "URLS CHECKED", color = ElectricCyan, icon = Icons.Filled.Search)
        WebStatChip(modifier = Modifier.weight(1f), value = stats.threatsBlocked, label = "BLOCKED", color = CrimsonPulse, icon = Icons.Filled.Block)
        WebStatChip(modifier = Modifier.weight(1f), value = stats.smsLinksScanned, label = "SMS LINKS", color = AmberGlow, icon = Icons.Filled.Sms)
    }
}

@Composable
fun WebStatChip(modifier: Modifier, value: Int, label: String, color: Color, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    val animatedValue by animateIntAsState(targetValue = value, animationSpec = tween(600), label = "statVal")

    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.08f), RoundedCornerShape(14.dp))
            .border(1.dp, color.copy(alpha = 0.2f), RoundedCornerShape(14.dp))
            .padding(vertical = 12.dp, horizontal = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null, tint = color.copy(alpha = 0.7f), modifier = Modifier.size(16.dp))
            Spacer(Modifier.height(4.dp))
            Text("$animatedValue", color = color, fontSize = 20.sp, fontWeight = FontWeight.Black)
            Text(label, color = color.copy(alpha = 0.6f), fontSize = 8.sp, letterSpacing = 0.5.sp, fontWeight = FontWeight.Medium)
        }
    }
}

// ─── URL Input Card ───────────────────────────────────────────────────────────

@Composable
fun UrlInputCard(
    urlInput: String,
    checkState: UrlCheckState,
    onInputChange: (String) -> Unit,
    onCheck: () -> Unit,
    onClear: () -> Unit
) {
    val isChecking = checkState is UrlCheckState.Checking
    val infiniteTransition = rememberInfiniteTransition(label = "scanline")
    val scanLineX by infiniteTransition.animateFloat(
        initialValue = -1f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1200, easing = LinearEasing)),
        label = "scanline"
    )
    val borderColor by animateColorAsState(
        targetValue = when (checkState) {
            is UrlCheckState.Checking -> AmberGlow
            is UrlCheckState.Result -> if (checkState.result.isMalicious) CrimsonPulse else NeonGreen
            else -> ElectricCyan.copy(alpha = 0.3f)
        },
        animationSpec = tween(400),
        label = "border"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(FrostedGlass.copy(alpha = 0.6f), RoundedCornerShape(20.dp))
            .border(1.5.dp, borderColor, RoundedCornerShape(20.dp))
            .clip(RoundedCornerShape(20.dp))
    ) {
        // Scanning line overlay
        if (isChecking) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(2.dp)
                    .align(Alignment.TopCenter)
                    .background(
                        brush = Brush.horizontalGradient(
                            listOf(
                                Color.Transparent,
                                AmberGlow.copy(alpha = 0.0f + (scanLineX + 1) / 2f),
                                AmberGlow,
                                AmberGlow.copy(alpha = 1f - (scanLineX + 1) / 2f),
                                Color.Transparent
                            ),
                            startX = (scanLineX * 500f),
                            endX = (scanLineX * 500f) + 300f
                        )
                    )
            )
        }

        Column(modifier = Modifier.padding(18.dp)) {
            Text("CHECK A URL", color = ElectricCyan, fontSize = 10.sp, letterSpacing = 3.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = urlInput,
                onValueChange = onInputChange,
                modifier = Modifier.fillMaxWidth(),
                placeholder = {
                    Text(
                        "https://suspicious-site.com or paste any link...",
                        color = TextSecondary.copy(alpha = 0.4f),
                        fontSize = 13.sp
                    )
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
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Go
                ),
                keyboardActions = KeyboardActions(onGo = { onCheck() }),
                leadingIcon = {
                    Icon(Icons.Filled.Link, contentDescription = null, tint = ElectricCyan.copy(alpha = 0.5f), modifier = Modifier.size(18.dp))
                },
                trailingIcon = {
                    if (urlInput.isNotEmpty()) {
                        IconButton(onClick = onClear) {
                            Icon(Icons.Filled.Close, contentDescription = "Clear", tint = TextSecondary, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            )

            Spacer(Modifier.height(12.dp))

            Button(
                onClick = onCheck,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                enabled = urlInput.isNotBlank() && !isChecking,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent,
                    disabledContainerColor = Color.Transparent
                ),
                border = BorderStroke(
                    1.5.dp,
                    if (urlInput.isNotBlank() && !isChecking) ElectricCyan else ElectricCyan.copy(alpha = 0.2f)
                ),
                contentPadding = PaddingValues(0.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            brush = if (urlInput.isNotBlank() && !isChecking)
                                Brush.horizontalGradient(listOf(ElectricCyan.copy(0.15f), ElectricCyan.copy(0.3f), ElectricCyan.copy(0.15f)))
                            else
                                Brush.horizontalGradient(listOf(Color.Transparent, Color.Transparent))
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    if (isChecking) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(
                                color = AmberGlow,
                                strokeWidth = 2.dp,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(10.dp))
                            Text("ANALYZING...", color = AmberGlow, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Shield, contentDescription = null, tint = ElectricCyan, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("SCAN URL", color = ElectricCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
                        }
                    }
                }
            }
        }
    }
}

// ─── URL Result Card ──────────────────────────────────────────────────────────

@Composable
fun UrlResultCard(result: UrlScanResult) {
    val color = if (result.isMalicious) CrimsonPulse else NeonGreen
    val infiniteTransition = rememberInfiniteTransition(label = "result")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.8f, targetValue = 1f,
        animationSpec = if (result.isMalicious)
            infiniteRepeatable(tween(500, easing = EaseInOut), RepeatMode.Reverse)
        else
            infiniteRepeatable(tween(2000, easing = EaseInOut), RepeatMode.Reverse),
        label = "pulse"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                brush = Brush.verticalGradient(
                    listOf(color.copy(alpha = 0.12f), color.copy(alpha = 0.06f))
                ),
                shape = RoundedCornerShape(20.dp)
            )
            .border(1.5.dp, color.copy(alpha = 0.5f), RoundedCornerShape(20.dp))
            .padding(20.dp)
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {

            // Big verdict icon
            Box(contentAlignment = Alignment.Center) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .scale(pulse)
                        .background(color.copy(alpha = 0.15f), CircleShape)
                )
                Icon(
                    imageVector = if (result.isMalicious) Icons.Filled.GppBad else Icons.Filled.GppGood,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(48.dp)
                )
            }

            Spacer(Modifier.height(12.dp))

            Text(
                text = if (result.isMalicious) "THREAT DETECTED" else "URL IS SAFE",
                color = color,
                fontSize = 18.sp,
                fontWeight = FontWeight.Black,
                letterSpacing = 2.sp
            )

            Spacer(Modifier.height(4.dp))
            Text(
                text = result.url,
                color = TextSecondary,
                fontSize = 11.sp,
                textAlign = TextAlign.Center,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                fontFamily = FontFamily.Monospace
            )

            Spacer(Modifier.height(16.dp))

            // Detail chips row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                ResultDetailChip(
                    modifier = Modifier.weight(1f),
                    label = "THREAT",
                    value = result.threatType.label,
                    color = color
                )
                ResultDetailChip(
                    modifier = Modifier.weight(1f),
                    label = "CONFIDENCE",
                    value = result.confidence.name,
                    color = color
                )
            }

            Spacer(Modifier.height(8.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Verified, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(12.dp))
                Spacer(Modifier.width(4.dp))
                Text("Verified by ${result.source}", color = TextSecondary, fontSize = 10.sp)
            }

            if (result.isMalicious) {
                Spacer(Modifier.height(12.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(CrimsonPulse.copy(alpha = 0.1f), RoundedCornerShape(10.dp))
                        .border(1.dp, CrimsonPulse.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = "⚠ ${result.threatType.description}. Do not visit this site or enter any personal information.",
                        color = CrimsonPulse.copy(alpha = 0.9f),
                        fontSize = 11.sp,
                        textAlign = TextAlign.Center,
                        lineHeight = 17.sp
                    )
                }
            }
        }
    }
}

@Composable
fun ResultDetailChip(modifier: Modifier, label: String, value: String, color: Color) {
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.08f), RoundedCornerShape(10.dp))
            .border(1.dp, color.copy(alpha = 0.2f), RoundedCornerShape(10.dp))
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(label, color = color.copy(alpha = 0.6f), fontSize = 8.sp, letterSpacing = 1.sp)
            Spacer(Modifier.height(3.dp))
            Text(value, color = color, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
    }
}

// ─── SMS Scanner Card ─────────────────────────────────────────────────────────

@Composable
fun SmsLinkScannerCard(smsState: SmsCheckState, onScan: () -> Unit) {
    val isScanning = smsState is SmsCheckState.Scanning
    val hasResults = smsState is SmsCheckState.Results
    val resultCount = if (hasResults) (smsState as SmsCheckState.Results).results.size else 0
    val threatCount = if (hasResults) (smsState as SmsCheckState.Results).results.count { it.scanResult.isMalicious } else 0

    val infiniteTransition = rememberInfiniteTransition(label = "sms")
    val smsWave by infiniteTransition.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1500, easing = LinearEasing)),
        label = "smsWave"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(FrostedGlass.copy(alpha = 0.5f), RoundedCornerShape(20.dp))
            .border(
                1.dp,
                if (isScanning) AmberGlow.copy(alpha = 0.5f) else ElectricCyan.copy(alpha = 0.15f),
                RoundedCornerShape(20.dp)
            )
            .padding(18.dp)
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(AmberGlow.copy(alpha = 0.1f), RoundedCornerShape(10.dp))
                        .border(1.dp, AmberGlow.copy(alpha = 0.2f), RoundedCornerShape(10.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Filled.Sms, contentDescription = null, tint = AmberGlow, modifier = Modifier.size(22.dp))
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("SMS LINK SCANNER", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                    Text(
                        if (hasResults) "$resultCount links found · $threatCount threats"
                        else "Scan your inbox for phishing links",
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }
            }

            Spacer(Modifier.height(14.dp))

            // Waveform visual when scanning
            if (isScanning) {
                Canvas(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(32.dp)
                        .padding(vertical = 4.dp)
                ) {
                    val wavePoints = 40
                    val stepX = size.width / wavePoints
                    for (i in 0 until wavePoints) {
                        val x = i * stepX
                        val amplitude = (sin((smsWave * 2 * PI + i * 0.4).toFloat()) * 10f + 10f).toFloat()
                        val waveColor = AmberGlow.copy(alpha = (sin((smsWave * 2 * PI + i * 0.3).toFloat()) + 1).toFloat() / 2f * 0.7f + 0.3f)
                        drawLine(
                            color = waveColor,
                            start = Offset(x, size.height / 2 - amplitude),
                            end = Offset(x, size.height / 2 + amplitude),
                            strokeWidth = 2.5f,
                            cap = StrokeCap.Round
                        )
                    }
                }
                Text(
                    "Scanning SMS inbox...",
                    color = AmberGlow.copy(alpha = 0.8f),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(10.dp))
            }

            OutlinedButton(
                onClick = onScan,
                modifier = Modifier.fillMaxWidth().height(44.dp),
                enabled = !isScanning,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, if (isScanning) AmberGlow.copy(alpha = 0.3f) else AmberGlow.copy(alpha = 0.5f)),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = AmberGlow)
            ) {
                if (isScanning) {
                    Text("SCANNING...", fontSize = 11.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold)
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            if (hasResults) "RESCAN SMS INBOX" else "SCAN SMS INBOX",
                            fontSize = 11.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

// ─── SMS Link Item ────────────────────────────────────────────────────────────

@Composable
fun SmsLinkItem(smsResult: SmsLinkResult) {
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        delay(100)
        visible = true
    }

    val isMalicious = smsResult.scanResult.isMalicious
    val color = if (isMalicious) CrimsonPulse else NeonGreen

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(300)) + slideInHorizontally(tween(300)) { -it / 2 }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = Brush.horizontalGradient(listOf(color.copy(alpha = 0.05f), FrostedGlass.copy(alpha = 0.3f))),
                    shape = RoundedCornerShape(14.dp)
                )
                .border(1.dp, color.copy(alpha = 0.25f), RoundedCornerShape(14.dp))
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(color.copy(alpha = 0.12f), CircleShape)
                    .border(1.dp, color.copy(alpha = 0.3f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    if (isMalicious) Icons.Filled.Warning else Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(smsResult.sender, color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                Text(
                    smsResult.messageSnippet,
                    color = TextSecondary,
                    fontSize = 10.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    smsResult.url,
                    color = color.copy(alpha = 0.8f),
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .background(color.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
                    .border(0.5.dp, color.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 5.dp)
            ) {
                Text(
                    if (isMalicious) "THREAT" else "SAFE",
                    color = color,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
            }
        }
    }
}

// ─── History Item ─────────────────────────────────────────────────────────────

@Composable
fun HistoryItem(result: UrlScanResult) {
    val color = if (result.isMalicious) CrimsonPulse else NeonGreen
    val timeFormat = remember { SimpleDateFormat("HH:mm · dd MMM", Locale.getDefault()) }
    val timeStr = timeFormat.format(Date(result.scannedAt))

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(FrostedGlass.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
            .border(0.5.dp, color.copy(alpha = 0.2f), RoundedCornerShape(12.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Color dot
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(color, CircleShape)
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                result.url,
                color = TextPrimary,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(timeStr, color = TextSecondary, fontSize = 9.sp)
        }
        Spacer(Modifier.width(10.dp))
        Text(
            if (result.isMalicious) "THREAT" else "CLEAN",
            color = color,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp
        )
    }
}
