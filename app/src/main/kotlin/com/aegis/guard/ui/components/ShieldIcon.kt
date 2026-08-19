package com.aegis.guard.ui.components

import androidx.compose.animation.core.InfiniteRepeatableSpec
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.unit.dp
import com.aegis.guard.ui.theme.ElectricCyan

@Composable
fun ShieldIcon(
    modifier: Modifier = Modifier,
    color: Color = ElectricCyan
) {
    val infiniteTransition = rememberInfiniteTransition()
    val scale by infiniteTransition.animateFloat(
        initialValue = 1.0f,
        targetValue = 1.05f,
        animationSpec = InfiniteRepeatableSpec(
            animation = tween(1000),
            repeatMode = RepeatMode.Reverse
        )
    )

    Canvas(modifier = modifier.size(100.dp)) {
        val path = Path().apply {
            val width = size.width
            val height = size.height
            moveTo(width / 2f, 0f)
            lineTo(width, height * 0.2f)
            lineTo(width, height * 0.5f)
            cubicTo(
                width, height * 0.8f,
                width * 0.8f, height,
                width / 2f, height
            )
            cubicTo(
                width * 0.2f, height,
                0f, height * 0.8f,
                0f, height * 0.5f
            )
            lineTo(0f, height * 0.2f)
            close()
        }
        scale(scale) {
            drawPath(path = path, color = color)
        }
    }
}
