package com.aegis.guard.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.aegis.guard.ui.callguard.CallGuardScreen
import com.aegis.guard.ui.dashboard.DashboardScreen
import com.aegis.guard.ui.scanner.ScannerScreen
import com.aegis.guard.ui.settings.SettingsScreen
import com.aegis.guard.ui.webshield.WebShieldScreen

sealed class Route(val route: String) {
    object Dashboard : Route("dashboard")
    object Scanner : Route("scanner")
    object WebShield : Route("webshield")
    object CallGuard : Route("callguard")
    object Settings : Route("settings")
}

@Composable
fun AegisNavHost() {
    val navController = rememberNavController()

    Scaffold(
        bottomBar = { BottomNavBar(navController = navController) }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = Route.Dashboard.route,
            modifier = Modifier.padding(paddingValues)
        ) {
            composable(Route.Dashboard.route) { DashboardScreen() }
            composable(Route.Scanner.route) { ScannerScreen() }
            composable(Route.WebShield.route) { WebShieldScreen() }
            composable(Route.CallGuard.route) { CallGuardScreen() }
            composable(Route.Settings.route) { SettingsScreen() }
        }
    }
}
