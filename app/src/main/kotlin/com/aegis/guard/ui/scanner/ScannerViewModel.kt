package com.aegis.guard.ui.scanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.guard.scanner.AppScanner
import com.aegis.guard.scanner.ScanResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class ScannerViewModel @Inject constructor(
    private val appScanner: AppScanner
) : ViewModel() {

    private val _uiState = MutableStateFlow<ScannerUiState>(ScannerUiState.Idle)
    val uiState: StateFlow<ScannerUiState> = _uiState.asStateFlow()

    fun startScan() {
        viewModelScope.launch {
            _uiState.value = ScannerUiState.Scanning(progress = 0f, appsScanned = 0)

            // Run the actual scan on IO
            val results = withContext(Dispatchers.IO) { appScanner.scanApps() }
            val total = results.size

            // Animate through results to give visual scanning feel
            results.forEachIndexed { index, _ ->
                val progress = (index + 1).toFloat() / total.toFloat()
                _uiState.value = ScannerUiState.Scanning(progress = progress, appsScanned = index + 1)
                // Vary speed: faster in the middle, slower at start/end
                delay(if (index < 5 || index > total - 5) 80L else 20L)
            }

            // Brief pause for dramatic effect
            delay(400)

            val sortedResults = results.sortedByDescending { it.score }
            _uiState.value = ScannerUiState.Results(sortedResults)
        }
    }
}

sealed class ScannerUiState {
    object Idle : ScannerUiState()
    data class Scanning(val progress: Float, val appsScanned: Int) : ScannerUiState()
    data class Results(val apps: List<ScanResult>) : ScannerUiState()
}
