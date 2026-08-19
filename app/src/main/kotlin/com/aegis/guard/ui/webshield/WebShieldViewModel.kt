package com.aegis.guard.ui.webshield

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class WebShieldStats(
    val urlsChecked: Int = 0,
    val threatsBlocked: Int = 0,
    val smsLinksScanned: Int = 0
)

sealed class UrlCheckState {
    object Idle : UrlCheckState()
    object Checking : UrlCheckState()
    data class Result(val result: UrlScanResult) : UrlCheckState()
    data class Error(val message: String) : UrlCheckState()
}

sealed class SmsCheckState {
    object Idle : SmsCheckState()
    object Scanning : SmsCheckState()
    data class Results(val results: List<SmsLinkResult>) : SmsCheckState()
}

@HiltViewModel
class WebShieldViewModel @Inject constructor(
    private val urlCheckService: UrlCheckService
) : ViewModel() {

    private val _urlInput = MutableStateFlow("")
    val urlInput: StateFlow<String> = _urlInput.asStateFlow()

    private val _urlCheckState = MutableStateFlow<UrlCheckState>(UrlCheckState.Idle)
    val urlCheckState: StateFlow<UrlCheckState> = _urlCheckState.asStateFlow()

    private val _smsCheckState = MutableStateFlow<SmsCheckState>(SmsCheckState.Idle)
    val smsCheckState: StateFlow<SmsCheckState> = _smsCheckState.asStateFlow()

    private val _history = MutableStateFlow<List<UrlScanResult>>(emptyList())
    val history: StateFlow<List<UrlScanResult>> = _history.asStateFlow()

    private val _stats = MutableStateFlow(WebShieldStats())
    val stats: StateFlow<WebShieldStats> = _stats.asStateFlow()

    fun onUrlInputChange(input: String) {
        _urlInput.value = input
        // Reset result when user starts typing again
        if (_urlCheckState.value is UrlCheckState.Result || _urlCheckState.value is UrlCheckState.Error) {
            _urlCheckState.value = UrlCheckState.Idle
        }
    }

    fun checkUrl() {
        val url = _urlInput.value.trim()
        if (url.isBlank()) return

        viewModelScope.launch {
            _urlCheckState.value = UrlCheckState.Checking
            try {
                val result = urlCheckService.checkUrl(url)
                _urlCheckState.value = UrlCheckState.Result(result)

                // Update history (most recent first, max 50)
                val updated = listOf(result) + _history.value
                _history.value = updated.take(50)

                // Update stats
                val currentStats = _stats.value
                _stats.value = currentStats.copy(
                    urlsChecked = currentStats.urlsChecked + 1,
                    threatsBlocked = currentStats.threatsBlocked + if (result.isMalicious) 1 else 0
                )
            } catch (e: Exception) {
                _urlCheckState.value = UrlCheckState.Error("Failed to check URL. Please try again.")
            }
        }
    }

    fun scanSmsLinks() {
        viewModelScope.launch {
            _smsCheckState.value = SmsCheckState.Scanning
            try {
                val results = urlCheckService.scanSmsLinks()
                _smsCheckState.value = SmsCheckState.Results(results)

                // Update stats
                val maliciousCount = results.count { it.scanResult.isMalicious }
                val currentStats = _stats.value
                _stats.value = currentStats.copy(
                    smsLinksScanned = currentStats.smsLinksScanned + results.size,
                    threatsBlocked = currentStats.threatsBlocked + maliciousCount
                )
            } catch (e: Exception) {
                _smsCheckState.value = SmsCheckState.Idle
            }
        }
    }

    fun clearResult() {
        _urlCheckState.value = UrlCheckState.Idle
        _urlInput.value = ""
    }
}
