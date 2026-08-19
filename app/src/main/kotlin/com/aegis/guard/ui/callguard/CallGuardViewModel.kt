package com.aegis.guard.ui.callguard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class NumberCheckState {
    object Idle : NumberCheckState()
    object Checking : NumberCheckState()
    data class Result(val info: CallRiskInfo) : NumberCheckState()
}

sealed class SimulatedCallState {
    object None : SimulatedCallState()
    data class Incoming(val info: CallRiskInfo) : SimulatedCallState()
    data class Screened(val info: CallRiskInfo, val blocked: Boolean) : SimulatedCallState()
}

@HiltViewModel
class CallGuardViewModel @Inject constructor(
    private val service: CallGuardService
) : ViewModel() {

    private val _numberInput = MutableStateFlow("")
    val numberInput: StateFlow<String> = _numberInput.asStateFlow()

    private val _checkState = MutableStateFlow<NumberCheckState>(NumberCheckState.Idle)
    val checkState: StateFlow<NumberCheckState> = _checkState.asStateFlow()

    private val _isProtectionEnabled = MutableStateFlow(true)
    val isProtectionEnabled: StateFlow<Boolean> = _isProtectionEnabled.asStateFlow()

    private val _blockedHistory = MutableStateFlow(emptyList<BlockedCallEntry>())
    val blockedHistory: StateFlow<List<BlockedCallEntry>> = _blockedHistory.asStateFlow()

    private val _stats = MutableStateFlow(CallGuardStats())
    val stats: StateFlow<CallGuardStats> = _stats.asStateFlow()

    private val _simulatedCall = MutableStateFlow<SimulatedCallState>(SimulatedCallState.None)
    val simulatedCall: StateFlow<SimulatedCallState> = _simulatedCall.asStateFlow()

    init {
        _blockedHistory.value = service.getBlockedCallHistory()
        _stats.value = service.getStats()
    }

    fun onNumberInputChange(input: String) {
        _numberInput.value = input
        if (_checkState.value is NumberCheckState.Result) {
            _checkState.value = NumberCheckState.Idle
        }
    }

    fun checkNumber() {
        val number = _numberInput.value.trim()
        if (number.isBlank()) return
        viewModelScope.launch {
            _checkState.value = NumberCheckState.Checking
            val result = service.checkNumber(number)
            _checkState.value = NumberCheckState.Result(result)
        }
    }

    fun toggleProtection() {
        _isProtectionEnabled.value = !_isProtectionEnabled.value
    }

    fun simulateIncomingCall(number: String) {
        viewModelScope.launch {
            val info = service.checkNumber(number)
            _simulatedCall.value = SimulatedCallState.Incoming(info)
            kotlinx.coroutines.delay(3000)
            val blocked = info.risk != CallRisk.SAFE
            _simulatedCall.value = SimulatedCallState.Screened(info, blocked)
            kotlinx.coroutines.delay(3000)
            _simulatedCall.value = SimulatedCallState.None
        }
    }

    fun dismissSimulation() {
        _simulatedCall.value = SimulatedCallState.None
    }

    fun clearResult() {
        _checkState.value = NumberCheckState.Idle
        _numberInput.value = ""
    }
}
