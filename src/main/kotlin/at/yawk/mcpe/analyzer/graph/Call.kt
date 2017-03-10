package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.EsilState
import at.yawk.mcpe.analyzer.R2Pipe

/**
 * @author yawkat
 */
sealed class Call {
    data class Static(val symbol: R2Pipe.Symbol, val state: EsilState) : Call()
    object Dynamic : Call()
    object NoReturn : Call()
}