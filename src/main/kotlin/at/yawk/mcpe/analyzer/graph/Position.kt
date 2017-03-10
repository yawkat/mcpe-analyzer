package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.Architecture
import at.yawk.mcpe.analyzer.hex

/**
 * @author yawkat
 */
data class Position(val address: Long, val architecture: Architecture) {
    override fun toString() = "$architecture/0x${address.hex()}"
}