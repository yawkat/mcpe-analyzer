package at.yawk.mcpe.analyzer

import org.slf4j.Logger

/**
 * @author yawkat
 */
internal fun Long.hex() = java.lang.Long.toHexString(this)

internal inline fun Logger.trace(msg: () -> String) {
    if (isTraceEnabled) trace(msg())
}

internal inline fun Logger.debug(msg: () -> String) {
    if (isTraceEnabled) debug(msg())
}