package at.yawk.mcpe.analyzer

/**
 * open for testing.
 *
 * @author yawkat
 */
open class PipeInfo(private val pipe: R2Pipe) {
    open val symbols: List<R2Pipe.Symbol> by lazy { pipe.listSymbols() }
    open val relocations: List<R2Pipe.Relocation> by lazy { pipe.listRelocations() }
    open val architecture: Architecture by lazy { Architecture.of(pipe) }

    fun symbolAtAddress(address: Long) = symbols.find { it.vaddr == address }
    fun relocationAtAddress(address: Long) = relocations.find { it.vaddr == address }
    fun symbolForName(name: String) = symbols.find { it.name == name }
}