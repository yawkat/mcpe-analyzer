package at.yawk.mcpe.analyzer.graph

import at.yawk.mcpe.analyzer.EsilState
import at.yawk.mcpe.analyzer.PipeInfo
import at.yawk.mcpe.analyzer.R2Pipe
import at.yawk.mcpe.analyzer.RegularExpression
import at.yawk.mcpe.analyzer.trace
import com.fasterxml.jackson.core.JsonProcessingException
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.ArrayDeque
import java.util.HashMap

private val log = LoggerFactory.getLogger(FunctionGraphBuilder::class.java)

fun buildFunctionGraph(
        pipe: R2Pipe,
        pipeInfo: PipeInfo,
        enterCall: (Call.Static) -> Boolean,

        position: Position
): AutomatonState<Call> {
    val functionGraphBuilder = FunctionGraphBuilder(pipe, pipeInfo, enterCall)
    val functionVisitor = functionGraphBuilder.FunctionVisitor(
            start = position,
            parent = null,
            returnPointFactory = { null }
    )
    val node = functionVisitor.getNode(position, EsilState.UNKNOWN)
    functionVisitor.build()
    return node.automatonState
}

private class InstructionCache(val pipe: R2Pipe) {
    private val cache = HashMap<Position, R2Pipe.Instruction>()

    inline fun get(position: Position, callTrace: () -> String) = cache.getOrPut(position) {
        try {
            var attempt = 0
            var value: R2Pipe.Instruction
            while (true) {
                // run twice to work around https://github.com/radare/radare2/issues/6922
                //pipe.at(position.address).disassemble(position.architecture)
                try {
                    value = pipe.at(position.address).disassemble(position.architecture)
                    break
                } catch (e: IOException) {
                    if (attempt++ > 2) throw e
                }
            }
            value
        } catch (e: JsonProcessingException) {
            throw Exception("Failed to disassemble instruction at $position (call trace ${callTrace()})", e)
        }
    }
}

private class FunctionGraphBuilder(
        val pipe: R2Pipe,
        val pipeInfo: PipeInfo,

        val enterCall: (Call.Static) -> Boolean
) {
    val instructionCache = InstructionCache(pipe)

    tailrec fun FunctionVisitor.tryRecurseInto(position: Position, state: EsilState): FunctionVisitor.InstructionNode? {
        memberNodes[position]?.let {
            it.mergeInState(state)
            return it
        }

        return parent?.tryRecurseInto(position, state)
    }

    val FunctionVisitor.InstructionNode?.automatonState: AutomatonState<Call>
        get() = this?.automatonState ?: AutomatonState(acceptingState = true)

    enum class State {
        BUILDING,
        COMPLETE,
    }

    inner class FunctionVisitor(
            val start: Position,
            val parent: FunctionVisitor?,
            returnPointFactory: () -> InstructionNode?
    ) {
        val memberNodes = HashMap<Position, InstructionNode>()
        val visitQueue = ArrayDeque<InstructionNode>()

        private var state = State.BUILDING

        private val returnPoint by lazy(LazyThreadSafetyMode.NONE, returnPointFactory)

        val callTrace: String by lazy(LazyThreadSafetyMode.NONE) {
            val prefix = if (parent == null) "" else parent.callTrace + "->"
            val symbol = pipeInfo.symbolAtAddress(start.address)
            prefix + (symbol?.name ?: start.toString())
        }

        fun getNode(position: Position, inState: EsilState): InstructionNode {
            val present = memberNodes[position]
            if (present != null) {
                present.mergeInState(inState)
                return present
            } else {
                val new = InstructionNode(position, inState)
                memberNodes[position] = new
                return new
            }
        }

        private fun checkState(state: State) {
            if (this.state != state) {
                throw IllegalStateException("In state ${this.state} but expected state $state")
            }
        }

        fun build() {
            checkState(State.BUILDING)
            while (true)
                (visitQueue.poll() ?: break).visit()
            state = State.COMPLETE
        }

        inner class InstructionNode(
                val position: Position,

                inState: EsilState
        ) {
            val automatonState = AutomatonState<Call>(acceptingState = false)
            var inState = inState.copy(registers = inState.registers - position.architecture.programCounter)

            private var inQueue = false

            init {
                enqueue()
            }

            fun enqueue() {
                checkState(State.BUILDING)
                if (!inQueue) {
                    inQueue = true
                    visitQueue.add(this)
                }
            }

            fun mergeInState(inState: EsilState) {
                checkState(State.BUILDING)
                val merged = EsilState.intersection(this.inState, inState)
                if (merged != this.inState) {
                    log.trace { "$position needs to be revisited" }
                    this.inState = merged
                    enqueue()
                }
            }

            private fun isNoReturn(symbol: R2Pipe.Symbol): Boolean {
                if (symbol.name == "imp.__assert_rtn") return true

                return false
            }

            fun <T> automatonTransition(prefix: RegularExpression<T>, next: AutomatonState<T>) = next to prefix

            private fun jumpOrCall(
                    isCall: Boolean,
                    state: EsilState,
                    target: Destination,
                    returnTo: () -> InstructionNode?
            ): Pair<AutomatonState<Call>, RegularExpression<Call>>? {
                when (target) {
                    is Destination.Unknown -> {
                        // dynamic call
                        return automatonTransition(
                                prefix = RegularExpression.Terminal(Call.Dynamic),
                                next = returnTo().automatonState
                        )
                    }
                    is Destination.Known -> {
                        val jumpPos = target.position

                        val recursion = tryRecurseInto(jumpPos, state)
                        if (recursion != null) {
                            // already visited that destination somewhere in the call trace!
                            // recursive (tail) call or already-visited loop destination
                            return automatonTransition(
                                    prefix = RegularExpression.empty(),
                                    next = recursion.automatonState
                            )
                        }

                        val symbol = pipeInfo.symbolAtAddress(jumpPos.address)

                        if (symbol != null) {
                            // (tail) call

                            if (isNoReturn(symbol)) {
                                // no transition, just let the jump node die
                                return null
                            }

                            if (!enterCall(Call.Static(symbol, state))) {
                                log.trace { "Registering static call to ${symbol.name} at $position" }
                                return automatonTransition(
                                        prefix = RegularExpression.Terminal(Call.Static(symbol, state)),
                                        next = returnTo().automatonState
                                )
                            }
                        }

                        val jumpInstruction = instructionCache.get(jumpPos, { callTrace })

                        if (jumpInstruction.isIllegal()) {
                            log.trace { "Jump target $jumpPos is illegal, marking as dynamic" }
                            return automatonTransition(
                                    prefix = RegularExpression.Terminal(Call.Dynamic),
                                    next = returnTo().automatonState
                            )
                        }

                        if (isCall) {
                            log.trace { "Entering call to ${symbol?.name} at $position" }
                            // enter call with new stack frame
                            val callVisitor = FunctionVisitor(jumpPos, this@FunctionVisitor, returnTo)
                            val jumpNode = callVisitor.getNode(jumpPos, state)
                            callVisitor.build()
                            return automatonTransition(
                                    prefix = RegularExpression.empty(),
                                    next = jumpNode.automatonState
                            )
                        } else {
                            // loop
                            val jumpNode = getNode(jumpPos, state)
                            return automatonTransition(
                                    prefix = RegularExpression.empty(),
                                    next = jumpNode.automatonState
                            )
                        }
                    }
                }
            }

            fun visit() {
                inQueue = false

                val insn = instructionCache.get(position, { callTrace })
                val transitions = computeTransitions(pipe, pipeInfo, position, insn, inState)

                automatonState.transitions.clear()
                for (transition in transitions) {
                    val automatonTransition = when (transition) {
                        is InstructionTransition.Return -> returnPoint.automatonState to RegularExpression.empty()
                        is InstructionTransition.Jump -> jumpOrCall(
                                isCall = false,
                                state = transition.state, target = transition.target,
                                returnTo = { returnPoint })
                        is InstructionTransition.Call -> jumpOrCall(
                                isCall = true,
                                state = transition.state, target = transition.target,
                                returnTo = { getNode(transition.returnPosition.position, EsilState.UNKNOWN) })
                    }
                    if (automatonTransition != null) {
                        automatonState.transitions[automatonTransition.first] = automatonTransition.second
                    }
                }
            }
        }
    }
}
