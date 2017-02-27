package at.yawk.mcpe.analyzer

import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.ArrayDeque
import java.util.HashMap
import java.util.HashSet

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(GraphBuilder::class.java)

fun buildFunctionGraph(pipe: R2Pipe, address: Long, enterCall: (Call) -> Boolean): RegularExpression<Call> {
    val node = GraphBuilder(pipe, enterCall).build(address, EsilState.UNKNOWN)
    val state = nodeToState(node)
    return automatonToRegex(state)
}

interface Call {
    data class Fixed(val address: Long, val state: EsilState) : Call
    object Unknown : Call
}

private class GraphBuilder(
        val pipe: R2Pipe,
        val enterCall: (Call) -> Boolean,

        val instructionCache: MutableMap<Long, R2Pipe.Instruction> = HashMap<Long, R2Pipe.Instruction>()
) {
    val nodeCache = HashMap<Long, Node>()
    val visitQueue = ArrayDeque<Node>()

    fun childBuilder() = GraphBuilder(pipe, enterCall, instructionCache)

    fun build(startAddress: Long, inState: EsilState): Node {
        val node = getNodeAt(startAddress, inState)
        while (true) {
            val next = visitQueue.poll() ?: break
            next.inQueue = false

            var tries = 0
            while (true) {
                try {
                    next.result = computeResult(next.address, next.initialState)
                    break
                } catch (e: IOException) {
                    if (tries >= 3) throw e
                    tries++
                    log.warn("Generic IOException during graph node computation, retrying... ($tries/3)")
                }
            }
        }
        return node
    }

    class Node(
            val address: Long,
            var initialState: EsilState
    ) {
        var inQueue = false
        var result: NodeResult? = null
    }

    data class NodeResult(
            val linkedCall: Call?,
            val next: List<Node>
    )

    private fun getInstructionAt(address: Long) = instructionCache.getOrPut(address) {
        pipe.seek(address)
        pipe.disassemble()
    }

    private fun getNodeAt(address: Long, inState: EsilState): Node {
        val present = nodeCache[address]
        if (present != null) {
            val mergedState = EsilState.intersection(present.initialState, inState)
            if (mergedState != present.initialState) {
                // need to revisit this node with less known state
                present.initialState = mergedState
                if (!present.inQueue) {
                    visitQueue.push(present)
                }
            }
            return present
        } else {
            val n = Node(address, inState)
            nodeCache[address] = n
            visitQueue.push(n)
            return n
        }
    }

    private fun computeResult(address: Long, inState: EsilState): NodeResult {
        val insn = getInstructionAt(address)

        val stateAfter: EsilState = try {
            interpretEsilInstruction(inState, insn.esil)
        } catch (e: Exception) {
            log.warn("ESIL evaluation failed", e)
            EsilState.UNKNOWN
        }

        val nextAddress = address + insn.size

        when (insn.type) {
            "call", "ucall" -> {
                val call = insn.jump?.let { Call.Fixed(it, stateAfter) } ?: Call.Unknown
                return NodeResult(call, listOf(getNodeAt(nextAddress, stateAfter)))
            }
            "jmp" -> {
                val targetAddress = insn.jump!!.toLong()
                if ((getInstructionAt(targetAddress).flags ?: emptyList<String>()).any { it.startsWith("sym.") }) {
                    // tail call
                    val call = Call.Fixed(insn.jump.toLong(), stateAfter)
                    if (!enterCall(call)) {
                        return NodeResult(call, emptyList())
                    }
                }
                return NodeResult(null, listOf(getNodeAt(targetAddress, inState)))
            }
            "cjmp" -> {
                val normal = getNodeAt(nextAddress, stateAfter)
                val jump = getNodeAt(insn.jump!!.toLong(), stateAfter)
                return NodeResult(null, listOf(normal, jump))
            }
            "ccall" -> {
                val normal = getNodeAt(nextAddress, stateAfter)
                val call = Call.Fixed(insn.jump!!.toLong(), stateAfter)
                if (enterCall(call)) {
                    val branchStart = childBuilder().build(call.address, stateAfter)
                    branchStart.depthFirstSearch {
                        if (it.result!!.next.isEmpty()) it.result = it.result!!.copy(next = listOf(normal))
                    }
                    return NodeResult(null, listOf(normal, branchStart))
                } else {
                    return NodeResult(call, listOf(normal))
                }
            }
            "ret" -> {
                return NodeResult(null, emptyList())
            }

            "rjmp", "ujmp", "mjmp", "ucjmp", "rcall", "icall", "ircall", "uccall",
            "cret"
            -> TODO(insn.type)

            else -> {
                return NodeResult(null, listOf(getNodeAt(nextAddress, stateAfter)))
            }
        }
    }
}

private tailrec fun GraphBuilder.Node.depthFirstSearch(f: (GraphBuilder.Node) -> Unit) {
    val next = result!!.next
    f(this)
    if (!next.isEmpty()) {
        next.forEachIndexed { i, node ->
            @Suppress("NON_TAIL_RECURSIVE_CALL")
            if (i > 0) node.depthFirstSearch(f)
        }
        next[0].depthFirstSearch(f)
    }
}

private class State<T>(
        val transitions: MutableMap<State<T>, RegularExpression<T>> = HashMap()
)

private fun nodeToState(n: GraphBuilder.Node): State<Call> {
    val map = HashMap<GraphBuilder.Node, State<Call>>()

    fun run(n: GraphBuilder.Node): State<Call> {
        map[n]?.let { return it }
        val origin: State<Call>
        val target: State<Call>
        val linkedCall = n.result!!.linkedCall
        if (linkedCall != null) {
            origin = State()
            target = State()
            origin.transitions[target] = RegularExpression.Terminal(linkedCall)
        } else {
            origin = State()
            target = origin
        }
        map[n] = origin
        for (next in n.result!!.next) {
            target.transitions[run(next)] = RegularExpression.Concatenate(emptyList())
        }
        return origin
    }

    return run(n)
}

private fun <T> automatonToRegex(start: State<T>): RegularExpression<T> {
    val allStates = HashSet<State<T>>()

    run {
        val addQueue = ArrayDeque<State<T>>()
        addQueue.push(start)
        while (true) {
            val next = addQueue.poll() ?: break
            if (allStates.add(next)) {
                addQueue.addAll(next.transitions.keys)
            }
        }
    }

    fun eliminate(state: State<T>) {
        allStates.remove(state)
        val selfTransition = state.transitions.remove(state)?.zeroOrMore() ?: RegularExpression.empty<T>()
        for (from in allStates) {
            val transitionToEliminate = from.transitions.remove(state) ?: continue
            for ((to, tail) in state.transitions) {
                val added = transitionToEliminate concat selfTransition concat tail
                val old = from.transitions[to]
                if (old == null) from.transitions[to] = added
                else from.transitions[to] = added or old
            }
        }
    }

    while (true) {
        val next = allStates.firstOrNull { it != start && !it.transitions.isEmpty() } ?: break
        eliminate(next)
    }

    if (allStates.size == 1) {
        return start.transitions[start]?.zeroOrMore() ?: RegularExpression.empty()
    }

    val end = allStates.filter { it != start }
    var endRegex = end.mapNotNull { start.transitions[it] }
    val inStartTransition = start.transitions[start]
    if (inStartTransition != null) {
        endRegex = endRegex.map { inStartTransition.zeroOrMore() concat it }
    }
    return RegularExpression.Or(endRegex.toSet())
}

