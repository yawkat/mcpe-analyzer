package at.yawk.mcpe.analyzer

import org.slf4j.LoggerFactory
import java.util.ArrayDeque
import java.util.HashMap
import java.util.HashSet

/**
 * @author yawkat
 */
private val log = LoggerFactory.getLogger(GraphBuilder::class.java)

fun buildFunctionGraph(pipe: R2Pipe, enterCall: (Call) -> Boolean): RegularExpression<Call> {
    val node = GraphBuilder(pipe, enterCall).build()
    val state = nodeToState(node)
    return automatonToRegex(state)
}

interface Call {
    data class Fixed(val address: Long, val state: EsilState) : Call
    object Unknown : Call
}

private class GraphBuilder(val pipe: R2Pipe, val enterCall: (Call) -> Boolean) {
    val registry = HashMap<Long, Node>()

    tailrec fun build(n: Node = Node(), stateIn: EsilState = EsilState.UNKNOWN): Node {
        val insn = pipe.disassemble()
        registry.putIfAbsent(insn.offset, n)?.let { return it }

        val state: EsilState = try {
            interpretEsilInstruction(stateIn, insn.esil)
        } catch (e: Exception) {
            log.warn("ESIL evaluation failed", e)
            EsilState.UNKNOWN
        }

        when (insn.type) {
            "call", "ucall" -> {
                n.linkedCall = insn.jump?.let { Call.Fixed(it, state) } ?: Call.Unknown
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                n.next = listOf(build())
                return n
            }
            "jmp" -> {
                pipe.seek(insn.jump!!.toLong())
                if ((pipe.disassemble().flags ?: emptyList<String>()).any { it.startsWith("sym.") }) {
                    // tail call
                    val call = Call.Fixed(insn.jump.toLong(), state)
                    if (!enterCall(call)) {
                        n.linkedCall = call
                        return n
                    }
                }
                return build(n, state)
            }
            "cjmp" -> {
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val normal = build()
                pipe.seek(insn.jump!!.toLong())
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val jump = build()
                n.next = listOf(normal, jump)
                return n
            }
            "ccall" -> {
                pipe.skip()
                @Suppress("NON_TAIL_RECURSIVE_CALL")
                val normal = build()
                val call = Call.Fixed(insn.jump!!.toLong(), state)
                val jump = if (enterCall(call)) {
                    @Suppress("NON_TAIL_RECURSIVE_CALL")
                    val branchStart = build(n)
                    branchStart.depthFirstSearch {
                        if (it.next.isEmpty()) it.next = listOf(normal)
                    }
                    branchStart
                } else {
                    Node(linkedCall = call, next = listOf(normal))
                }
                n.next = listOf(normal, jump)
                return n
            }
            "ret" -> {
                return n
            }

            "rjmp", "ujmp", "mjmp", "ucjmp", "rcall", "icall", "ircall", "uccall",
            "cret"
            -> TODO(insn.type)

            else -> {
                pipe.skip()
                return build(n, state)
            }
        }
    }
}

private class Node(
        var linkedCall: Call? = null,
        var next: List<Node> = emptyList()
)

private tailrec fun Node.depthFirstSearch(f: (Node) -> Unit) {
    val next = next
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

private fun nodeToState(n: Node): State<Call> {
    val map = HashMap<Node, State<Call>>()

    fun run(n: Node): State<Call> {
        map[n]?.let { return it }
        val origin: State<Call>
        val target: State<Call>
        val linkedCall = n.linkedCall
        if (linkedCall != null) {
            origin = State()
            target = State()
            origin.transitions[target] = RegularExpression.Terminal(linkedCall)
        } else {
            origin = State()
            target = origin
        }
        map[n] = origin
        for (next in n.next) {
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

